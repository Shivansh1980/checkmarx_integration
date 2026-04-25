from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ...domain.constants import SONAR_COVERAGE_METRIC_KEYS, SONAR_FILE_PAGE_SIZE, SONAR_LOCALLY_EVALUABLE_QUALITY_GATE_METRICS, SONAR_PROJECTS_PAGE_SIZE
from ...domain.errors import SonarError, SonarHttpError, SonarPermissionError
from ...domain.models import SonarCredentials
from ...infrastructure.clients.sonar import SonarClient
from ...shared.utils import compact_dict, to_float, to_int, utc_now_iso


def _coalesce_path(component: dict[str, Any]) -> str:
	return str(component.get("path") or component.get("name") or component.get("key") or "").replace("\\", "/")


def _access_mode(validation: dict[str, Any], metas: list[dict[str, Any]], permission_gaps: set[str]) -> str:
	modes = {str(meta.get("used_auth_mode", "")).strip() for meta in metas if meta.get("used_auth_mode")}
	modes.discard("")
	if not validation.get("token_configured") and not modes:
		return "anonymous"
	if modes == {"authenticated"} and not permission_gaps:
		return "authenticated"
	if modes == {"anonymous"}:
		return "anonymous"
	if modes == {"authenticated"} and permission_gaps:
		return "partial_access"
	if modes == {"anonymous", "authenticated"}:
		return "partial_access"
	if validation.get("token_configured") and not validation.get("token_valid") and not modes:
		return "anonymous"
	return "partial_access" if permission_gaps else (next(iter(modes)) if modes else "anonymous")


def _build_capabilities() -> dict[str, str]:
	return {
		"can_list_projects": "unknown",
		"can_list_branches": "unknown",
		"can_read_project_measures": "unknown",
		"can_read_file_measures": "unknown",
		"can_read_source": "unknown",
		"can_read_line_level_coverage": "unknown",
	}


def _safe_int(value: Any, default: int = 0) -> int:
	parsed = to_int(value, default=default)
	return int(parsed or 0)


def _safe_float(value: Any) -> float | None:
	return to_float(value, default=None)


def _file_name_from_path(path: str) -> str:
	cleaned = str(path or "").replace("\\", "/").rstrip("/")
	return cleaned.split("/")[-1] if cleaned else ""


def _priority_label(score: float, *, executable_metrics: bool, likely_help: bool) -> str:
	if not executable_metrics:
		return "informational"
	if score >= 35 or likely_help:
		return "high"
	if score >= 18:
		return "medium"
	return "low"


def _priority_score(entry: dict[str, Any], total_uncovered: int) -> float:
	coverage = _safe_float(entry.get("coverage"))
	uncovered_lines = _safe_int(entry.get("uncovered_lines"))
	lines_to_cover = _safe_int(entry.get("lines_to_cover"))
	if coverage is None and uncovered_lines <= 0 and lines_to_cover <= 0:
		return 0.0
	coverage_gap = 100.0 if coverage is None else max(0.0, 100.0 - coverage)
	uncovered_share = (100.0 * uncovered_lines / total_uncovered) if total_uncovered > 0 else 0.0
	size_weight = min(lines_to_cover, 300) / 3.0
	return round((0.5 * coverage_gap) + (0.35 * uncovered_share) + (0.15 * size_weight), 2)


def _priority_reason(entry: dict[str, Any]) -> str:
	coverage = _safe_float(entry.get("coverage"))
	uncovered_lines = _safe_int(entry.get("uncovered_lines"))
	uncovered_conditions = _safe_int(entry.get("uncovered_conditions"))
	if coverage is None:
		if uncovered_lines <= 0:
			return "This file does not currently expose executable coverage metrics in Sonar."
		return "Coverage metrics are incomplete for this file, so Sonar impact is estimated from uncovered lines."
	if coverage == 0:
		return "This file has executable code with no recorded test coverage."
	if uncovered_conditions > 0 and (entry.get("branch_coverage") or 100) < 60:
		return "Conditional branches are poorly covered and likely hide edge cases."
	if uncovered_lines >= 25:
		return "This file carries a large uncovered line count relative to the project."
	return "Improving this file should lift coverage with focused unit or path tests."


def _recommended_focus(entry: dict[str, Any]) -> str:
	branch_coverage = _safe_float(entry.get("branch_coverage"))
	uncovered_conditions = _safe_int(entry.get("uncovered_conditions"))
	coverage = _safe_float(entry.get("coverage"))
	if uncovered_conditions > 0 and branch_coverage is not None and branch_coverage < 60:
		return "Target decision branches, error paths, and boolean edge cases first."
	if coverage is not None and coverage < 20:
		return "Start with happy-path coverage, then add tests for null, empty, and exception scenarios."
	if coverage is None:
		return "Check whether this file is executable code or excluded from imported coverage reports."
	return "Add focused tests around the uncovered logic paths in this file."


def _extract_source_map(source_payload: dict[str, Any]) -> dict[int, str]:
	source_map: dict[int, str] = {}
	sources = source_payload.get("sources")
	if not isinstance(sources, list):
		return source_map
	for item in sources:
		if isinstance(item, (list, tuple)) and len(item) >= 2:
			line = to_int(item[0], default=None)
			code = item[1]
			if line is None or code in (None, ""):
				continue
			source_map[int(line)] = str(code)
			continue
		if not isinstance(item, dict):
			continue
		line = to_int(item.get("line") or item.get("lineNumber"), default=None)
		code = item.get("code") or item.get("source") or item.get("lineText")
		if line is None or code in (None, ""):
			continue
		source_map[int(line)] = str(code)
	return source_map


def _extract_line_details(payload: dict[str, Any]) -> tuple[list[int], list[int], dict[int, str]]:
	uncovered: set[int] = set()
	covered: set[int] = set()
	source_map: dict[int, str] = {}

	def visit(node: Any) -> None:
		if isinstance(node, dict):
			line = to_int(node.get("line") or node.get("lineNumber"), default=None)
			if line is not None:
				text = node.get("code") or node.get("source") or node.get("lineText")
				if text not in (None, ""):
					source_map[int(line)] = str(text)
				status_text = str(node.get("coverageStatus") or node.get("status") or "").lower()
				hits = node.get("lineHits")
				if hits in (None, ""):
					hits = node.get("utHits")
				if hits in (None, ""):
					hits = node.get("hits")
				covered_flag = node.get("covered")
				if hits not in (None, ""):
					try:
						hits_value = int(float(hits))
					except (TypeError, ValueError):
						hits_value = None
					if hits_value is not None:
						if hits_value > 0:
							covered.add(int(line))
						else:
							uncovered.add(int(line))
				elif isinstance(covered_flag, bool):
					if covered_flag:
						covered.add(int(line))
					else:
						uncovered.add(int(line))
				elif "uncovered" in status_text or status_text == "no_coverage":
					uncovered.add(int(line))
				elif "covered" in status_text:
					covered.add(int(line))
			for value in node.values():
				visit(value)
		elif isinstance(node, list):
			for item in node:
				visit(item)

	visit(payload)
	return sorted(uncovered), sorted(covered), source_map


def _build_source_excerpt(uncovered_lines: list[int], source_map: dict[int, str], *, limit: int = 20) -> list[dict[str, Any]]:
	if not uncovered_lines or not source_map:
		return []
	selected: set[int] = set()
	for line in uncovered_lines[: max(1, limit // 3)]:
		for candidate in range(max(1, line - 1), line + 2):
			if candidate in source_map:
				selected.add(candidate)
	entries: list[dict[str, Any]] = []
	for line in sorted(selected)[:limit]:
		entries.append(
			{
				"line": line,
				"text": source_map[line],
				"status": "uncovered" if line in uncovered_lines else "context",
			}
		)
	return entries


def _normalize_file_record(entry: dict[str, Any]) -> dict[str, Any]:
	return {
		"file_key": entry.get("file_key"),
		"file_path": entry.get("file_path"),
		"file_name": _file_name_from_path(str(entry.get("file_path") or "")),
		"coverage_pct": entry.get("coverage"),
		"line_coverage_pct": entry.get("line_coverage"),
		"branch_coverage_pct": entry.get("branch_coverage"),
		"total_lines_considered": entry.get("lines_to_cover"),
		"covered_lines_count": entry.get("covered_lines"),
		"uncovered_lines_count": entry.get("uncovered_lines"),
		"uncovered_line_numbers": list(entry.get("uncovered_line_numbers", [])),
		"covered_line_numbers": list(entry.get("covered_line_numbers", [])),
		"priority_score": entry.get("priority_score"),
		"priority": entry.get("priority"),
		"estimated_project_impact_pct": entry.get("estimated_project_impact_pct"),
		"should_target_first": entry.get("should_target_first"),
		"why": entry.get("priority_reason"),
		"suggested_test_focus": entry.get("recommended_test_focus"),
		"has_executable_coverage_metrics": entry.get("has_executable_coverage_metrics"),
		"line_number_quality": entry.get("line_number_quality"),
	}


def _build_priority_section(files: list[dict[str, Any]], *, limit: int = 10) -> dict[str, Any]:
	targets = []
	for index, entry in enumerate(files[:limit], start=1):
		targets.append(
			{
				"rank": index,
				"file_path": entry.get("file_path"),
				"file_name": _file_name_from_path(str(entry.get("file_path") or "")),
				"coverage_pct": entry.get("coverage"),
				"uncovered_lines_count": entry.get("uncovered_lines"),
				"uncovered_line_numbers": list(entry.get("uncovered_line_numbers", [])),
				"priority_score": entry.get("priority_score"),
				"priority": entry.get("priority"),
				"expected_coverage_gain_pct": entry.get("estimated_project_impact_pct"),
				"why": entry.get("priority_reason"),
				"suggested_test_focus": entry.get("recommended_test_focus"),
			}
		)
	return {"top_files_to_target": targets}


def _split_delimited_values(raw_value: str) -> list[str]:
	cleaned = str(raw_value or "").replace(";", ",")
	return [item.strip() for item in cleaned.split(",") if item.strip()]


def _default_workspace_root() -> Path:
	return Path(__file__).resolve().parents[4]


def _default_local_source_paths(workspace_root: Path) -> list[str]:
	default_src = workspace_root / "src"
	if default_src.is_dir():
		return ["src"]
	packages = [
		child.name
		for child in workspace_root.iterdir()
		if child.is_dir() and (child / "__init__.py").is_file()
	]
	return packages or ["."]


def _safe_branch_coverage(summary: dict[str, Any]) -> float | None:
	total_branches = _safe_int(summary.get("num_branches"))
	covered_branches = _safe_int(summary.get("covered_branches"))
	if total_branches <= 0:
		return None
	return round((100.0 * covered_branches / total_branches), 2)


def _tail_output(text: str, *, line_limit: int = 40) -> str:
	lines = [line.rstrip() for line in str(text or "").splitlines() if line.strip()]
	if not lines:
		return ""
	return "\n".join(lines[-line_limit:])


def _build_quality_gate_prediction(
	*,
	threshold: float,
	overall_coverage: float | None,
	would_meet_threshold: bool,
	files_below_threshold: list[dict[str, Any]],
	mode: str,
) -> dict[str, Any]:
	failing_conditions: list[dict[str, Any]] = []
	if overall_coverage is None:
		failing_conditions.append(
			{
				"metric": "coverage",
				"status": "unknown",
				"actual": None,
				"threshold": threshold,
				"reason": "Overall local coverage could not be determined from the coverage.py output.",
			}
		)
	elif not would_meet_threshold:
		failing_conditions.append(
			{
				"metric": "coverage",
				"status": "fail",
				"actual": round(float(overall_coverage), 2),
				"threshold": threshold,
				"reason": f"Overall coverage {overall_coverage:.2f}% is below the configured local quality gate threshold of {threshold:.2f}%.",
			}
		)

	return {
		"mode": mode,
		"evaluated_locally": True,
		"status": "pass" if would_meet_threshold else "fail",
		"would_pass": would_meet_threshold,
		"coverage_threshold_pct": threshold,
		"overall_coverage_pct": None if overall_coverage is None else round(float(overall_coverage), 2),
		"failing_conditions": failing_conditions,
		"files_below_threshold": [
			{
				"file_path": item.get("file_path"),
				"file_name": _file_name_from_path(str(item.get("file_path") or "")),
				"coverage_pct": item.get("coverage"),
				"uncovered_lines_count": item.get("uncovered_lines"),
				"uncovered_line_numbers": list(item.get("uncovered_line_numbers", [])),
			}
			for item in files_below_threshold[:25]
		],
		"limitations": [
			"This is a local pre-push quality-gate prediction based on coverage.py results.",
			"Final SonarQube pipeline results can still differ because of exclusions, imported report paths, or additional server-side gate conditions.",
		],
	}


def _normalize_lookup_text(value: str) -> str:
	return "".join(character.lower() for character in str(value or "") if character.isalnum())


def _rank_project_match(project: dict[str, Any], query: str) -> tuple[int, str]:
	query_text = str(query or "").strip()
	if not query_text:
		return (0, "none")
	query_lower = query_text.lower()
	query_normalized = _normalize_lookup_text(query_text)
	project_key = str(project.get("key") or "").strip()
	project_name = str(project.get("name") or "").strip()
	key_lower = project_key.lower()
	name_lower = project_name.lower()
	key_normalized = _normalize_lookup_text(project_key)
	name_normalized = _normalize_lookup_text(project_name)

	if query_lower == key_lower:
		return (100, "exact_key")
	if query_lower == name_lower:
		return (95, "exact_name")
	if query_normalized and query_normalized == key_normalized:
		return (90, "normalized_key")
	if query_normalized and query_normalized == name_normalized:
		return (85, "normalized_name")
	if query_lower and query_lower in key_lower:
		return (80, "key_contains")
	if query_lower and query_lower in name_lower:
		return (75, "name_contains")
	if query_normalized and query_normalized in key_normalized:
		return (70, "normalized_key_contains")
	if query_normalized and query_normalized in name_normalized:
		return (65, "normalized_name_contains")
	return (0, "none")


def _evaluate_quality_gate_condition(*, comparator: str, actual: float, threshold: float) -> bool | None:
	resolved = str(comparator or "").strip().upper()
	if resolved == "LT":
		return actual >= threshold
	if resolved == "GT":
		return actual <= threshold
	if resolved == "EQ":
		return actual == threshold
	return None


def _local_metric_for_quality_gate(
	*,
	metric_key: str,
	overall_coverage: float | None,
	line_coverage: float | None,
	branch_coverage: float | None,
) -> float | None:
	resolved = str(metric_key or "").strip()
	if resolved == "coverage":
		return overall_coverage
	if resolved == "line_coverage":
		return line_coverage
	if resolved == "branch_coverage":
		return branch_coverage
	return None


def _quality_gate_status_to_decision(status: str) -> tuple[str, bool | None]:
	resolved = str(status or "").strip().upper()
	if resolved == "OK":
		return ("pass", True)
	if resolved in {"ERROR", "WARN"}:
		return ("fail", False)
	return ("unknown", None)


def _format_remote_scope(project_key: str, *, branch: str = "", pull_request: str = "") -> str:
	if pull_request:
		return f"project '{project_key}' pull request '{pull_request}'"
	if branch:
		return f"project '{project_key}' branch '{branch}'"
	return f"project '{project_key}'"


class SonarCoverageService:
	def __init__(self, credentials: SonarCredentials) -> None:
		self.credentials = credentials
		self.client = SonarClient(base_url=credentials.base_url, token=credentials.token, timeout=credentials.timeout)

	def _resolve_remote_project_for_workspace(
		self,
		*,
		explicit_project: str,
		project_query: str,
		workspace_root: Path,
		branch: str,
		pull_request: str,
	) -> dict[str, Any]:
		lookup_terms: list[str] = []
		for candidate in (explicit_project, project_query, workspace_root.name):
			cleaned = str(candidate or "").strip()
			if cleaned and cleaned not in lookup_terms:
				lookup_terms.append(cleaned)

		attempts: list[dict[str, Any]] = []
		if explicit_project.strip():
			try:
				payload, _ = self.client.get_component_measures(explicit_project.strip(), branch=branch, pull_request=pull_request)
				component = payload.get("component") if isinstance(payload.get("component"), dict) else {}
				return {
					"lookup_attempted": True,
					"matched": True,
					"query_used": explicit_project.strip(),
					"match_strategy": "explicit_project_key",
					"project_key": str(component.get("key") or explicit_project.strip()),
					"project_name": str(component.get("name") or explicit_project.strip()),
					"branch_name": branch or str(component.get("branch") or ""),
					"attempts": attempts,
				}
			except SonarHttpError as exc:
				attempts.append({"query": explicit_project.strip(), "strategy": "explicit_project_key", "error": str(exc)})

		for lookup_term in lookup_terms:
			try:
				payload, _ = self.client.list_projects(query=lookup_term, page=1, page_size=25)
			except SonarHttpError as exc:
				attempts.append({"query": lookup_term, "strategy": "search", "error": str(exc)})
				continue

			projects = self.client.normalize_project_list(payload)
			best_project: dict[str, Any] | None = None
			best_score = -1
			best_strategy = "none"
			for candidate in projects:
				score, strategy = _rank_project_match(candidate, lookup_term)
				if score > best_score:
					best_score = score
					best_strategy = strategy
					best_project = candidate

			attempts.append(
				{
					"query": lookup_term,
					"strategy": "search",
					"candidate_count": len(projects),
					"best_score": None if best_score < 0 else best_score,
					"best_match_strategy": best_strategy,
				}
			)
			if best_project is not None and best_score >= 65:
				return {
					"lookup_attempted": True,
					"matched": True,
					"query_used": lookup_term,
					"match_strategy": best_strategy,
					"project_key": str(best_project.get("key") or lookup_term),
					"project_name": str(best_project.get("name") or best_project.get("key") or lookup_term),
					"branch_name": branch or "",
					"attempts": attempts,
				}

		return {
			"lookup_attempted": bool(lookup_terms),
			"matched": False,
			"query_used": lookup_terms[0] if lookup_terms else "",
			"match_strategy": "not_found",
			"project_key": "",
			"project_name": "",
			"branch_name": branch or "",
			"attempts": attempts,
		}

	def _predict_remote_quality_gate(
		self,
		*,
		project_key: str,
		branch: str,
		pull_request: str,
		overall_coverage: float | None,
		line_coverage: float | None,
		branch_coverage: float | None,
	) -> dict[str, Any]:
		payload, _ = self.client.get_quality_gate_status(project_key=project_key, branch=branch, pull_request=pull_request)
		project_status = payload.get("projectStatus") if isinstance(payload.get("projectStatus"), dict) else {}
		conditions = project_status.get("conditions") if isinstance(project_status.get("conditions"), list) else []

		evaluated_conditions: list[dict[str, Any]] = []
		unsupported_conditions: list[dict[str, Any]] = []
		for raw_condition in conditions:
			if not isinstance(raw_condition, dict):
				continue
			metric_key = str(raw_condition.get("metricKey") or "").strip()
			comparator = str(raw_condition.get("comparator") or "").strip().upper()
			threshold = _safe_float(raw_condition.get("errorThreshold"))
			local_actual = _local_metric_for_quality_gate(
				metric_key=metric_key,
				overall_coverage=overall_coverage,
				line_coverage=line_coverage,
				branch_coverage=branch_coverage,
			)
			if metric_key not in SONAR_LOCALLY_EVALUABLE_QUALITY_GATE_METRICS or threshold is None or local_actual is None:
				unsupported_conditions.append(
					compact_dict(
						{
							"metric": metric_key,
							"comparator": comparator,
							"threshold": threshold,
							"remote_status": raw_condition.get("status"),
							"reason": "Condition cannot be evaluated locally from coverage.py metrics.",
						}
					)
				)
				continue

			passes = _evaluate_quality_gate_condition(comparator=comparator, actual=local_actual, threshold=threshold)
			status = "pass" if passes else "fail"
			if passes is None:
				unsupported_conditions.append(
					compact_dict(
						{
							"metric": metric_key,
							"comparator": comparator,
							"threshold": threshold,
							"reason": "Comparator is not supported by the local predictor.",
						}
					)
				)
				continue

			evaluated_conditions.append(
				compact_dict(
					{
						"metric": metric_key,
						"comparator": comparator,
						"threshold": threshold,
						"local_actual": round(float(local_actual), 2),
						"remote_actual": _safe_float(raw_condition.get("actualValue")),
						"remote_status": raw_condition.get("status"),
						"status": status,
					}
				)
			)

		failed_conditions = [item for item in evaluated_conditions if item.get("status") == "fail"]
		prediction_status = "unknown"
		prediction_would_pass: bool | None = None
		if failed_conditions:
			prediction_status = "fail"
			prediction_would_pass = False
		elif evaluated_conditions and not unsupported_conditions:
			prediction_status = "pass"
			prediction_would_pass = True

		return {
			"project_key": project_key,
			"current_status": str(project_status.get("status") or "NONE"),
			"ignored_conditions": bool(project_status.get("ignoredConditions", False)),
			"cayc_status": project_status.get("caycStatus"),
			"period": project_status.get("period"),
			"prediction_status": prediction_status,
			"would_pass": prediction_would_pass,
			"evaluated_conditions": evaluated_conditions,
			"unsupported_conditions": unsupported_conditions,
			"notes": [
				"This prediction evaluates only SonarQube quality gate conditions that can be derived from local coverage.py metrics.",
				"Unsupported gate conditions still require a real Sonar analysis to determine the final gate result.",
			],
		}

	def _resolve_remote_analysis_context(
		self,
		*,
		project: str,
		branch: str,
		pull_request: str,
	) -> tuple[dict[str, Any], list[dict[str, Any]]]:
		metas: list[dict[str, Any]] = []
		context: dict[str, Any] = {
			"scope_type": "pull_request" if pull_request else ("branch" if branch else "project"),
			"requested_scope": {
				"project_key": project,
				"branch": branch or "",
				"pull_request": pull_request or "",
			},
			"resolved_scope": {
				"project_key": project,
				"branch": branch or "",
				"pull_request": pull_request or "",
				"analysis_date": "",
				"quality_gate_status": "",
			},
			"notes": [],
		}

		if pull_request:
			pull_request_context: dict[str, Any] = {
				"lookup_attempted": True,
				"lookup_supported": None,
				"requested": pull_request,
				"matched": False,
			}
			if not hasattr(self.client, "list_project_pull_requests"):
				pull_request_context["lookup_supported"] = False
				pull_request_context["lookup_error"] = "The configured Sonar client does not expose pull request discovery."
				context["notes"].append("Pull request discovery is unavailable in the current Sonar client configuration.")
				context["pull_request"] = pull_request_context
				return context, metas

			try:
				payload, meta = self.client.list_project_pull_requests(project)
				metas.append(meta)
				pull_requests = self.client.normalize_pull_requests(payload) if hasattr(self.client, "normalize_pull_requests") else []
				pull_request_context["lookup_supported"] = True
				pull_request_context["available_count"] = len(pull_requests)
				matched = next(
					(
						item
						for item in pull_requests
						if str(item.get("key") or "").strip() == pull_request.strip()
					),
					None,
				)
				if matched is not None:
					status = matched.get("status") if isinstance(matched.get("status"), dict) else {}
					pull_request_context.update(
						{
							"matched": True,
							"title": matched.get("title"),
							"branch": matched.get("branch"),
							"base": matched.get("base"),
							"analysis_date": matched.get("analysisDate"),
							"quality_gate_status": status.get("qualityGateStatus"),
						}
					)
					context["resolved_scope"].update(
						{
							"branch": str(matched.get("branch") or branch or ""),
							"pull_request": pull_request,
							"analysis_date": str(matched.get("analysisDate") or ""),
							"quality_gate_status": str(status.get("qualityGateStatus") or ""),
						}
					)
				else:
					context["notes"].append(
						f"No Sonar pull request analysis metadata was found for pull request '{pull_request}'."
					)
			except SonarHttpError as exc:
				pull_request_context["lookup_supported"] = False if exc.status_code == 404 else None
				pull_request_context["lookup_error"] = str(exc)
				if exc.status_code == 404:
					context["notes"].append(
						"This SonarQube server does not expose pull request listing for the requested project or edition."
					)
				else:
					context["notes"].append(f"Pull request discovery failed: {exc}")
			context["pull_request"] = pull_request_context
			return context, metas

		branch_context: dict[str, Any] = {
			"lookup_attempted": False,
			"requested": branch or "",
			"matched": False,
		}
		if not hasattr(self.client, "list_project_branches"):
			context["branch"] = branch_context
			return context, metas

		try:
			payload, meta = self.client.list_project_branches(project)
			metas.append(meta)
			branch_context["lookup_attempted"] = True
			branches = self.client.normalize_branches(payload) if hasattr(self.client, "normalize_branches") else []
			matched_branch: dict[str, Any] | None = None
			if branch.strip():
				matched_branch = next(
					(
						item
						for item in branches
						if str(item.get("name") or "").strip().lower() == branch.strip().lower()
					),
					None,
				)
			else:
				matched_branch = next((item for item in branches if bool(item.get("isMain"))), None)

			if matched_branch is not None:
				status = matched_branch.get("status") if isinstance(matched_branch.get("status"), dict) else {}
				resolved_branch = str(matched_branch.get("name") or branch or "")
				branch_context.update(
					{
						"matched": True,
						"resolved": resolved_branch,
						"is_main": bool(matched_branch.get("isMain")),
						"analysis_date": matched_branch.get("analysisDate"),
						"quality_gate_status": status.get("qualityGateStatus"),
					}
				)
				context["resolved_scope"].update(
					{
						"branch": resolved_branch,
						"analysis_date": str(matched_branch.get("analysisDate") or ""),
						"quality_gate_status": str(status.get("qualityGateStatus") or ""),
					}
				)
			elif branch.strip():
				context["notes"].append(f"Branch '{branch}' was not returned by SonarQube for project '{project}'.")
		except SonarHttpError as exc:
			branch_context["lookup_attempted"] = True
			branch_context["lookup_error"] = str(exc)
			context["notes"].append(f"Branch discovery failed: {exc}")

		context["branch"] = branch_context
		return context, metas

	def _build_remote_quality_gate_summary(
		self,
		*,
		project_key: str,
		branch: str,
		pull_request: str,
		overall_coverage: float | None,
		coverage_threshold: float,
		analysis_context: dict[str, Any],
	) -> tuple[dict[str, Any], dict[str, Any]]:
		payload, meta = self.client.get_quality_gate_status(project_key=project_key, branch=branch, pull_request=pull_request)
		project_status = payload.get("projectStatus") if isinstance(payload.get("projectStatus"), dict) else {}
		conditions_payload = project_status.get("conditions") if isinstance(project_status.get("conditions"), list) else []
		conditions: list[dict[str, Any]] = []
		failing_conditions: list[dict[str, Any]] = []
		for raw_condition in conditions_payload:
			if not isinstance(raw_condition, dict):
				continue
			condition = compact_dict(
				{
					"metric": raw_condition.get("metricKey"),
					"status": raw_condition.get("status"),
					"comparator": raw_condition.get("comparator"),
					"threshold": _safe_float(raw_condition.get("errorThreshold")),
					"actual": _safe_float(raw_condition.get("actualValue")),
					"period_index": _safe_int(raw_condition.get("periodIndex"), default=0) or None,
				}
			)
			conditions.append(condition)
			if str(raw_condition.get("status") or "").strip().upper() not in {"", "OK"}:
				failing_conditions.append(condition)

		current_status = str(project_status.get("status") or "NONE").upper()
		decision_status, would_pass = _quality_gate_status_to_decision(current_status)
		meets_requested_threshold = None if overall_coverage is None else round(float(overall_coverage), 2) >= round(float(coverage_threshold), 2)
		resolved_scope = analysis_context.get("resolved_scope") if isinstance(analysis_context.get("resolved_scope"), dict) else {}
		quality_gate = {
			"source": "sonar_remote_analysis",
			"evaluated_remotely": True,
			"scope_type": analysis_context.get("scope_type"),
			"status": decision_status,
			"current_status": current_status,
			"would_pass": would_pass,
			"coverage_threshold_pct": float(coverage_threshold),
			"overall_coverage_pct": None if overall_coverage is None else round(float(overall_coverage), 2),
			"meets_requested_coverage_threshold": meets_requested_threshold,
			"project_key": project_key,
			"resolved_branch": resolved_scope.get("branch") or branch or "",
			"resolved_pull_request": resolved_scope.get("pull_request") or pull_request or "",
			"analysis_date": resolved_scope.get("analysis_date") or "",
			"ignored_conditions": bool(project_status.get("ignoredConditions", False)),
			"cayc_status": project_status.get("caycStatus"),
			"period": project_status.get("period"),
			"conditions": conditions,
			"failing_conditions": failing_conditions,
		}
		return quality_gate, meta

	def _run_local_command(
		self,
		command: list[str],
		*,
		cwd: Path,
		timeout: int,
	) -> subprocess.CompletedProcess[str]:
		return subprocess.run(
			command,
			cwd=str(cwd),
			capture_output=True,
			text=True,
			timeout=max(1, int(timeout)),
			check=False,
		)

	def access_probe(self, *, project: str = "", branch: str = "", project_query: str = "", include_projects: bool = False) -> dict[str, Any]:
		validation = self.client.validate_token()
		capabilities = _build_capabilities()
		permission_gaps: set[str] = set()
		metas: list[dict[str, Any]] = []
		projects: list[dict[str, Any]] = []
		branches: list[dict[str, Any]] = []

		try:
			payload, meta = self.client.list_projects(query=project_query, page=1, page_size=25)
			metas.append(meta)
			capabilities["can_list_projects"] = "confirmed"
			if include_projects:
				projects = [
					compact_dict(
						{
							"key": item.get("key"),
							"name": item.get("name"),
							"qualifier": item.get("qualifier"),
							"visibility": item.get("visibility"),
							"last_analysis_date": item.get("lastAnalysisDate"),
						}
					)
					for item in self.client.normalize_project_list(payload)
				]
		except SonarHttpError as exc:
			capabilities["can_list_projects"] = "unavailable"
			if isinstance(exc, SonarPermissionError):
				permission_gaps.add("Browse permission is missing for project discovery.")

		if project:
			try:
				payload, meta = self.client.list_project_branches(project)
				metas.append(meta)
				capabilities["can_list_branches"] = "confirmed"
				branches = [
					compact_dict(
						{
							"name": item.get("name"),
							"is_main": item.get("isMain"),
							"analysis_date": item.get("analysisDate"),
						}
					)
					for item in self.client.normalize_branches(payload)
				]
			except SonarHttpError as exc:
				capabilities["can_list_branches"] = "unavailable"
				if isinstance(exc, SonarPermissionError):
					permission_gaps.add("Browse permission is missing for branch discovery.")

			try:
				_, meta = self.client.get_component_measures(project, branch=branch)
				metas.append(meta)
				capabilities["can_read_project_measures"] = "confirmed"
			except SonarHttpError as exc:
				capabilities["can_read_project_measures"] = "unavailable"
				if isinstance(exc, SonarPermissionError):
					permission_gaps.add("Browse permission is missing for project measures.")

			try:
				_, meta = self.client.get_measures_component_tree(project, branch=branch, page=1, page_size=1)
				metas.append(meta)
				capabilities["can_read_file_measures"] = "confirmed"
			except SonarHttpError as exc:
				capabilities["can_read_file_measures"] = "unavailable"
				if isinstance(exc, SonarPermissionError):
					permission_gaps.add("Browse permission is missing for file measures.")

		mode = _access_mode(validation, metas, permission_gaps)
		return {
			"ok": True,
			"server": "sonar",
			"generated_at": utc_now_iso(),
			"access_mode": mode,
			"authentication": self.client.build_auth_section(validation, metas),
			"capabilities": capabilities,
			"permission_gaps": sorted(permission_gaps),
			"projects": projects,
			"branches": branches,
		}

	def list_projects(self, *, project_query: str = "", page: int = 1, page_size: int = SONAR_PROJECTS_PAGE_SIZE, include_branches_for: str = "") -> dict[str, Any]:
		validation = self.client.validate_token()
		payload, meta = self.client.list_projects(query=project_query, page=page, page_size=page_size)
		projects = []
		for item in self.client.normalize_project_list(payload):
			projects.append(
				compact_dict(
					{
						"key": item.get("key"),
						"name": item.get("name"),
						"qualifier": item.get("qualifier"),
						"visibility": item.get("visibility"),
						"last_analysis_date": item.get("lastAnalysisDate"),
					}
				)
			)

		branches: list[dict[str, Any]] = []
		metas = [meta]
		permission_gaps: set[str] = set()
		if include_branches_for:
			try:
				branch_payload, branch_meta = self.client.list_project_branches(include_branches_for)
				metas.append(branch_meta)
				branches = [
					compact_dict(
						{
							"name": item.get("name"),
							"is_main": item.get("isMain"),
							"analysis_date": item.get("analysisDate"),
						}
					)
					for item in self.client.normalize_branches(branch_payload)
				]
			except SonarPermissionError:
				permission_gaps.add("Browse permission is missing for branch discovery.")

		return {
			"ok": True,
			"server": "sonar",
			"generated_at": utc_now_iso(),
			"access_mode": _access_mode(validation, metas, permission_gaps),
			"authentication": self.client.build_auth_section(validation, metas),
			"projects": projects,
			"branches": branches,
			"page": max(1, int(page)),
			"page_size": max(1, int(page_size)),
		}

	def _collect_line_numbers_for_file(
		self,
		*,
		file_key: str,
		branch: str = "",
		pull_request: str = "",
	) -> tuple[list[int], list[int], str]:
		uncovered_lines: list[int] = []
		covered_lines: list[int] = []
		quality = "unavailable"
		try:
			internal_payload, _ = self.client.get_component_app(file_key, branch=branch, pull_request=pull_request)
			uncovered_lines, covered_lines, _ = _extract_line_details(internal_payload)
			if uncovered_lines or covered_lines:
				quality = "estimated"
		except SonarHttpError:
			quality = "unavailable"
		return uncovered_lines, covered_lines, quality

	def coverage_report(
		self,
		*,
		project: str,
		branch: str = "",
		pull_request: str = "",
		file_limit: int = 25,
		coverage_threshold: float = 80.0,
		include_raw: bool = False,
	) -> dict[str, Any]:
		if not project.strip():
			raise SonarError("A Sonar project key is required.")
		if branch and pull_request:
			raise SonarError("Provide either branch or pull_request, not both.")

		validation = self.client.validate_token()
		permission_gaps: set[str] = set()
		metas: list[dict[str, Any]] = []

		try:
			project_payload, project_meta = self.client.get_component_measures(project, branch=branch, pull_request=pull_request)
		except SonarHttpError as exc:
			if pull_request and exc.status_code == 404:
				raise SonarError(
					f"Sonar project '{project}' does not have a coverage report for pull request '{pull_request}'."
				) from exc
			if branch and exc.status_code == 404:
				raise SonarError(f"Sonar project '{project}' does not have a coverage report for branch '{branch}'.") from exc
			raise
		metas.append(project_meta)
		project_component = project_payload.get("component") if isinstance(project_payload.get("component"), dict) else {}
		project_measures = self.client.parse_measures(project_component)
		analysis_context, analysis_metas = self._resolve_remote_analysis_context(project=project, branch=branch, pull_request=pull_request)
		metas.extend(analysis_metas)

		file_components: list[dict[str, Any]] = []
		page = 1
		while True:
			page_payload, page_meta = self.client.get_measures_component_tree(
				project,
				branch=branch,
				pull_request=pull_request,
				page=page,
				page_size=SONAR_FILE_PAGE_SIZE,
			)
			metas.append(page_meta)
			components = self.client.normalize_components(page_payload)
			file_components.extend(components)
			paging = page_payload.get("paging") if isinstance(page_payload.get("paging"), dict) else {}
			total = _safe_int(paging.get("total"))
			page_size_value = max(1, _safe_int(paging.get("pageSize") or SONAR_FILE_PAGE_SIZE))
			page_index = max(1, _safe_int(paging.get("pageIndex") or page))
			if not components or (total and page_index * page_size_value >= total):
				break
			page += 1

		total_uncovered = _safe_int(project_measures.get("uncovered_lines"))
		if total_uncovered <= 0:
			total_uncovered = sum(_safe_int(self.client.parse_measures(component).get("uncovered_lines")) for component in file_components)

		files: list[dict[str, Any]] = []
		for component in file_components:
			measures = self.client.parse_measures(component)
			entry = {
				"file_key": component.get("key"),
				"file_path": _coalesce_path(component),
				"coverage": _safe_float(measures.get("coverage")),
				"line_coverage": _safe_float(measures.get("line_coverage")),
				"branch_coverage": _safe_float(measures.get("branch_coverage")),
				"lines_to_cover": _safe_int(measures.get("lines_to_cover")),
				"uncovered_lines": _safe_int(measures.get("uncovered_lines")),
				"conditions_to_cover": _safe_int(measures.get("conditions_to_cover")),
				"uncovered_conditions": _safe_int(measures.get("uncovered_conditions")),
				"new_coverage": _safe_float(measures.get("new_coverage")),
			}
			entry["estimated_project_impact_pct"] = round((100.0 * entry["uncovered_lines"] / total_uncovered), 2) if total_uncovered > 0 else 0.0
			entry["priority_score"] = _priority_score(entry, total_uncovered)
			entry["priority_reason"] = _priority_reason(entry)
			entry["recommended_test_focus"] = _recommended_focus(entry)
			entry["likely_help_overall_coverage"] = entry["estimated_project_impact_pct"] >= 3.0 or entry["uncovered_lines"] >= 15
			has_executable_metrics = entry["lines_to_cover"] > 0 or entry["uncovered_lines"] > 0 or entry["coverage"] is not None
			entry["has_executable_coverage_metrics"] = has_executable_metrics
			entry["covered_lines"] = max(0, entry["lines_to_cover"] - entry["uncovered_lines"])
			entry["uncovered_line_numbers"] = []
			entry["covered_line_numbers"] = []
			entry["line_number_quality"] = "unavailable"
			entry["priority"] = _priority_label(
				entry["priority_score"],
				executable_metrics=has_executable_metrics,
				likely_help=entry["likely_help_overall_coverage"],
			)
			entry["should_target_first"] = bool(has_executable_metrics and entry["priority"] in {"high", "medium"})
			entry["data_quality"] = {
				"coverage": "confirmed" if entry["coverage"] is not None else "unavailable",
				"uncovered_line_numbers": "unavailable",
				"covered_line_numbers": "unavailable",
			}
			files.append(entry)

		files.sort(
			key=lambda item: (
				1 if item["has_executable_coverage_metrics"] else 0,
				item["priority_score"],
				item["uncovered_lines"],
				-(item["coverage"] or 0.0),
			),
			reverse=True,
		)
		file_limit = max(1, int(file_limit))
		top_files = files[:file_limit]
		for entry in top_files:
			if not entry["has_executable_coverage_metrics"]:
				continue
			uncovered_line_numbers, covered_line_numbers, line_number_quality = self._collect_line_numbers_for_file(
				file_key=str(entry.get("file_key") or ""),
				branch=branch,
				pull_request=pull_request,
			)
			entry["uncovered_line_numbers"] = uncovered_line_numbers
			entry["covered_line_numbers"] = covered_line_numbers
			entry["line_number_quality"] = line_number_quality
			entry["data_quality"]["uncovered_line_numbers"] = line_number_quality
			entry["data_quality"]["covered_line_numbers"] = line_number_quality
		below_threshold = [
			item for item in files
			if item["has_executable_coverage_metrics"] and item.get("coverage") is not None and (item.get("coverage") or 0.0) < float(coverage_threshold)
		]
		total_lines_considered = _safe_int(project_measures.get("lines_to_cover"))
		total_covered_lines = max(0, total_lines_considered - total_uncovered)
		files_with_uncovered_lines = [item for item in files if _safe_int(item.get("uncovered_lines")) > 0]
		quality_gate: dict[str, Any] | None = None
		quality_gate_error = ""
		try:
			quality_gate, quality_gate_meta = self._build_remote_quality_gate_summary(
				project_key=str(project_component.get("key") or project),
				branch=branch,
				pull_request=pull_request,
				overall_coverage=_safe_float(project_measures.get("coverage")),
				coverage_threshold=float(coverage_threshold),
				analysis_context=analysis_context,
			)
			metas.append(quality_gate_meta)
		except SonarHttpError as exc:
			quality_gate_error = str(exc)
			quality_gate = {
				"source": "sonar_remote_analysis",
				"evaluated_remotely": False,
				"scope_type": analysis_context.get("scope_type"),
				"status": "unknown",
				"current_status": "UNAVAILABLE",
				"would_pass": None,
				"coverage_threshold_pct": float(coverage_threshold),
				"overall_coverage_pct": _safe_float(project_measures.get("coverage")),
				"meets_requested_coverage_threshold": (
					None
					if _safe_float(project_measures.get("coverage")) is None
					else _safe_float(project_measures.get("coverage")) >= float(coverage_threshold)
				),
				"project_key": str(project_component.get("key") or project),
				"resolved_branch": str((analysis_context.get("resolved_scope") or {}).get("branch") or branch or ""),
				"resolved_pull_request": str((analysis_context.get("resolved_scope") or {}).get("pull_request") or pull_request or ""),
				"conditions": [],
				"failing_conditions": [],
				"error": quality_gate_error,
			}
		project_summary = {
			"project_key": project_component.get("key") or project,
			"project_name": project_component.get("name") or project,
			"branch_name": str((analysis_context.get("resolved_scope") or {}).get("branch") or branch or project_component.get("branch") or "main"),
			"pull_request": pull_request or "",
			"overall_coverage_pct": _safe_float(project_measures.get("coverage")),
			"line_coverage_pct": _safe_float(project_measures.get("line_coverage")),
			"branch_coverage_pct": _safe_float(project_measures.get("branch_coverage")),
			"total_lines_considered": total_lines_considered,
			"total_covered_lines": total_covered_lines,
			"total_uncovered_lines": total_uncovered,
			"total_files_analyzed": len(files),
			"total_files_with_uncovered_lines": len(files_with_uncovered_lines),
			"total_files_with_executable_coverage": len([item for item in files if item["has_executable_coverage_metrics"]]),
		}
		meets_requested_threshold = None
		if project_summary["overall_coverage_pct"] is not None:
			meets_requested_threshold = float(project_summary["overall_coverage_pct"]) >= float(coverage_threshold)
		decision_status = "unknown"
		decision_source = "none"
		would_pass_quality_gate: bool | None = None
		message = "SonarQube did not return enough information to determine a coverage decision."
		if quality_gate is not None and quality_gate.get("evaluated_remotely"):
			decision_status = str(quality_gate.get("status") or "unknown")
			decision_source = "sonar_quality_gate"
			would_pass_quality_gate = quality_gate.get("would_pass") if isinstance(quality_gate.get("would_pass"), bool) or quality_gate.get("would_pass") is None else None
			if decision_status == "pass":
				message = (
					f"SonarQube quality gate is passing for {_format_remote_scope(str(project_summary['project_key']), branch=branch, pull_request=pull_request)}."
				)
			elif decision_status == "fail":
				message = (
					f"SonarQube quality gate is failing for {_format_remote_scope(str(project_summary['project_key']), branch=branch, pull_request=pull_request)}."
				)
			else:
				message = (
					f"SonarQube did not report a definitive quality gate result for {_format_remote_scope(str(project_summary['project_key']), branch=branch, pull_request=pull_request)}."
				)
		elif meets_requested_threshold is not None:
			decision_status = "pass" if meets_requested_threshold else "fail"
			decision_source = "requested_coverage_threshold"
			message = (
				f"Remote Sonar coverage is {project_summary['overall_coverage_pct']:.2f}% and "
				f"{'meets' if meets_requested_threshold else 'does not meet'} the requested threshold of {float(coverage_threshold):.2f}%."
			)

		payload = {
			"ok": True,
			"server": "sonar",
			"report_type": "coverage_improvement",
			"generated_at": utc_now_iso(),
			"access_mode": _access_mode(validation, metas, permission_gaps),
			"authentication": self.client.build_auth_section(validation, metas),
			"project_summary": project_summary,
			"analysis_context": analysis_context,
			"quality_gate": quality_gate,
			"decision_summary": {
				"status": decision_status,
				"source": decision_source,
				"scope_type": analysis_context.get("scope_type"),
				"project_key": project_summary["project_key"],
				"branch_name": project_summary["branch_name"],
				"pull_request": project_summary["pull_request"],
				"quality_gate_status": None if quality_gate is None else quality_gate.get("current_status"),
				"would_pass_quality_gate": would_pass_quality_gate,
				"requested_coverage_threshold_pct": float(coverage_threshold),
				"overall_coverage_pct": project_summary["overall_coverage_pct"],
				"meets_requested_coverage_threshold": meets_requested_threshold,
				"message": message,
			},
			"files": [_normalize_file_record(item) for item in top_files],
			"priority": _build_priority_section(top_files, limit=min(10, len(top_files))),
		}
		if quality_gate_error:
			payload["quality_gate_error"] = quality_gate_error
		if include_raw:
			payload["raw"] = {
				"project_measures": project_payload,
				"file_count": len(file_components),
			}
		return payload

	def local_coverage_report(
		self,
		*,
		project: str = "",
		project_query: str = "",
		branch: str = "",
		pull_request: str = "",
		working_directory: str = "",
		source_paths: str = "",
		pytest_args: str = "",
		coverage_threshold: float = 80.0,
		file_limit: int = 25,
		local_timeout: int | None = None,
		compare_with_remote: bool = False,
		include_raw: bool = False,
	) -> dict[str, Any]:
		workspace_root = Path(working_directory).expanduser().resolve() if str(working_directory or "").strip() else _default_workspace_root()
		if not workspace_root.exists() or not workspace_root.is_dir():
			raise SonarError(f"Local working directory does not exist: {workspace_root}")

		resolved_source_paths = _split_delimited_values(source_paths) or _default_local_source_paths(workspace_root)
		resolved_pytest_args = shlex.split(str(pytest_args or ""), posix=os.name != "nt") if str(pytest_args or "").strip() else []
		resolved_timeout = max(1, int(local_timeout or self.credentials.timeout or 300))
		file_limit = max(1, int(file_limit))
		threshold = float(coverage_threshold)

		with tempfile.TemporaryDirectory(prefix="sonar-local-coverage-") as temp_dir:
			coverage_file = Path(temp_dir) / ".coverage"
			coverage_json = Path(temp_dir) / "coverage.json"
			coverage_run_command = [
				sys.executable,
				"-m",
				"coverage",
				"run",
				f"--data-file={coverage_file}",
			]
			if resolved_source_paths and resolved_source_paths != ["."]:
				coverage_run_command.append(f"--source={','.join(resolved_source_paths)}")
			coverage_run_command.extend(["-m", "pytest", *resolved_pytest_args])

			run_result = self._run_local_command(
				coverage_run_command,
				cwd=workspace_root,
				timeout=resolved_timeout,
			)
			if run_result.returncode != 0:
				error_excerpt = _tail_output(run_result.stderr or run_result.stdout)
				raise SonarError(
					f"Local coverage test run failed with exit code {run_result.returncode}."
					f" {error_excerpt}".rstrip()
				)

			json_result = self._run_local_command(
				[
					sys.executable,
					"-m",
					"coverage",
					"json",
					f"--data-file={coverage_file}",
					"-o",
					str(coverage_json),
				],
				cwd=workspace_root,
				timeout=resolved_timeout,
			)
			if json_result.returncode != 0:
				error_excerpt = _tail_output(json_result.stderr or json_result.stdout)
				raise SonarError(
					f"Failed to export local coverage JSON with exit code {json_result.returncode}."
					f" {error_excerpt}".rstrip()
				)

			try:
				coverage_payload = json.loads(coverage_json.read_text(encoding="utf-8"))
			except (OSError, json.JSONDecodeError) as exc:
				raise SonarError("Local coverage JSON output was unreadable.") from exc

		if not isinstance(coverage_payload, dict):
			raise SonarError("Local coverage output was not a JSON object.")

		totals = coverage_payload.get("totals") if isinstance(coverage_payload.get("totals"), dict) else {}
		total_lines_considered = _safe_int(totals.get("num_statements"))
		total_uncovered_lines = _safe_int(totals.get("missing_lines"))
		total_covered_lines = max(0, total_lines_considered - total_uncovered_lines)
		overall_coverage = _safe_float(totals.get("percent_covered"))
		line_coverage = round((100.0 * total_covered_lines / total_lines_considered), 2) if total_lines_considered > 0 else None
		if overall_coverage is None:
			overall_coverage = _safe_float(totals.get("percent_covered_display"))
		total_branches = 0
		total_covered_branches = 0

		files: list[dict[str, Any]] = []
		coverage_files = coverage_payload.get("files") if isinstance(coverage_payload.get("files"), dict) else {}
		for file_path, file_payload in coverage_files.items():
			if not isinstance(file_payload, dict):
				continue
			summary = file_payload.get("summary") if isinstance(file_payload.get("summary"), dict) else {}
			missing_line_numbers = [int(line) for line in file_payload.get("missing_lines", []) if isinstance(line, int)]
			covered_line_numbers = [int(line) for line in file_payload.get("executed_lines", []) if isinstance(line, int)]
			coverage = _safe_float(summary.get("percent_covered"))
			if coverage is None:
				coverage = _safe_float(summary.get("percent_covered_display"))
			lines_to_cover = _safe_int(summary.get("num_statements"))
			uncovered_lines = _safe_int(summary.get("missing_lines"), default=len(missing_line_numbers))
			covered_lines = _safe_int(summary.get("covered_lines"), default=max(0, lines_to_cover - uncovered_lines))
			branch_coverage = _safe_branch_coverage(summary)
			total_branches += _safe_int(summary.get("num_branches"))
			total_covered_branches += _safe_int(summary.get("covered_branches"))
			entry = {
				"file_key": file_path,
				"file_path": str(file_path).replace("\\", "/"),
				"coverage": coverage,
				"line_coverage": coverage,
				"branch_coverage": branch_coverage,
				"lines_to_cover": lines_to_cover,
				"covered_lines": covered_lines,
				"uncovered_lines": uncovered_lines,
				"conditions_to_cover": _safe_int(summary.get("num_branches")),
				"uncovered_conditions": _safe_int(summary.get("missing_branches")),
				"estimated_project_impact_pct": round((100.0 * uncovered_lines / total_uncovered_lines), 2) if total_uncovered_lines > 0 else 0.0,
				"has_executable_coverage_metrics": lines_to_cover > 0,
				"uncovered_line_numbers": missing_line_numbers,
				"covered_line_numbers": covered_line_numbers,
				"line_number_quality": "confirmed",
				"priority_score": 0.0,
				"priority_reason": "",
				"recommended_test_focus": "",
				"likely_help_overall_coverage": False,
				"priority": "low",
				"should_target_first": False,
			}
			entry["priority_score"] = _priority_score(entry, total_uncovered_lines)
			entry["priority_reason"] = _priority_reason(entry)
			entry["recommended_test_focus"] = _recommended_focus(entry)
			entry["likely_help_overall_coverage"] = entry["estimated_project_impact_pct"] >= 3.0 or uncovered_lines >= 15
			entry["priority"] = _priority_label(
				entry["priority_score"],
				executable_metrics=entry["has_executable_coverage_metrics"],
				likely_help=entry["likely_help_overall_coverage"],
			)
			entry["should_target_first"] = bool(entry["has_executable_coverage_metrics"] and entry["priority"] in {"high", "medium"})
			files.append(entry)

		files.sort(
			key=lambda item: (
				1 if item["has_executable_coverage_metrics"] else 0,
				item["priority_score"],
				item["uncovered_lines"],
				-(item["coverage"] or 0.0),
			),
			reverse=True,
		)
		top_files = files[:file_limit]
		files_with_uncovered_lines = [item for item in files if _safe_int(item.get("uncovered_lines")) > 0]
		files_below_threshold = [
			item for item in files
			if item["has_executable_coverage_metrics"] and item.get("coverage") is not None and (item.get("coverage") or 0.0) < threshold
		]
		would_meet_threshold = overall_coverage is not None and overall_coverage >= threshold
		project_name = project.strip() or workspace_root.name
		overall_branch_coverage = round((100.0 * total_covered_branches / total_branches), 2) if total_branches > 0 else None
		sonar_project = {
			"lookup_attempted": False,
			"matched": False,
			"query_used": "",
			"match_strategy": "not_attempted",
			"project_key": project.strip() or "",
			"project_name": project_name,
			"branch_name": branch or "",
			"attempts": [],
		}
		sonar_quality_gate: dict[str, Any] | None = None
		sonar_quality_gate_error = ""
		if self.credentials.base_url:
			sonar_project = self._resolve_remote_project_for_workspace(
				explicit_project=project,
				project_query=project_query,
				workspace_root=workspace_root,
				branch=branch,
				pull_request=pull_request,
			)
			if sonar_project.get("matched") and sonar_project.get("project_key"):
				try:
					sonar_quality_gate = self._predict_remote_quality_gate(
						project_key=str(sonar_project.get("project_key") or ""),
						branch=branch,
						pull_request=pull_request,
						overall_coverage=overall_coverage,
						line_coverage=line_coverage,
						branch_coverage=overall_branch_coverage,
					)
				except SonarError as exc:
					sonar_quality_gate_error = str(exc)

		payload = {
			"ok": True,
			"server": "sonar",
			"operation": "local_report",
			"report_type": "local_coverage_prediction",
			"generated_at": utc_now_iso(),
			"project_summary": {
				"project_key": project.strip() or str(sonar_project.get("project_key") or "local-workspace"),
				"project_name": project_name,
				"branch_name": branch or "local",
				"pull_request": pull_request or "",
				"overall_coverage_pct": overall_coverage,
				"line_coverage_pct": line_coverage,
				"branch_coverage_pct": overall_branch_coverage,
				"total_lines_considered": total_lines_considered,
				"total_covered_lines": total_covered_lines,
				"total_uncovered_lines": total_uncovered_lines,
				"total_files_analyzed": len(files),
				"total_files_with_uncovered_lines": len(files_with_uncovered_lines),
				"total_files_with_executable_coverage": len([item for item in files if item["has_executable_coverage_metrics"]]),
			},
			"threshold_pct": threshold,
			"would_meet_threshold": would_meet_threshold,
			"predicted_sonar_outcome": "pass" if would_meet_threshold else "fail",
			"prediction_basis": "Local pytest coverage via coverage.py. SonarQube can still differ if exclusions, imported reports, or branch settings are different.",
			"workspace_root": str(workspace_root),
			"test_command": " ".join(coverage_run_command),
			"source_paths": resolved_source_paths,
			"quality_gate": _build_quality_gate_prediction(
				threshold=threshold,
				overall_coverage=overall_coverage,
				would_meet_threshold=would_meet_threshold,
				files_below_threshold=files_below_threshold,
				mode="sonar_quality_gate_prediction" if sonar_quality_gate is not None else "threshold_prediction",
			),
			"sonar_project": sonar_project,
			"files": [_normalize_file_record(item) for item in top_files],
			"priority": _build_priority_section(top_files, limit=min(10, len(top_files))),
		}
		if sonar_quality_gate is not None:
			payload["sonar_quality_gate"] = sonar_quality_gate
			payload["quality_gate"]["sonar_prediction_status"] = sonar_quality_gate.get("prediction_status")
			payload["quality_gate"]["sonar_prediction_would_pass"] = sonar_quality_gate.get("would_pass")
		if sonar_quality_gate_error:
			payload["sonar_quality_gate_error"] = sonar_quality_gate_error

		if compare_with_remote and sonar_project.get("matched") and sonar_project.get("project_key") and self.credentials.base_url:
			try:
				remote_payload = self.coverage_report(
					project=str(sonar_project.get("project_key") or project),
					branch=branch,
					pull_request=pull_request,
					file_limit=min(10, file_limit),
					coverage_threshold=threshold,
					include_raw=False,
				)
				remote_summary = remote_payload.get("project_summary") if isinstance(remote_payload.get("project_summary"), dict) else {}
				remote_coverage = _safe_float(remote_summary.get("overall_coverage_pct"))
				payload["remote_comparison"] = {
					"remote_project_summary": remote_summary,
					"local_minus_remote_coverage_pct": None if overall_coverage is None or remote_coverage is None else round(overall_coverage - remote_coverage, 2),
				}
			except SonarError as exc:
				payload["remote_comparison_error"] = str(exc)

		if include_raw:
			payload["raw"] = {
				"coverage_json": coverage_payload,
			}
		return payload

	def predict_quality_gate(
		self,
		*,
		project: str = "",
		project_query: str = "",
		branch: str = "",
		pull_request: str = "",
		working_directory: str = "",
		local_metrics: dict[str, Any] | None = None,
	) -> dict[str, Any]:
		"""Predict whether the workspace will clear the Sonar quality gate.

		This operation does NOT run any local tests. Callers (typically the
		coding agent) are expected to measure coverage themselves using whatever
		tooling fits the workspace stack (pytest+coverage, jest, dotnet test,
		jacoco, ...) and pass the resulting numbers in via ``local_metrics``.

		The tool returns:
		  * The Sonar gate definition (conditions, comparators, thresholds)
		  * The current remote gate status
		  * If ``local_metrics`` is supplied, a per-condition local evaluation
		    and an overall ``would_pass`` decision
		  * If ``local_metrics`` is omitted, ``measurement_instructions`` that
		    tell the caller exactly which metrics to measure and the JSON shape
		    to send back on the next call.
		"""
		if not self.credentials.base_url:
			raise SonarError("SONAR_BASE_URL must be configured to fetch the quality gate definition.")

		workspace_root = Path(working_directory).expanduser().resolve() if str(working_directory or "").strip() else _default_workspace_root()

		sonar_project = self._resolve_remote_project_for_workspace(
			explicit_project=project,
			project_query=project_query,
			workspace_root=workspace_root,
			branch=branch,
			pull_request=pull_request,
		)
		if not sonar_project.get("matched") or not sonar_project.get("project_key"):
			raise SonarError(
				"Could not resolve a Sonar project for this workspace. "
				"Pass project=<sonar_project_key> or project_query=<name> explicitly."
			)
		project_key = str(sonar_project["project_key"])

		try:
			gate_payload, _ = self.client.get_quality_gate_status(
				project_key=project_key, branch=branch, pull_request=pull_request
			)
		except SonarHttpError as exc:
			raise SonarError(
				f"Could not fetch quality gate status for {_format_remote_scope(project_key, branch=branch, pull_request=pull_request)}: {exc}"
			) from exc

		project_status = gate_payload.get("projectStatus") if isinstance(gate_payload.get("projectStatus"), dict) else {}
		raw_conditions = project_status.get("conditions") if isinstance(project_status.get("conditions"), list) else []

		gate_definition: list[dict[str, Any]] = []
		for raw_condition in raw_conditions:
			if not isinstance(raw_condition, dict):
				continue
			metric_key = str(raw_condition.get("metricKey") or "").strip()
			gate_definition.append(
				compact_dict(
					{
						"metric": metric_key,
						"comparator": str(raw_condition.get("comparator") or "").strip().upper(),
						"error_threshold": _safe_float(raw_condition.get("errorThreshold")),
						"remote_actual": _safe_float(raw_condition.get("actualValue")),
						"remote_status": raw_condition.get("status"),
						"on_new_code": metric_key.startswith("new_"),
						"evaluable_locally": metric_key in SONAR_LOCALLY_EVALUABLE_QUALITY_GATE_METRICS,
					}
				)
			)

		local_evaluation: dict[str, Any] | None = None
		if local_metrics:
			normalized_metrics: dict[str, float] = {}
			for key, value in dict(local_metrics).items():
				parsed = _safe_float(value)
				if parsed is not None:
					normalized_metrics[str(key).strip()] = float(parsed)

			evaluated: list[dict[str, Any]] = []
			unsupported: list[dict[str, Any]] = []
			for raw_condition in raw_conditions:
				if not isinstance(raw_condition, dict):
					continue
				metric_key = str(raw_condition.get("metricKey") or "").strip()
				comparator = str(raw_condition.get("comparator") or "").strip().upper()
				threshold = _safe_float(raw_condition.get("errorThreshold"))
				local_actual = normalized_metrics.get(metric_key)
				if local_actual is None or threshold is None:
					unsupported.append(
						compact_dict(
							{
								"metric": metric_key,
								"comparator": comparator,
								"threshold": threshold,
								"remote_actual": _safe_float(raw_condition.get("actualValue")),
								"remote_status": raw_condition.get("status"),
								"reason": "No local value supplied for this metric in `local_metrics`."
								if threshold is not None
								else "Sonar did not report an error threshold for this condition.",
							}
						)
					)
					continue

				passes = _evaluate_quality_gate_condition(
					comparator=comparator, actual=local_actual, threshold=threshold
				)
				if passes is None:
					unsupported.append(
						compact_dict(
							{
								"metric": metric_key,
								"comparator": comparator,
								"threshold": threshold,
								"reason": "Comparator is not supported by the predictor.",
							}
						)
					)
					continue
				evaluated.append(
					compact_dict(
						{
							"metric": metric_key,
							"comparator": comparator,
							"threshold": threshold,
							"local_actual": round(float(local_actual), 2),
							"remote_actual": _safe_float(raw_condition.get("actualValue")),
							"remote_status": raw_condition.get("status"),
							"status": "pass" if passes else "fail",
						}
					)
				)

			failed = [item for item in evaluated if item.get("status") == "fail"]
			if failed:
				overall_status = "fail"
				would_pass: bool | None = False
			elif evaluated and not unsupported:
				overall_status = "pass"
				would_pass = True
			elif evaluated and unsupported:
				overall_status = "likely_pass_partial"
				would_pass = None
			else:
				overall_status = "needs_local_metrics"
				would_pass = None

			local_evaluation = {
				"status": overall_status,
				"would_pass": would_pass,
				"evaluated_conditions": evaluated,
				"unsupported_conditions": unsupported,
				"failing_conditions": failed,
				"local_metrics_received": normalized_metrics,
			}

		measurement_instructions: dict[str, Any] | None = None
		if local_evaluation is None:
			required_metrics = [
				str(condition.get("metricKey") or "").strip()
				for condition in raw_conditions
				if isinstance(condition, dict) and str(condition.get("metricKey") or "").strip() in SONAR_LOCALLY_EVALUABLE_QUALITY_GATE_METRICS
			]
			all_metrics = [
				str(condition.get("metricKey") or "").strip()
				for condition in raw_conditions
				if isinstance(condition, dict) and str(condition.get("metricKey") or "").strip()
			]
			measurement_instructions = {
				"purpose": "Measure these coverage metrics in the workspace using your stack's tooling, then re-call this tool with the numbers in `local_metrics`.",
				"required_metrics_for_full_prediction": required_metrics,
				"all_gate_metrics": all_metrics,
				"local_metrics_payload_shape": {
					"coverage": "<overall percent 0-100>",
					"line_coverage": "<line percent 0-100>",
					"branch_coverage": "<branch percent 0-100>",
				},
				"stack_command_examples": {
					"python": "python -m coverage run -m pytest && python -m coverage json -o coverage.json  (read totals.percent_covered and totals branch numbers)",
					"node_jest": "npx jest --coverage --json --outputFile=jest-coverage.json  (read coverageMap totals)",
					"node_vitest": "npx vitest run --coverage --reporter=json --outputFile=vitest-coverage.json",
					"dotnet": "dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=json  (read CoverletOutput coverage.json)",
					"java_maven": "mvn -B test jacoco:report  (read target/site/jacoco/jacoco.csv)",
					"go": "go test ./... -coverprofile=cover.out && go tool cover -func=cover.out  (read 'total:' line)",
				},
				"notes": [
					"Conditions on `new_*` metrics typically require a baseline comparison and may not be evaluable from a single local run.",
					"You can call this tool with only the metrics you can measure; unsupported conditions will be reported separately.",
				],
			}

		response: dict[str, Any] = {
			"ok": True,
			"server": "sonar",
			"operation": "local_quality_gate",
			"report_type": "local_quality_gate_prediction",
			"generated_at": utc_now_iso(),
			"sonar_project": sonar_project,
			"quality_gate": {
				"project_key": project_key,
				"branch": branch or "",
				"pull_request": pull_request or "",
				"current_remote_status": str(project_status.get("status") or "NONE"),
				"ignored_conditions": bool(project_status.get("ignoredConditions", False)),
				"definition": gate_definition,
				"local_evaluation": local_evaluation,
				"would_pass": None if local_evaluation is None else local_evaluation.get("would_pass"),
				"status": "needs_local_metrics" if local_evaluation is None else local_evaluation.get("status"),
			},
			"workspace_root": str(workspace_root),
			"notes": [
				"This operation does not run any local tests; it only fetches the gate definition and evaluates supplied metrics.",
				"To finalize a pre-push pass/fail decision, measure the metrics listed in `measurement_instructions` and call this tool again with `local_metrics`.",
			],
		}
		if measurement_instructions is not None:
			response["measurement_instructions"] = measurement_instructions
		return response

	def file_coverage_detail(
		self,
		*,
		project: str,
		branch: str = "",
		pull_request: str = "",
		file: str = "",
		file_key: str = "",
		include_source: bool = True,
		include_line_details: bool = True,
		use_internal_fallbacks: bool = False,
		include_raw: bool = False,
	) -> dict[str, Any]:
		if not project.strip():
			raise SonarError("A Sonar project key is required.")
		if branch and pull_request:
			raise SonarError("Provide either branch or pull_request, not both.")

		validation = self.client.validate_token()
		permission_gaps: set[str] = set()
		metas: list[dict[str, Any]] = []

		component, component_meta = self.client.resolve_file_component(
			project,
			file_path=file,
			file_key=file_key,
			branch=branch,
			pull_request=pull_request,
		)
		metas.append(component_meta)
		resolved_key = str(component.get("key") or file_key or "")
		resolved_path = _coalesce_path(component)

		measures_payload, measures_meta = self.client.get_component_measures(
			resolved_key,
			branch=branch,
			pull_request=pull_request,
		)
		metas.append(measures_meta)
		measure_component = measures_payload.get("component") if isinstance(measures_payload.get("component"), dict) else {}
		measures = self.client.parse_measures(measure_component)

		uncovered_lines: list[int] = []
		covered_lines: list[int] = []
		source_map: dict[int, str] = {}
		line_detail_quality = "unavailable"
		source_quality = "unavailable"
		internal_payload: dict[str, Any] | None = None

		if include_line_details and use_internal_fallbacks:
			try:
				internal_payload, app_meta = self.client.get_component_app(resolved_key, branch=branch, pull_request=pull_request)
				metas.append(app_meta)
				uncovered_lines, covered_lines, source_map = _extract_line_details(internal_payload)
				if uncovered_lines or covered_lines:
					line_detail_quality = "estimated"
			except SonarPermissionError:
				permission_gaps.add("See Source Code permission is missing for line-level coverage detail.")
			except SonarHttpError:
				line_detail_quality = "unavailable"

		source_excerpt: list[dict[str, Any]] = []
		if include_source:
			try:
				source_payload, source_meta = self.client.show_source(resolved_key, branch=branch, pull_request=pull_request)
				metas.append(source_meta)
				source_map.update(_extract_source_map(source_payload))
				source_quality = "confirmed"
			except SonarPermissionError:
				permission_gaps.add("See Source Code permission is missing for source excerpts.")
			except SonarHttpError:
				source_quality = "unavailable"

		if uncovered_lines and source_map:
			source_excerpt = _build_source_excerpt(uncovered_lines, source_map)

		coverage = _safe_float(measures.get("coverage"))
		covered_lines_count = max(0, _safe_int(measures.get("lines_to_cover")) - _safe_int(measures.get("uncovered_lines")))
		has_executable_coverage_metrics = _safe_int(measures.get("lines_to_cover")) > 0 or _safe_int(measures.get("uncovered_lines")) > 0 or coverage is not None
		priority_score = _priority_score(
			{
				"coverage": coverage,
				"uncovered_lines": _safe_int(measures.get("uncovered_lines")),
				"lines_to_cover": _safe_int(measures.get("lines_to_cover")),
			},
			_safe_int(measures.get("uncovered_lines")),
		)
		entry = {
			"file_key": resolved_key,
			"file_path": resolved_path,
			"file_name": _file_name_from_path(resolved_path),
			"coverage": coverage,
			"line_coverage": _safe_float(measures.get("line_coverage")),
			"branch_coverage": _safe_float(measures.get("branch_coverage")),
			"lines_to_cover": _safe_int(measures.get("lines_to_cover")),
			"uncovered_lines": _safe_int(measures.get("uncovered_lines")),
			"covered_lines": covered_lines_count,
			"conditions_to_cover": _safe_int(measures.get("conditions_to_cover")),
			"uncovered_conditions": _safe_int(measures.get("uncovered_conditions")),
			"uncovered_line_numbers": uncovered_lines,
			"covered_line_numbers": covered_lines,
			"line_number_quality": line_detail_quality,
			"priority_score": priority_score,
			"priority": _priority_label(priority_score, executable_metrics=has_executable_coverage_metrics, likely_help=_safe_int(measures.get("uncovered_lines")) >= 15),
			"has_executable_coverage_metrics": has_executable_coverage_metrics,
			"priority_reason": _priority_reason({
				"coverage": coverage,
				"uncovered_lines": _safe_int(measures.get("uncovered_lines")),
				"uncovered_conditions": _safe_int(measures.get("uncovered_conditions")),
				"branch_coverage": _safe_float(measures.get("branch_coverage")),
			}),
			"suggested_test_focus": _recommended_focus({
				"coverage": coverage,
				"branch_coverage": _safe_float(measures.get("branch_coverage")),
				"uncovered_conditions": _safe_int(measures.get("uncovered_conditions")),
			}),
			"should_target_first": bool(has_executable_coverage_metrics and priority_score >= 18),
			"data_quality": {
				"coverage": "confirmed" if coverage is not None else "unavailable",
				"uncovered_line_numbers": line_detail_quality,
				"covered_line_numbers": line_detail_quality,
				"source_excerpt": source_quality if source_excerpt or source_quality == "confirmed" else "unavailable",
			},
		}

		payload = {
			"ok": True,
			"server": "sonar",
			"report_type": "file_coverage_improvement",
			"generated_at": utc_now_iso(),
			"access_mode": _access_mode(validation, metas, permission_gaps),
			"project_summary": {
				"project_key": project,
				"branch_name": branch or "main",
				"pull_request": pull_request or "",
			},
			"file": _normalize_file_record(entry),
			"priority": {
				"top_files_to_target": [
					compact_dict(
						{
							"rank": 1,
							"file_path": resolved_path,
							"file_name": _file_name_from_path(resolved_path),
							"coverage_pct": coverage,
							"uncovered_lines_count": _safe_int(measures.get("uncovered_lines")),
							"uncovered_line_numbers": uncovered_lines,
							"priority_score": priority_score,
							"priority": entry["priority"],
							"why": entry["priority_reason"],
							"suggested_test_focus": entry["suggested_test_focus"],
						}
					)
				]
			},
			"permission_gaps": sorted(permission_gaps),
		}
		if include_raw:
			payload["raw"] = compact_dict(
				{
					"component": component,
					"measures": measures_payload,
					"internal_component": internal_payload,
				}
			)
		return payload


def run_sonar_access_probe(service: SonarCoverageService, **kwargs: Any) -> dict[str, Any]:
	return service.access_probe(**kwargs)


def run_sonar_projects(service: SonarCoverageService, **kwargs: Any) -> dict[str, Any]:
	return service.list_projects(**kwargs)


def run_sonar_coverage_report(service: SonarCoverageService, **kwargs: Any) -> dict[str, Any]:
	return service.coverage_report(**kwargs)


def run_sonar_file_coverage_detail(service: SonarCoverageService, **kwargs: Any) -> dict[str, Any]:
	return service.file_coverage_detail(**kwargs)