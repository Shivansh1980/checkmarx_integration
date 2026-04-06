from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ...domain.constants import SONAR_COVERAGE_METRIC_KEYS, SONAR_FILE_PAGE_SIZE, SONAR_PROJECTS_PAGE_SIZE
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


class SonarCoverageService:
	def __init__(self, credentials: SonarCredentials) -> None:
		self.credentials = credentials
		self.client = SonarClient(base_url=credentials.base_url, token=credentials.token, timeout=credentials.timeout)

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

		project_payload, project_meta = self.client.get_component_measures(project, branch=branch, pull_request=pull_request)
		metas.append(project_meta)
		project_component = project_payload.get("component") if isinstance(project_payload.get("component"), dict) else {}
		project_measures = self.client.parse_measures(project_component)

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
		project_summary = {
			"project_key": project_component.get("key") or project,
			"project_name": project_component.get("name") or project,
			"branch_name": branch or project_component.get("branch") or "main",
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

		payload = {
			"ok": True,
			"server": "sonar",
			"report_type": "coverage_improvement",
			"generated_at": utc_now_iso(),
			"access_mode": _access_mode(validation, metas, permission_gaps),
			"project_summary": project_summary,
			"files": [_normalize_file_record(item) for item in top_files],
			"priority": _build_priority_section(top_files, limit=min(10, len(top_files))),
		}
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
		if overall_coverage is None:
			overall_coverage = _safe_float(totals.get("percent_covered_display"))

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

		payload = {
			"ok": True,
			"server": "sonar",
			"operation": "local_report",
			"report_type": "local_coverage_prediction",
			"generated_at": utc_now_iso(),
			"project_summary": {
				"project_key": project.strip() or "local-workspace",
				"project_name": project_name,
				"branch_name": branch or "local",
				"pull_request": pull_request or "",
				"overall_coverage_pct": overall_coverage,
				"line_coverage_pct": overall_coverage,
				"branch_coverage_pct": None,
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
			"files": [_normalize_file_record(item) for item in top_files],
			"priority": _build_priority_section(top_files, limit=min(10, len(top_files))),
		}

		if compare_with_remote and project.strip() and self.credentials.base_url:
			try:
				remote_payload = self.coverage_report(
					project=project,
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