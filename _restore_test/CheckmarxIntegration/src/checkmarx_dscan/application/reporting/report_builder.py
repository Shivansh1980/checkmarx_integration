from __future__ import annotations

import html
import re
from collections import Counter
from typing import Any, Iterable

from ...domain.constants import ENGINE_ORDER, SEVERITY_ORDER, SUCCESS_SCAN_STATUSES
from ...domain.models import ArchiveInfo, FindingLocation, NormalizedFinding, ProjectScanExecutionReport, ProjectScanRequest, ScanExecutionReport, ScanRequest, ScanSummary
from ...shared.utils import compact_dict, dedupe_preserve_order, pick, pick_str, to_float, to_int, truncate, utc_now_iso


PACKAGE_IDENTIFIER_PATTERN = re.compile(r"^(?P<ecosystem>[^-]+)-(?P<name>.+)-(?P<version>\d[\w.+~-]*)$")


def normalize_result_type(raw_value: Any) -> str:
	text = str(raw_value or "").strip().lower()
	if text.startswith("infrastructure"):
		return "kics"
	if text.startswith("dependency") or text.startswith("sca-"):
		return "sca"
	if text == "iac-security":
		return "kics"
	return text or "unknown"


def extract_scan_status(scan: dict[str, Any]) -> str:
	status = pick(scan, "status", "Status")
	if isinstance(status, dict):
		status = pick(status, "value", "Value", "name", "Name")
	return str(status or "Unknown").strip() or "Unknown"


def format_status_details(status_details: Any, detail_limit: int = 160) -> str:
	if not isinstance(status_details, list):
		return ""

	parts: list[str] = []
	for item in status_details:
		if not isinstance(item, dict):
			continue
		name = pick_str(item, "name", "Name")
		status = pick_str(item, "status", "Status")
		details = html.unescape(pick_str(item, "details", "Details"))
		error_code = pick(item, "errorCode", "ErrorCode")
		segment = " ".join(part for part in [name, status] if part)
		if details:
			detail_text = truncate(details, detail_limit)
			segment = f"{segment} ({detail_text})" if segment else detail_text
		if error_code not in (None, "", 0, "0"):
			segment = f"{segment} [errorCode={error_code}]" if segment else f"errorCode={error_code}"
		if segment:
			parts.append(segment)
	return "; ".join(parts)


def extract_result_data(result: dict[str, Any]) -> dict[str, Any]:
	data = pick(result, "data", "Data", default={})
	return data if isinstance(data, dict) else {}


def extract_result_location(result: dict[str, Any]) -> FindingLocation:
	data = extract_result_data(result)
	nodes = pick(data, "nodes", "Nodes", default=[])
	if isinstance(nodes, list) and nodes:
		node = nodes[0] if isinstance(nodes[0], dict) else {}
		filename = pick_str(node, "fileName", "FileName", "name", "Name") or pick_str(
			data,
			"filename",
			"Filename",
		)
		line = to_int(pick(node, "line", "Line"), default=None)
		column = to_int(pick(node, "column", "Column"), default=None)
		return FindingLocation(filename=filename, line=line, column=column)

	filename = pick_str(data, "filename", "Filename", "imageFilePath", "ImageFilePath")
	sca_package_data = pick(data, "scaPackageData", "ScaPackageData", default={})
	if not filename and isinstance(sca_package_data, dict):
		locations = pick(sca_package_data, "locations", "Locations", default=[])
		if isinstance(locations, list) and locations:
			filename = str(locations[0])
	line = to_int(pick(data, "line", "Line"), default=None)
	return FindingLocation(filename=filename, line=line)


def extract_result_title(result: dict[str, Any]) -> str:
	data = extract_result_data(result)
	result_type = normalize_result_type(pick(result, "type", "Type"))
	if result_type == "sca":
		candidates = [
			pick_str(data, "queryName", "QueryName"),
			pick_str(data, "packageName", "PackageName"),
			pick_str(data, "packageIdentifier", "PackageIdentifier"),
		]
	elif result_type == "kics":
		candidates = [
			pick_str(data, "queryName", "QueryName"),
			pick_str(data, "issueType", "IssueType"),
			pick_str(data, "filename", "Filename"),
		]
	else:
		candidates = [
			pick_str(data, "queryName", "QueryName"),
			pick_str(data, "ruleName", "RuleName"),
			pick_str(data, "packageName", "PackageName"),
		]

	candidates.extend(
		[
			pick_str(result, "id", "ID"),
			pick_str(result, "similarityId", "SimilarityID"),
		]
	)
	for candidate in candidates:
		if candidate:
			return candidate
	return "Unnamed finding"


def extract_result_description(result: dict[str, Any], *, limit: int | None = None) -> str:
	data = extract_result_data(result)
	description = pick_str(result, "description", "Description") or pick_str(data, "description", "Description")
	cleaned = html.unescape(description)
	return truncate(cleaned, limit) if limit is not None else cleaned


def _collect_string_values(value: Any) -> list[str]:
	if isinstance(value, str):
		return [value.strip()] if value.strip() else []
	if isinstance(value, list):
		values: list[str] = []
		for item in value:
			values.extend(_collect_string_values(item))
		return values
	if isinstance(value, dict):
		for key in ("url", "URL", "href", "Href", "link", "Link", "value", "Value", "name", "Name"):
			candidate = pick_str(value, key)
			if candidate:
				return [candidate]
	return []


def extract_references(result: dict[str, Any]) -> list[str]:
	data = extract_result_data(result)
	candidates = [
		pick(data, "references", "References"),
		pick(data, "reference", "Reference"),
		pick(data, "links", "Links"),
		pick(data, "packageData", "PackageData"),
		pick(result, "links", "Links"),
	]
	collected: list[str] = []
	for candidate in candidates:
		collected.extend(_collect_string_values(candidate))
	return dedupe_preserve_order(collected)


def infer_package_coordinates(package_identifier: str) -> tuple[str, str]:
	identifier = str(package_identifier or "").strip()
	if not identifier:
		return "", ""

	if identifier.startswith("pkg:"):
		_, _, remainder = identifier[4:].partition("/")
		if not remainder:
			return "", ""
		name, separator, version = remainder.rpartition("@")
		if separator:
			return name, version
		return remainder, ""

	match = PACKAGE_IDENTIFIER_PATTERN.match(identifier)
	if not match:
		return "", ""
	return match.group("name"), match.group("version")


def extract_recommended_version(data: dict[str, Any], sca_package_data: dict[str, Any]) -> str:
	recommended_version = pick_str(
		data,
		"recommendedVersion",
		"RecommendedVersion",
		"fixVersion",
		"FixVersion",
		"fixedVersion",
		"FixedVersion",
	) or pick_str(
		sca_package_data,
		"recommendedVersion",
		"RecommendedVersion",
		"fixVersion",
		"FixVersion",
		"fixedVersion",
		"FixedVersion",
	)
	if recommended_version:
		return recommended_version

	text_recommendation = pick_str(data, "recommendations", "Recommendations") or pick_str(
		sca_package_data,
		"recommendations",
		"Recommendations",
	)
	if text_recommendation and "\n" not in text_recommendation and len(text_recommendation) <= 64 and any(
		character.isdigit() for character in text_recommendation
	):
		return text_recommendation
	return ""


def build_fix_recommendation(
	data: dict[str, Any],
	sca_package_data: dict[str, Any],
	*,
	package_name: str,
	package_version: str,
	package_identifier: str,
	recommended_version: str,
) -> str:
	explicit_recommendation = html.unescape(
		pick_str(
			data,
			"recommendation",
			"Recommendation",
			"fix",
			"Fix",
			"proposedFix",
			"ProposedFix",
			"remediation",
			"Remediation",
		)
		or pick_str(
			sca_package_data,
			"recommendation",
			"Recommendation",
			"fix",
			"Fix",
			"proposedFix",
			"ProposedFix",
			"remediation",
			"Remediation",
		)
	)
	if explicit_recommendation:
		return explicit_recommendation

	text_recommendation = html.unescape(
		pick_str(data, "recommendations", "Recommendations")
		or pick_str(sca_package_data, "recommendations", "Recommendations")
	)
	if text_recommendation and text_recommendation != recommended_version:
		return text_recommendation

	if recommended_version:
		subject = package_name or package_identifier or "the affected package"
		if package_version:
			return f"Upgrade {subject} from {package_version} to {recommended_version}."
		return f"Upgrade {subject} to {recommended_version}."
	return ""


def _ordered_counter(counter: Counter[str], ordering: Iterable[str]) -> dict[str, int]:
	ordered: dict[str, int] = {}
	for key in ordering:
		if counter.get(key, 0):
			ordered[key] = counter[key]
	for key in sorted(counter):
		if key not in ordered and counter[key]:
			ordered[key] = counter[key]
	return ordered


def format_counter(counter: dict[str, int], ordered_keys: Iterable[str]) -> str:
	parts: list[str] = []
	ordered_keys = tuple(ordered_keys)
	for key in ordered_keys:
		count = counter.get(key, 0)
		if count:
			parts.append(f"{key}={count}")
	leftovers = sorted(key for key in counter if key not in ordered_keys and counter[key])
	for key in leftovers:
		parts.append(f"{key}={counter[key]}")
	return ", ".join(parts) if parts else "none"


def _severity_rank(severity: str) -> int:
	try:
		return SEVERITY_ORDER.index((severity or "unknown").lower())
	except ValueError:
		return len(SEVERITY_ORDER)


def _group_display_title(group: dict[str, Any]) -> str:
	package_name = pick_str(group, "package_name")
	package_version = pick_str(group, "package_version")
	issue_title = pick_str(group, "issue_title")
	if package_name and package_version:
		return f"{package_name} {package_version}"
	if package_name:
		return package_name
	return issue_title or "Unnamed issue"


def build_actionable_issue_groups(findings: list[dict[str, Any]], *, limit: int | None = None) -> list[dict[str, Any]]:
	grouped: dict[tuple[str, ...], dict[str, Any]] = {}

	for finding in findings:
		if not isinstance(finding, dict):
			continue

		location = pick(finding, "location", default={})
		location_display = ""
		if isinstance(location, dict):
			location_display = (
				pick_str(location, "display")
				or pick_str(location, "filename")
				or ""
			)

		finding_type = pick_str(finding, "type") or "unknown"
		package_name = pick_str(finding, "package_name")
		package_identifier = pick_str(finding, "package_identifier")
		package_version = pick_str(finding, "package_version")
		recommended_version = pick_str(finding, "recommended_version")
		issue_title = pick_str(finding, "title") or pick_str(finding, "id") or "Unnamed issue"
		language = pick_str(finding, "language")
		category = pick_str(finding, "category")
		issue_key = package_name or package_identifier or issue_title

		if package_name or package_identifier:
			group_key = (
				"package",
				finding_type,
				issue_key,
				package_version,
				recommended_version,
				location_display,
			)
		else:
			group_key = (
				"finding",
				finding_type,
				issue_title,
				location_display,
				language,
				category,
			)

		group = grouped.get(group_key)
		if group is None:
			group = {
				"type": finding_type,
				"severity": pick_str(finding, "severity") or "unknown",
				"issue_title": issue_title,
				"package_name": package_name,
				"package_identifier": package_identifier,
				"package_version": package_version,
				"recommended_version": recommended_version,
				"category": category,
				"language": language,
				"location": location_display,
				"vulnerability_count": 0,
				"vulnerability_ids": [],
				"finding_titles": [],
				"references": [],
				"fix_recommendation": pick_str(finding, "fix_recommendation"),
			}
			grouped[group_key] = group

		group["vulnerability_count"] += 1
		current_severity = pick_str(finding, "severity") or "unknown"
		if _severity_rank(current_severity) < _severity_rank(pick_str(group, "severity") or "unknown"):
			group["severity"] = current_severity

		vulnerability_id = pick_str(finding, "id")
		if vulnerability_id and vulnerability_id not in group["vulnerability_ids"]:
			group["vulnerability_ids"].append(vulnerability_id)

		if issue_title and issue_title not in group["finding_titles"]:
			group["finding_titles"].append(issue_title)

		for reference in pick(finding, "references", default=[]):
			if isinstance(reference, str) and reference and reference not in group["references"]:
				group["references"].append(reference)

		if not group["fix_recommendation"]:
			group["fix_recommendation"] = pick_str(finding, "fix_recommendation")

	actionable_issues = [
		compact_dict(
			{
				"type": pick_str(group, "type"),
				"severity": pick_str(group, "severity"),
				"title": _group_display_title(group),
				"issue_title": pick_str(group, "issue_title"),
				"package_name": pick_str(group, "package_name"),
				"package_identifier": pick_str(group, "package_identifier"),
				"package_version": pick_str(group, "package_version"),
				"recommended_version": pick_str(group, "recommended_version"),
				"category": pick_str(group, "category"),
				"language": pick_str(group, "language"),
				"location": pick_str(group, "location"),
				"vulnerability_count": pick(group, "vulnerability_count", default=0),
				"vulnerability_ids": pick(group, "vulnerability_ids", default=[]),
				"finding_titles": pick(group, "finding_titles", default=[]),
				"fix_recommendation": pick_str(group, "fix_recommendation"),
				"references": pick(group, "references", default=[]),
			}
		)
		for group in grouped.values()
	]

	actionable_issues.sort(
		key=lambda issue: (
			_severity_rank(pick_str(issue, "severity") or "unknown"),
			-(to_int(pick(issue, "vulnerability_count"), default=0) or 0),
			pick_str(issue, "type"),
			pick_str(issue, "title"),
		)
	)
	if limit is not None:
		return actionable_issues[: max(0, limit)]
	return actionable_issues


def build_fix_targets(actionable_issues: list[dict[str, Any]], *, limit: int | None = None) -> list[dict[str, Any]]:
	fix_targets: list[dict[str, Any]] = []
	for issue in actionable_issues:
		if not isinstance(issue, dict):
			continue
		fix_targets.append(
			compact_dict(
				{
					"type": pick_str(issue, "type"),
					"severity": pick_str(issue, "severity"),
					"target": pick_str(issue, "title"),
					"location": pick_str(issue, "location"),
					"package_name": pick_str(issue, "package_name"),
					"package_version": pick_str(issue, "package_version"),
					"recommended_version": pick_str(issue, "recommended_version"),
					"vulnerability_count": to_int(pick(issue, "vulnerability_count"), default=0) or 0,
					"fix_recommendation": pick_str(issue, "fix_recommendation"),
					"finding_titles": pick(issue, "finding_titles", default=[]),
					"vulnerability_ids": pick(issue, "vulnerability_ids", default=[]),
					"references": pick(issue, "references", default=[]),
				}
			)
		)
	if limit is not None:
		return fix_targets[: max(0, limit)]
	return fix_targets


def _filter_findings_by_type(findings: list[dict[str, Any]], finding_type: str) -> list[dict[str, Any]]:
	return [finding for finding in findings if isinstance(finding, dict) and pick_str(finding, "type") == finding_type]


def build_scan_agent_report(
	*,
	project: dict[str, Any],
	scan: dict[str, Any],
	summary: ScanSummary,
	findings: list[NormalizedFinding],
	detail_source: str = "checkmarx_api",
	enrichment_error: str = "",
) -> dict[str, Any]:
	findings_payload = [finding.to_dict() for finding in findings]
	actionable_issues = build_actionable_issue_groups(findings_payload)
	enabled_engines = scan.get("engines") if isinstance(scan.get("engines"), list) else []
	engines_with_findings = list(summary.engine_counts.keys())
	zero_finding_engines = [engine for engine in enabled_engines if engine not in summary.engine_counts]

	code_issues = _filter_findings_by_type(findings_payload, "sast")
	dependency_issues = _filter_findings_by_type(findings_payload, "sca")
	infrastructure_issues = _filter_findings_by_type(findings_payload, "kics")
	container_issues = _filter_findings_by_type(findings_payload, "containers")

	code_fix_targets = build_fix_targets(build_actionable_issue_groups(code_issues))
	dependency_fix_targets = build_fix_targets(build_actionable_issue_groups(dependency_issues))
	infrastructure_fix_targets = build_fix_targets(build_actionable_issue_groups(infrastructure_issues))
	container_fix_targets = build_fix_targets(build_actionable_issue_groups(container_issues))

	return compact_dict(
		{
			"project_id": pick_str(project, "id"),
			"project_name": pick_str(project, "name"),
			"scan_id": pick_str(scan, "id"),
			"branch_name": pick_str(scan, "branch"),
			"status": pick_str(scan, "status"),
			"status_details": pick_str(scan, "status_details"),
			"engines_enabled": enabled_engines,
			"detail_source": detail_source,
			"detailed_findings_available": True,
			"vulnerability_summary": summary.to_dict(),
			"engine_coverage": {
				"enabled_engines": enabled_engines,
				"engines_with_findings": engines_with_findings,
				"zero_finding_engines": zero_finding_engines,
			},
			"vulnerabilities": findings_payload,
			"top_vulnerabilities": findings_payload[:20],
			"actionable_issues": actionable_issues,
			"top_actionable_issues": actionable_issues[:20],
			"fix_targets": build_fix_targets(actionable_issues),
			"top_fix_targets": build_fix_targets(actionable_issues, limit=20),
			"code_issues": code_issues,
			"dependency_issues": dependency_issues,
			"infrastructure_issues": infrastructure_issues,
			"container_issues": container_issues,
			"code_fix_targets": code_fix_targets,
			"dependency_fix_targets": dependency_fix_targets,
			"infrastructure_fix_targets": infrastructure_fix_targets,
			"container_fix_targets": container_fix_targets,
			"enrichment_error": enrichment_error,
		}
	)


def normalize_finding(result: dict[str, Any], index: int) -> NormalizedFinding:
	data = extract_result_data(result)
	sca_package_data = pick(data, "scaPackageData", "ScaPackageData", default={})
	if not isinstance(sca_package_data, dict):
		sca_package_data = {}

	result_type = normalize_result_type(pick(result, "type", "Type"))
	severity = str(pick(result, "severity", "Severity") or "unknown").strip().lower() or "unknown"
	state = (
		pick_str(result, "state", "State", "status", "Status")
		or pick_str(data, "state", "State", "status", "Status")
		or "unknown"
	)
	package_name = pick_str(data, "packageName", "PackageName") or pick_str(sca_package_data, "packageName", "PackageName")
	package_version = pick_str(data, "packageVersion", "PackageVersion") or pick_str(
		sca_package_data,
		"packageVersion",
		"PackageVersion",
	)
	package_identifier = pick_str(data, "packageIdentifier", "PackageIdentifier") or pick_str(
		sca_package_data,
		"packageIdentifier",
		"PackageIdentifier",
	)
	inferred_package_name, inferred_package_version = infer_package_coordinates(package_identifier)
	if not package_name:
		package_name = inferred_package_name
	if not package_version:
		package_version = inferred_package_version
	recommended_version = extract_recommended_version(data, sca_package_data)
	fix_recommendation = build_fix_recommendation(
		data,
		sca_package_data,
		package_name=package_name,
		package_version=package_version,
		package_identifier=package_identifier,
		recommended_version=recommended_version,
	)
	attributes = compact_dict(
		{
			"query_id": pick(result, "queryId", "QueryID") or pick(data, "queryId", "QueryID"),
			"query_name": pick_str(data, "queryName", "QueryName"),
			"rule_name": pick_str(data, "ruleName", "RuleName"),
			"group": pick_str(data, "group", "Group"),
			"issue_type": pick_str(data, "issueType", "IssueType"),
			"language": pick_str(data, "languageName", "LanguageName", "language", "Language"),
			"package_type": pick_str(sca_package_data, "packageType", "PackageType"),
			"package_manager": pick_str(sca_package_data, "packageManager", "PackageManager"),
			"package_namespace": pick_str(sca_package_data, "packageNamespace", "PackageNamespace"),
			"fix_state": pick_str(data, "fixState", "FixState"),
			"cwe": pick_str(data, "cweId", "CweId", "cwe", "Cwe"),
			"cvss_score": to_float(pick(data, "cvssScore", "CvssScore"), default=None),
			"node_count": len(pick(data, "nodes", "Nodes", default=[])) if isinstance(pick(data, "nodes", "Nodes", default=[]), list) else None,
			"compliance": pick(data, "compliance", "Compliance"),
			"tags": pick(data, "tags", "Tags"),
			"similarity_id": pick_str(result, "similarityId", "SimilarityID"),
			"recommended_version": recommended_version,
		}
	)

	return NormalizedFinding(
		index=index,
		identifier=pick_str(result, "id", "ID"),
		finding_type=result_type,
		severity=severity,
		state=state,
		title=extract_result_title(result),
		description=extract_result_description(result),
		location=extract_result_location(result),
		similarity_id=pick_str(result, "similarityId", "SimilarityID"),
		category=pick_str(data, "category", "Category", "group", "Group", "issueType", "IssueType"),
		language=pick_str(data, "languageName", "LanguageName", "language", "Language"),
		package_name=package_name,
		package_version=package_version,
		package_identifier=package_identifier,
		recommended_version=recommended_version,
		cwe=pick_str(data, "cweId", "CweId", "cwe", "Cwe"),
		cvss_score=to_float(pick(data, "cvssScore", "CvssScore"), default=None),
		fix_recommendation=fix_recommendation,
		references=extract_references(result),
		attributes=attributes,
		details=data,
	)


def build_summary(scan: dict[str, Any], findings: list[NormalizedFinding], total_count: int) -> ScanSummary:
	severity_counter: Counter[str] = Counter()
	engine_counter: Counter[str] = Counter()
	for finding in findings:
		severity_counter[finding.severity or "unknown"] += 1
		engine_counter[finding.finding_type or "unknown"] += 1

	highest_severity = next((severity for severity in SEVERITY_ORDER if severity_counter.get(severity)), "unknown")
	terminal_status = extract_scan_status(scan)
	return ScanSummary(
		total_findings=total_count,
		terminal_status=terminal_status,
		status_details=format_status_details(pick(scan, "statusDetails", "StatusDetails", default=[])),
		successful=terminal_status in SUCCESS_SCAN_STATUSES,
		severity_counts=_ordered_counter(severity_counter, SEVERITY_ORDER),
		engine_counts=_ordered_counter(engine_counter, ENGINE_ORDER),
		highest_severity=highest_severity,
	)


def build_execution_report(
	*,
	request: ScanRequest,
	archive: ArchiveInfo,
	project: dict[str, Any],
	project_created: bool,
	created_scan: dict[str, Any],
	final_scan: dict[str, Any],
	results_payload: dict[str, Any],
	include_raw: bool,
	generated_at: str | None = None,
) -> ScanExecutionReport:
	results = pick(results_payload, "results", "Results", default=[])
	if not isinstance(results, list):
		results = []

	findings = [normalize_finding(result, index) for index, result in enumerate(results, start=1) if isinstance(result, dict)]
	total_count = to_int(pick(results_payload, "totalCount", "TotalCount"), default=len(findings)) or len(findings)
	summary = build_summary(final_scan, findings, total_count)
	project_info = compact_dict(
		{
			"id": pick_str(project, "id", "ID"),
			"name": pick_str(project, "name", "Name") or request.project_name,
			"main_branch": pick_str(project, "mainBranch", "MainBranch") or request.branch,
			"created": project_created,
		}
	)
	scan_info = compact_dict(
		{
			"id": pick_str(final_scan, "id", "ID") or pick_str(created_scan, "id", "ID"),
			"branch": request.branch,
			"status": extract_scan_status(final_scan),
			"status_details": format_status_details(pick(final_scan, "statusDetails", "StatusDetails", default=[])),
			"engines": pick(final_scan, "engines", "Engines", default=[]),
			"total_results": total_count,
			"created_at": pick_str(final_scan, "createdAt", "CreatedAt") or pick_str(created_scan, "createdAt", "CreatedAt"),
			"completed_at": pick_str(final_scan, "completedAt", "CompletedAt", "finishedAt", "FinishedAt"),
		}
	)
	raw = None
	if include_raw:
		raw = {
			"project": project,
			"created_scan": created_scan,
			"final_scan": final_scan,
			"results": results_payload,
		}
	return ScanExecutionReport(
		generated_at=generated_at or utc_now_iso(),
		request=request.to_dict(),
		archive=archive,
		project=project_info,
		scan=scan_info,
		summary=summary,
		findings=findings,
		agent_report=build_scan_agent_report(project=project_info, scan=scan_info, summary=summary, findings=findings),
		raw=raw,
	)


def build_project_scan_execution_report(
	*,
	request: ProjectScanRequest,
	project: dict[str, Any],
	final_scan: dict[str, Any],
	results_payload: dict[str, Any],
	include_raw: bool,
	generated_at: str | None = None,
) -> ProjectScanExecutionReport:
	results = pick(results_payload, "results", "Results", default=[])
	if not isinstance(results, list):
		results = []

	findings = [normalize_finding(result, index) for index, result in enumerate(results, start=1) if isinstance(result, dict)]
	total_count = to_int(pick(results_payload, "totalCount", "TotalCount"), default=len(findings)) or len(findings)
	summary = build_summary(final_scan, findings, total_count)
	project_info = compact_dict(
		{
			"id": pick_str(project, "id", "ID"),
			"name": pick_str(project, "name", "Name") or request.project_name,
			"main_branch": pick_str(project, "mainBranch", "MainBranch"),
		}
	)
	scan_info = compact_dict(
		{
			"id": pick_str(final_scan, "id", "ID") or pick_str(results_payload, "scanID", "scanId", "ScanID"),
			"branch": pick_str(final_scan, "branch", "Branch") or request.branch,
			"status": extract_scan_status(final_scan),
			"status_details": format_status_details(pick(final_scan, "statusDetails", "StatusDetails", default=[])),
			"engines": pick(final_scan, "engines", "Engines", default=[]),
			"total_results": total_count,
			"created_at": pick_str(final_scan, "createdAt", "CreatedAt"),
			"completed_at": pick_str(final_scan, "completedAt", "CompletedAt", "finishedAt", "FinishedAt"),
		}
	)
	raw = None
	if include_raw:
		raw = {
			"project": project,
			"final_scan": final_scan,
			"results": results_payload,
		}
	return ProjectScanExecutionReport(
		generated_at=generated_at or utc_now_iso(),
		request=request.to_dict(),
		project=project_info,
		scan=scan_info,
		summary=summary,
		findings=findings,
		agent_report=build_scan_agent_report(project=project_info, scan=scan_info, summary=summary, findings=findings),
		raw=raw,
	)


def build_normalized_scan_results_view(
	scan: dict[str, Any],
	results_payload: dict[str, Any],
	*,
	include_raw: bool = False,
) -> dict[str, Any]:
	results = pick(results_payload, "results", "Results", default=[])
	if not isinstance(results, list):
		results = []

	findings = [normalize_finding(result, index) for index, result in enumerate(results, start=1) if isinstance(result, dict)]
	total_count = to_int(pick(results_payload, "totalCount", "TotalCount"), default=len(findings)) or len(findings)
	summary = build_summary(scan, findings, total_count)
	payload = {
		"scan": compact_dict(
			{
				"id": pick_str(scan, "id", "ID") or pick_str(results_payload, "scanID", "scanId", "ScanID"),
				"project_name": pick_str(scan, "projectName", "ProjectName"),
				"branch": pick_str(scan, "branch", "Branch"),
				"status": extract_scan_status(scan),
				"status_details": format_status_details(pick(scan, "statusDetails", "StatusDetails", default=[])),
				"engines": pick(scan, "engines", "Engines", default=[]),
				"created_at": pick_str(scan, "createdAt", "CreatedAt"),
				"completed_at": pick_str(scan, "completedAt", "CompletedAt", "finishedAt", "FinishedAt"),
			}
		),
		"summary": summary.to_dict(),
		"findings": [finding.to_dict() for finding in findings],
	}
	if include_raw:
		payload["raw"] = {
			"scan": scan,
			"results": results_payload,
		}
	return payload


def build_agent_report_from_jenkins_artifact(
	report_payload: Any,
	*,
	detailed_view: dict[str, Any] | None = None,
	enrichment_error: str = "",
) -> dict[str, Any]:
	report_mapping = report_payload if isinstance(report_payload, dict) else {}
	apisec_count = 0
	engines_result = pick(report_mapping, "EnginesResult", "enginesResult", default={})
	if isinstance(engines_result, dict):
		apisec_result = pick(engines_result, "apisec", "APISec", default={})
		if isinstance(apisec_result, dict):
			apisec_count = sum(
				to_int(pick(apisec_result, severity.capitalize(), severity), default=0) or 0
				for severity in ("critical", "high", "medium", "low", "info")
			)
	if apisec_count == 0:
		api_security = pick(report_mapping, "APISecurity", "apiSecurity", default={})
		if isinstance(api_security, dict):
			risks = pick(api_security, "risks", "Risks", default=[])
			if isinstance(risks, list):
				apisec_count = sum(to_int(item, default=0) or 0 for item in risks)

	artifact_severity_counts = compact_dict(
		{
			"critical": to_int(pick(report_mapping, "CriticalIssues"), default=0) or 0,
			"high": to_int(pick(report_mapping, "HighIssues"), default=0) or 0,
			"medium": to_int(pick(report_mapping, "MediumIssues"), default=0) or 0,
			"low": to_int(pick(report_mapping, "LowIssues"), default=0) or 0,
			"info": to_int(pick(report_mapping, "InfoIssues"), default=0) or 0,
		}
	)
	artifact_engine_counts = compact_dict(
		{
			"sast": to_int(pick(report_mapping, "SastIssues"), default=0) or 0,
			"sca": to_int(pick(report_mapping, "ScaIssues"), default=0) or 0,
			"kics": to_int(pick(report_mapping, "KicsIssues"), default=0) or 0,
			"containers": to_int(pick(report_mapping, "ContainersIssues"), default=0) or 0,
			"apisec": apisec_count,
		}
	)
	if "apisec" in artifact_engine_counts and artifact_engine_counts["apisec"] == 0:
		artifact_engine_counts.pop("apisec", None)
	total_issues = to_int(pick(report_mapping, "TotalIssues", "TotalFindings", "totalCount"), default=None)
	highest_severity = next((severity for severity in SEVERITY_ORDER if artifact_severity_counts.get(severity)), "unknown")
	artifact_vulnerability_summary = {
		"total_findings": total_issues,
		"severity_counts": artifact_severity_counts,
		"engine_counts": artifact_engine_counts,
		"highest_severity": highest_severity,
		"successful": pick_str(report_mapping, "Status") in SUCCESS_SCAN_STATUSES,
	}
	agent_report = compact_dict(
		{
			"scan_id": pick_str(report_mapping, "ScanID", "scanId"),
			"project_id": pick_str(report_mapping, "ProjectID", "projectId"),
			"project_name": pick_str(report_mapping, "ProjectName", "projectName"),
			"branch_name": pick_str(report_mapping, "BranchName", "branchName"),
			"status": pick_str(report_mapping, "Status", "status"),
			"risk_style": pick_str(report_mapping, "RiskStyle", "riskStyle"),
			"risk_message": pick_str(report_mapping, "RiskMsg", "riskMsg"),
			"created_at": pick_str(report_mapping, "CreatedAt", "createdAt"),
			"base_uri": pick_str(report_mapping, "BaseURI", "baseUri"),
			"engines_enabled": pick(report_mapping, "EnginesEnabled", "enginesEnabled", default=[]),
			"policies": pick(report_mapping, "Policies", "policies"),
			"detail_source": "checkmarx_api" if detailed_view is not None else "artifact_summary_only",
			"detailed_findings_available": detailed_view is not None,
			"artifact_vulnerability_summary": artifact_vulnerability_summary,
			"api_vulnerability_summary": detailed_view.get("summary") if detailed_view is not None else None,
			"normalized_scan": detailed_view.get("scan") if detailed_view is not None else None,
			"vulnerabilities": detailed_view.get("findings", []) if detailed_view is not None else [],
			"top_vulnerabilities": detailed_view.get("findings", [])[:20] if detailed_view is not None else [],
			"actionable_issues": build_actionable_issue_groups(detailed_view.get("findings", [])) if detailed_view is not None else [],
			"top_actionable_issues": build_actionable_issue_groups(detailed_view.get("findings", []), limit=20) if detailed_view is not None else [],
			"fix_targets": build_fix_targets(build_actionable_issue_groups(detailed_view.get("findings", []))) if detailed_view is not None else [],
			"top_fix_targets": build_fix_targets(build_actionable_issue_groups(detailed_view.get("findings", []), limit=20), limit=20) if detailed_view is not None else [],
			"enrichment_error": enrichment_error,
		}
	)
	return agent_report


def render_console_report(report: ScanExecutionReport, results_limit: int) -> str:
	lines = [
		"",
		f"Project: {report.project.get('name', 'n/a')}",
		f"Scan ID: {report.scan.get('id', 'n/a')}",
		f"Final scan status: {report.scan.get('status', 'Unknown')}",
	]
	if report.scan.get("status_details"):
		lines.append(f"Status details: {report.scan['status_details']}")

	engines = report.scan.get("engines")
	if isinstance(engines, list) and engines:
		lines.append(f"Enabled engines: {', '.join(str(engine) for engine in engines)}")
	else:
		lines.append("Enabled engines: n/a")

	lines.extend(
		[
			f"Total findings: {report.summary.total_findings}",
			f"Severity counts: {format_counter(report.summary.severity_counts, SEVERITY_ORDER)}",
			f"Engine counts: {format_counter(report.summary.engine_counts, ENGINE_ORDER)}",
		]
	)

	visible_count = max(0, results_limit)
	if not report.findings or visible_count == 0:
		if not report.findings:
			lines.append("No findings were returned for this scan.")
		return "\n".join(lines)

	lines.append("")
	lines.append(f"Top {min(visible_count, len(report.findings))} findings:")
	for finding in report.findings[:visible_count]:
		line = f"{finding.index}. [{finding.severity.upper()}] [{finding.finding_type}] {finding.title}"
		if finding.location.display:
			line = f"{line} @ {finding.location.display}"
		lines.append(line)
		if finding.description:
			lines.append(f"   {truncate(finding.description, 220)}")
	return "\n".join(lines)


def render_project_scan_console_report(report: ProjectScanExecutionReport, results_limit: int) -> str:
	lines = [
		"",
		f"Project: {report.project.get('name', 'n/a')}",
		f"Scan ID: {report.scan.get('id', 'n/a')}",
		f"Branch: {report.scan.get('branch', 'n/a')}",
		f"Latest scan status: {report.scan.get('status', 'Unknown')}",
	]
	if report.scan.get("status_details"):
		lines.append(f"Status details: {report.scan['status_details']}")

	engines = report.scan.get("engines")
	if isinstance(engines, list) and engines:
		lines.append(f"Enabled engines: {', '.join(str(engine) for engine in engines)}")
	else:
		lines.append("Enabled engines: n/a")

	lines.extend(
		[
			f"Total findings: {report.summary.total_findings}",
			f"Severity counts: {format_counter(report.summary.severity_counts, SEVERITY_ORDER)}",
			f"Engine counts: {format_counter(report.summary.engine_counts, ENGINE_ORDER)}",
		]
	)

	visible_count = max(0, results_limit)
	if not report.findings or visible_count == 0:
		if not report.findings:
			lines.append("No findings were returned for this scan.")
		return "\n".join(lines)

	lines.append("")
	lines.append(f"Top {min(visible_count, len(report.findings))} findings:")
	for finding in report.findings[:visible_count]:
		line = f"{finding.index}. [{finding.severity.upper()}] [{finding.finding_type}] {finding.title}"
		if finding.location.display:
			line = f"{line} @ {finding.location.display}"
		lines.append(line)
		if finding.description:
			lines.append(f"   {truncate(finding.description, 220)}")
	return "\n".join(lines)
