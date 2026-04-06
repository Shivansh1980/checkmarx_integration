from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constants import (
	DEFAULT_JENKINS_FALLBACK_BUILDS,
	DEFAULT_POLL_INTERVAL,
	DEFAULT_POLL_TIMEOUT,
	DEFAULT_RESULTS_PAGE_SIZE,
	DEFAULT_SCAN_TYPES,
	DEFAULT_TIMEOUT,
)
from ..shared.utils import compact_dict


REPORT_PROFILE_FULL = "full"
REPORT_PROFILE_COMPACT = "compact"


def normalize_report_profile(profile: str | None) -> str:
	value = str(profile or REPORT_PROFILE_FULL).strip().lower()
	if value not in {REPORT_PROFILE_FULL, REPORT_PROFILE_COMPACT}:
		return REPORT_PROFILE_FULL
	return value


def _count_detailed_findings(agent_report: dict[str, Any]) -> int | None:
	vulnerabilities = agent_report.get("vulnerabilities")
	if isinstance(vulnerabilities, list):
		return len(vulnerabilities)
	return None


def _build_scan_compact_agent_report(agent_report: dict[str, Any]) -> dict[str, Any]:
	vulnerabilities = agent_report.get("vulnerabilities")
	return compact_dict(
		{
			"project_id": agent_report.get("project_id"),
			"project_name": agent_report.get("project_name"),
			"scan_id": agent_report.get("scan_id"),
			"branch_name": agent_report.get("branch_name"),
			"status": agent_report.get("status"),
			"status_details": agent_report.get("status_details"),
			"engines_enabled": agent_report.get("engines_enabled"),
			"detail_source": agent_report.get("detail_source"),
			"detailed_findings_available": agent_report.get("detailed_findings_available"),
			"detailed_findings_count": _count_detailed_findings(agent_report),
			"canonical_vulnerability_path": "agent_report.vulnerabilities",
			"vulnerability_summary": agent_report.get("vulnerability_summary"),
			"engine_coverage": agent_report.get("engine_coverage"),
			"vulnerabilities": list(vulnerabilities) if isinstance(vulnerabilities, list) else [],
			"top_actionable_issues": agent_report.get("top_actionable_issues", []),
			"top_fix_targets": agent_report.get("top_fix_targets", []),
			"enrichment_error": agent_report.get("enrichment_error"),
		}
	)


def _build_jenkins_compact_agent_report(agent_report: dict[str, Any]) -> dict[str, Any]:
	vulnerabilities = agent_report.get("vulnerabilities")
	return compact_dict(
		{
			"scan_id": agent_report.get("scan_id"),
			"project_id": agent_report.get("project_id"),
			"project_name": agent_report.get("project_name"),
			"branch_name": agent_report.get("branch_name"),
			"status": agent_report.get("status"),
			"risk_style": agent_report.get("risk_style"),
			"risk_message": agent_report.get("risk_message"),
			"created_at": agent_report.get("created_at"),
			"base_uri": agent_report.get("base_uri"),
			"engines_enabled": agent_report.get("engines_enabled"),
			"policies": agent_report.get("policies"),
			"detail_source": agent_report.get("detail_source"),
			"detailed_findings_available": agent_report.get("detailed_findings_available"),
			"detailed_findings_count": _count_detailed_findings(agent_report),
			"canonical_vulnerability_path": "agent_report.vulnerabilities",
			"artifact_vulnerability_summary": agent_report.get("artifact_vulnerability_summary"),
			"api_vulnerability_summary": agent_report.get("api_vulnerability_summary"),
			"normalized_scan": agent_report.get("normalized_scan"),
			"vulnerabilities": list(vulnerabilities) if isinstance(vulnerabilities, list) else [],
			"top_actionable_issues": agent_report.get("top_actionable_issues", []),
			"top_fix_targets": agent_report.get("top_fix_targets", []),
			"enrichment_error": agent_report.get("enrichment_error"),
		}
	)


def serialize_agent_report(agent_report: dict[str, Any], profile: str | None = None) -> dict[str, Any]:
	resolved_profile = normalize_report_profile(profile)
	if resolved_profile == REPORT_PROFILE_FULL:
		return dict(agent_report)
	if "vulnerability_summary" in agent_report:
		return _build_scan_compact_agent_report(agent_report)
	return _build_jenkins_compact_agent_report(agent_report)


@dataclass(slots=True)
class CheckmarxCredentials:
	api_token: str
	base_url: str = ""
	auth_url: str = ""
	tenant: str = ""
	timeout: int = DEFAULT_TIMEOUT


@dataclass(slots=True)
class JenkinsCredentials:
	username: str = ""
	api_token: str = ""
	base_url: str = ""
	timeout: int = DEFAULT_TIMEOUT


@dataclass(slots=True)
class SonarCredentials:
	base_url: str
	token: str = ""
	timeout: int = DEFAULT_TIMEOUT


@dataclass(slots=True)
class ScanRequest:
	project_name: str
	source_path: Path
	branch: str = "main"
	scan_types: list[str] = field(default_factory=lambda: list(DEFAULT_SCAN_TYPES))
	poll_interval: int = DEFAULT_POLL_INTERVAL
	poll_timeout: int = DEFAULT_POLL_TIMEOUT
	results_page_size: int = DEFAULT_RESULTS_PAGE_SIZE
	include_raw: bool = True
	keep_archive: bool = False

	def to_dict(self) -> dict[str, Any]:
		return {
			"project_name": self.project_name,
			"source_path": str(self.source_path),
			"branch": self.branch,
			"scan_types": list(self.scan_types),
			"poll_interval": self.poll_interval,
			"poll_timeout": self.poll_timeout,
			"results_page_size": self.results_page_size,
			"include_raw": self.include_raw,
			"keep_archive": self.keep_archive,
		}


@dataclass(slots=True)
class ProjectScanRequest:
	project_name: str
	branch: str = ""
	results_page_size: int = DEFAULT_RESULTS_PAGE_SIZE
	include_raw: bool = True
	prefer_terminal_scan: bool = True
	scan_lookback: int = 100

	def to_dict(self) -> dict[str, Any]:
		return {
			"project_name": self.project_name,
			"branch": self.branch,
			"results_page_size": self.results_page_size,
			"include_raw": self.include_raw,
			"prefer_terminal_scan": self.prefer_terminal_scan,
			"scan_lookback": self.scan_lookback,
		}


@dataclass(slots=True)
class JenkinsArtifactRequest:
	job_url: str
	build_number: int | None = None
	artifact_name: str = "checkmarx-ast-results.json"
	poll_interval: int = DEFAULT_POLL_INTERVAL
	poll_timeout: int = DEFAULT_POLL_TIMEOUT
	include_raw: bool = True
	prefer_running_build: bool = True
	fallback_build_lookback: int = DEFAULT_JENKINS_FALLBACK_BUILDS

	def to_dict(self) -> dict[str, Any]:
		return {
			"job_url": self.job_url,
			"build_number": self.build_number,
			"artifact_name": self.artifact_name,
			"poll_interval": self.poll_interval,
			"poll_timeout": self.poll_timeout,
			"include_raw": self.include_raw,
			"prefer_running_build": self.prefer_running_build,
			"fallback_build_lookback": self.fallback_build_lookback,
		}


@dataclass(slots=True)
class ArchiveInfo:
	path: str
	created: bool
	size_bytes: int
	size_human: str
	retained: bool

	def to_dict(self) -> dict[str, Any]:
		return {
			"path": self.path,
			"created": self.created,
			"size_bytes": self.size_bytes,
			"size_human": self.size_human,
			"retained": self.retained,
		}


@dataclass(slots=True)
class FindingLocation:
	filename: str = ""
	line: int | None = None
	column: int | None = None

	@property
	def display(self) -> str:
		if not self.filename:
			return ""
		if self.line is not None and self.column is not None:
			return f"{self.filename}:{self.line}:{self.column}"
		if self.line is not None:
			return f"{self.filename}:{self.line}"
		return self.filename

	def to_dict(self) -> dict[str, Any]:
		return compact_dict(
			{
				"filename": self.filename,
				"line": self.line,
				"column": self.column,
				"display": self.display,
			}
		)


@dataclass(slots=True)
class JenkinsArtifactInfo:
	file_name: str
	relative_path: str
	display_path: str
	download_url: str

	def to_dict(self) -> dict[str, Any]:
		return compact_dict(
			{
				"file_name": self.file_name,
				"relative_path": self.relative_path,
				"display_path": self.display_path,
				"download_url": self.download_url,
			}
		)


@dataclass(slots=True)
class JenkinsBuildInfo:
	number: int
	url: str
	result: str = ""
	building: bool = False
	display_name: str = ""
	full_display_name: str = ""
	description: str = ""
	timestamp: int | None = None
	duration_ms: int | None = None
	artifact_count: int = 0
	selected_from: str = ""

	def to_dict(self) -> dict[str, Any]:
		return compact_dict(
			{
				"number": self.number,
				"url": self.url,
				"result": self.result,
				"building": self.building,
				"display_name": self.display_name,
				"full_display_name": self.full_display_name,
				"description": self.description,
				"timestamp": self.timestamp,
				"duration_ms": self.duration_ms,
				"artifact_count": self.artifact_count,
				"selected_from": self.selected_from,
			}
		)


@dataclass(slots=True)
class JenkinsArtifactSummary:
	build_selected_from: str
	build_result: str
	building: bool
	artifact_found: bool
	artifact_name: str
	report_kind: str
	report_total_findings: int | None = None
	detail_source: str = "artifact_summary_only"
	detailed_findings_available: bool = False
	detailed_findings_count: int | None = None

	def to_dict(self) -> dict[str, Any]:
		return compact_dict(
			{
				"build_selected_from": self.build_selected_from,
				"build_result": self.build_result,
				"building": self.building,
				"artifact_found": self.artifact_found,
				"artifact_name": self.artifact_name,
				"report_kind": self.report_kind,
				"report_total_findings": self.report_total_findings,
				"detail_source": self.detail_source,
				"detailed_findings_available": self.detailed_findings_available,
				"detailed_findings_count": self.detailed_findings_count,
			}
		)


@dataclass(slots=True)
class NormalizedFinding:
	index: int
	identifier: str
	finding_type: str
	severity: str
	state: str
	title: str
	description: str
	location: FindingLocation
	similarity_id: str = ""
	category: str = ""
	language: str = ""
	package_name: str = ""
	package_version: str = ""
	package_identifier: str = ""
	recommended_version: str = ""
	cwe: str = ""
	cvss_score: float | None = None
	fix_recommendation: str = ""
	references: list[str] = field(default_factory=list)
	attributes: dict[str, Any] = field(default_factory=dict)
	details: dict[str, Any] = field(default_factory=dict)

	def to_dict(self) -> dict[str, Any]:
		return compact_dict(
			{
				"index": self.index,
				"id": self.identifier,
				"type": self.finding_type,
				"severity": self.severity,
				"state": self.state,
				"title": self.title,
				"description": self.description,
				"location": self.location.to_dict(),
				"similarity_id": self.similarity_id,
				"category": self.category,
				"language": self.language,
				"package_name": self.package_name,
				"package_version": self.package_version,
				"package_identifier": self.package_identifier,
				"recommended_version": self.recommended_version,
				"cwe": self.cwe,
				"cvss_score": self.cvss_score,
				"fix_recommendation": self.fix_recommendation,
				"references": list(self.references),
				"attributes": dict(self.attributes),
				"details": dict(self.details),
			}
		)


@dataclass(slots=True)
class ScanSummary:
	total_findings: int
	terminal_status: str
	status_details: str
	successful: bool
	severity_counts: dict[str, int]
	engine_counts: dict[str, int]
	highest_severity: str = "unknown"

	def to_dict(self) -> dict[str, Any]:
		return {
			"total_findings": self.total_findings,
			"terminal_status": self.terminal_status,
			"status_details": self.status_details,
			"successful": self.successful,
			"severity_counts": dict(self.severity_counts),
			"engine_counts": dict(self.engine_counts),
			"highest_severity": self.highest_severity,
		}


@dataclass(slots=True)
class ScanExecutionReport:
	generated_at: str
	request: dict[str, Any]
	archive: ArchiveInfo
	project: dict[str, Any]
	scan: dict[str, Any]
	summary: ScanSummary
	findings: list[NormalizedFinding]
	agent_report: dict[str, Any] | None = None
	raw: dict[str, Any] | None = None

	def to_dict(self, *, include_raw: bool | None = None, profile: str | None = None) -> dict[str, Any]:
		should_include_raw = self.raw is not None if include_raw is None else include_raw
		resolved_profile = normalize_report_profile(profile)
		payload = {
			"generated_at": self.generated_at,
			"request": dict(self.request),
			"archive": self.archive.to_dict(),
			"project": dict(self.project),
			"scan": dict(self.scan),
			"summary": self.summary.to_dict(),
		}
		if resolved_profile == REPORT_PROFILE_FULL:
			payload["findings"] = [finding.to_dict() for finding in self.findings]
		if self.agent_report is not None:
			payload["agent_report"] = serialize_agent_report(self.agent_report, resolved_profile)
		if resolved_profile != REPORT_PROFILE_FULL:
			payload["report_profile"] = resolved_profile
		if should_include_raw and self.raw is not None:
			payload["raw"] = dict(self.raw)
		return payload


@dataclass(slots=True)
class ProjectScanExecutionReport:
	generated_at: str
	request: dict[str, Any]
	project: dict[str, Any]
	scan: dict[str, Any]
	summary: ScanSummary
	findings: list[NormalizedFinding]
	agent_report: dict[str, Any] | None = None
	raw: dict[str, Any] | None = None

	def to_dict(self, *, include_raw: bool | None = None, profile: str | None = None) -> dict[str, Any]:
		should_include_raw = self.raw is not None if include_raw is None else include_raw
		resolved_profile = normalize_report_profile(profile)
		payload = {
			"generated_at": self.generated_at,
			"request": dict(self.request),
			"project": dict(self.project),
			"scan": dict(self.scan),
			"summary": self.summary.to_dict(),
		}
		if resolved_profile == REPORT_PROFILE_FULL:
			payload["findings"] = [finding.to_dict() for finding in self.findings]
		if self.agent_report is not None:
			payload["agent_report"] = serialize_agent_report(self.agent_report, resolved_profile)
		if resolved_profile != REPORT_PROFILE_FULL:
			payload["report_profile"] = resolved_profile
		if should_include_raw and self.raw is not None:
			payload["raw"] = dict(self.raw)
		return payload


@dataclass(slots=True)
class JenkinsArtifactExecutionReport:
	generated_at: str
	request: dict[str, Any]
	job: dict[str, Any]
	build: JenkinsBuildInfo
	artifact: JenkinsArtifactInfo
	summary: JenkinsArtifactSummary
	report: Any
	agent_report: dict[str, Any] | None = None
	raw: dict[str, Any] | None = None

	def to_dict(self, *, include_raw: bool | None = None, profile: str | None = None) -> dict[str, Any]:
		should_include_raw = self.raw is not None if include_raw is None else include_raw
		resolved_profile = normalize_report_profile(profile)
		payload = {
			"generated_at": self.generated_at,
			"request": dict(self.request),
			"job": dict(self.job),
			"build": self.build.to_dict(),
			"artifact": self.artifact.to_dict(),
			"summary": self.summary.to_dict(),
			"report": self.report,
		}
		if self.agent_report is not None:
			payload["agent_report"] = serialize_agent_report(self.agent_report, resolved_profile)
		if resolved_profile != REPORT_PROFILE_FULL:
			payload["report_profile"] = resolved_profile
		if should_include_raw and self.raw is not None:
			payload["raw"] = dict(self.raw)
		return payload
