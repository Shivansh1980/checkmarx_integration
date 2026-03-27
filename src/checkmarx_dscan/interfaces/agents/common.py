from __future__ import annotations

from typing import Any

from ...application.config.resolvers import (
	load_env_file,
	resolve_credentials,
	resolve_jenkins_artifact_request,
	resolve_jenkins_credentials,
	resolve_project_scan_request,
	resolve_scan_request,
)
from ...application.services.checkmarx_scan import CheckmarxScanService
from ...application.services.jenkins_artifact import JenkinsArtifactService
from ...application.services.project_catalog import CheckmarxProjectCatalogService
from ...application.services.project_scan import ProjectScanService
from ...domain.errors import CheckmarxError
from ...infrastructure.serialization.json import dumps_json, write_output_json


CHECKMARX_SCAN_TOOL_NAME = "checkmarx_scan"
CHECKMARX_SCAN_TOOL_DESCRIPTION = (
	"Run Checkmarx through a single tool in three modes. Use scan_mode=projects to enumerate accessible Checkmarx projects "
	"and get best-match candidates for a user-supplied project query. By default, fetch the latest existing Checkmarx scan "
	"for the project and optional branch directly from Checkmarx. Use scan_mode=upload only when the user explicitly wants "
	"to upload local source and start a new scan. When source is omitted or scan_mode=latest_project, fetch the "
	"latest existing Checkmarx scan for the project and optional branch directly from Checkmarx. Scan report modes return "
	"normalized findings plus an agent_report section containing vulnerability_summary, engine_coverage, top_actionable_issues, "
	"top_fix_targets, and categorized code/dependency/container/infrastructure issues. Use findings or "
	"agent_report.vulnerabilities for long-form detail. report_profile is accepted for client compatibility and current "
	"responses remain compact by default. Use include_raw=true only when the normalized and agent-friendly "
	"fields are insufficient and raw.final_scan/raw.results are needed."
)

CHECKMARX_PROJECT_SCAN_TOOL_NAME = "checkmarx_project_latest_scan"
CHECKMARX_PROJECT_SCAN_TOOL_DESCRIPTION = (
	"Fetch the latest existing Checkmarx One scan for a project and optional branch directly from Checkmarx, "
	"then return normalized findings plus an agent_report section containing vulnerability_summary, engine_coverage, "
	"top_actionable_issues, top_fix_targets, and categorized code/dependency/container/infrastructure issues. "
	"Prefer this tool over Jenkins when you want the latest project scan directly from Checkmarx. Use findings or "
	"agent_report.vulnerabilities for long-form detail. Use include_raw=true when raw.final_scan/raw.results are needed."
)

JENKINS_ARTIFACT_TOOL_NAME = "jenkins_artifact"
JENKINS_ARTIFACT_TOOL_DESCRIPTION = (
	"Track a Jenkins pipeline build, locate the archived Checkmarx JSON artifact, download it, and return a JSON bundle "
	"containing Jenkins metadata plus an agent_report section with vulnerability_summary, engine_coverage when available, "
	"top_actionable_issues, top_fix_targets, and detailed vulnerabilities when Checkmarx enrichment succeeds. When "
	"detail_source is artifact_summary_only, use checkmarx_scan without a source path or with scan_mode=latest_project for "
	"a direct Checkmarx lookup if you need full finding descriptions."
)


def _resolve_checkmarx_scan_mode(scan_mode: str, source: str) -> str:
	resolved_mode = (scan_mode or "auto").strip().lower().replace("-", "_")
	if resolved_mode in {"project_catalog", "enumerate_projects"}:
		resolved_mode = "projects"
	if resolved_mode not in {"auto", "upload", "latest_project", "projects"}:
		raise CheckmarxError("scan_mode must be one of: auto, upload, latest_project, projects")
	if resolved_mode == "auto":
		return "latest_project"
	return resolved_mode


def execute_checkmarx_scan_tool(**kwargs: Any) -> dict[str, Any]:
	load_env_file(kwargs.get("env_file", ".env"))
	include_raw = kwargs.get("include_raw", True)
	source = kwargs.get("source", "")
	resolved_mode = _resolve_checkmarx_scan_mode(kwargs.get("scan_mode", "auto"), source)
	credentials = resolve_credentials(
		base_url=kwargs.get("base_url", ""),
		api_token=kwargs.get("api_token", ""),
		auth_url=kwargs.get("auth_url", ""),
		tenant=kwargs.get("tenant", ""),
		timeout=kwargs.get("timeout"),
	)
	if resolved_mode == "projects":
		payload = CheckmarxProjectCatalogService(credentials).execute(
			project_query=kwargs.get("project_query") or kwargs.get("project", ""),
			include_raw=include_raw,
		)
	elif resolved_mode == "upload":
		request = resolve_scan_request(
			project_name=kwargs["project"],
			source=source,
			branch=kwargs.get("branch", ""),
			scan_types=kwargs.get("scan_types", ""),
			poll_interval=kwargs.get("poll_interval"),
			poll_timeout=kwargs.get("poll_timeout"),
			results_page_size=kwargs.get("results_page_size"),
			include_raw=include_raw,
			keep_archive=kwargs.get("keep_archive", False),
		)
		report = CheckmarxScanService(credentials).execute(request)
		payload = report.to_dict(include_raw=include_raw)
	else:
		request = resolve_project_scan_request(
			project_name=kwargs["project"],
			branch=kwargs.get("branch", ""),
			results_page_size=kwargs.get("results_page_size"),
			include_raw=include_raw,
			prefer_terminal_scan=kwargs.get("prefer_terminal_scan", True),
			scan_lookback=kwargs.get("scan_lookback"),
		)
		report = ProjectScanService(credentials).execute(request)
		payload = report.to_dict(include_raw=include_raw)
	if kwargs.get("output_json"):
		write_output_json(kwargs["output_json"], payload, default_file_name="checkmarx_scan_report.json")
	return payload


def run_checkmarx_scan_tool_json(**kwargs: Any) -> str:
	return dumps_json(execute_checkmarx_scan_tool(**kwargs))


def execute_checkmarx_project_scan_tool(**kwargs: Any) -> dict[str, Any]:
	legacy_kwargs = dict(kwargs)
	legacy_kwargs.setdefault("source", "")
	legacy_kwargs["scan_mode"] = "latest_project"
	return execute_checkmarx_scan_tool(**legacy_kwargs)


def run_checkmarx_project_scan_tool_json(**kwargs: Any) -> str:
	return dumps_json(execute_checkmarx_project_scan_tool(**kwargs))


def execute_jenkins_artifact_tool(**kwargs: Any) -> dict[str, Any]:
	load_env_file(kwargs.get("env_file", ".env"))
	include_raw = kwargs.get("include_raw", True)
	credentials = resolve_jenkins_credentials(
		base_url=kwargs.get("base_url", ""),
		username=kwargs.get("username", ""),
		api_token=kwargs.get("api_token", ""),
		timeout=kwargs.get("timeout"),
	)
	checkmarx_credentials = None
	try:
		checkmarx_credentials = resolve_credentials(
			base_url=kwargs.get("checkmarx_base_url", ""),
			api_token=kwargs.get("checkmarx_api_token", ""),
			auth_url=kwargs.get("checkmarx_auth_url", ""),
			tenant=kwargs.get("checkmarx_tenant", ""),
			timeout=kwargs.get("timeout"),
		)
	except CheckmarxError:
		checkmarx_credentials = None
	request = resolve_jenkins_artifact_request(
		job_url=kwargs["job_url"],
		build_number=kwargs.get("build_number"),
		artifact_name=kwargs.get("artifact_name", ""),
		poll_interval=kwargs.get("poll_interval"),
		poll_timeout=kwargs.get("poll_timeout"),
		include_raw=include_raw,
		prefer_running_build=kwargs.get("prefer_running_build", True),
		fallback_build_lookback=kwargs.get("fallback_build_lookback"),
		credentials=credentials,
	)
	report = JenkinsArtifactService(credentials, checkmarx_credentials=checkmarx_credentials).execute(request)
	payload = report.to_dict(include_raw=include_raw)
	if kwargs.get("output_json"):
		write_output_json(kwargs["output_json"], payload, default_file_name="jenkins_artifact_report.json")
	return payload


def run_jenkins_artifact_tool_json(**kwargs: Any) -> str:
	return dumps_json(execute_jenkins_artifact_tool(**kwargs))


__all__ = [
	"CHECKMARX_PROJECT_SCAN_TOOL_DESCRIPTION",
	"CHECKMARX_PROJECT_SCAN_TOOL_NAME",
	"CHECKMARX_SCAN_TOOL_DESCRIPTION",
	"CHECKMARX_SCAN_TOOL_NAME",
	"JENKINS_ARTIFACT_TOOL_DESCRIPTION",
	"JENKINS_ARTIFACT_TOOL_NAME",
	"execute_checkmarx_project_scan_tool",
	"execute_checkmarx_scan_tool",
	"execute_jenkins_artifact_tool",
	"run_checkmarx_project_scan_tool_json",
	"run_checkmarx_scan_tool_json",
	"run_jenkins_artifact_tool_json",
]