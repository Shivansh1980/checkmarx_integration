from __future__ import annotations

from typing import Any

from ...application.config.resolvers import (
	load_env_file,
	resolve_credentials,
	resolve_jenkins_artifact_request,
	resolve_jenkins_credentials,
	resolve_project_scan_request,
	resolve_scan_request,
	resolve_sonar_credentials,
)
from ...application.services.checkmarx_scan import CheckmarxScanService
from ...application.services.jenkins_artifact import JenkinsArtifactService
from ...application.services.project_catalog import CheckmarxProjectCatalogService
from ...application.services.project_scan import ProjectScanService
from ...application.services.sonar import SonarCoverageService
from ...domain.errors import CheckmarxError
from ...domain.models import REPORT_PROFILE_COMPACT, normalize_report_profile
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

SONAR_TOOL_NAME = "sonar"
SONAR_TOOL_DESCRIPTION = (
	"Unified SonarQube and local coverage tool. Use operation=access_probe to validate server access, operation=projects to "
	"discover project keys, operation=remote_report to fetch the latest SonarQube coverage for a project, operation=file_detail "
	"to inspect one file, and operation=local_report to run pytest-based local coverage in the current workspace and predict "
	"whether the code is likely to clear the requested Sonar coverage threshold before push."
)


def _resolve_sonar_operation(operation: str) -> str:
	resolved = str(operation or "remote_report").strip().lower().replace("-", "_")
	allowed = {"access_probe", "projects", "remote_report", "file_detail", "local_report"}
	if resolved not in allowed:
		raise CheckmarxError(f"operation must be one of: {', '.join(sorted(allowed))}")
	return resolved


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
	report_profile = normalize_report_profile(kwargs.get("report_profile", REPORT_PROFILE_COMPACT))
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
		payload = report.to_dict(include_raw=include_raw, profile=report_profile)
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
		payload = report.to_dict(include_raw=include_raw, profile=report_profile)
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
	report_profile = normalize_report_profile(kwargs.get("report_profile", REPORT_PROFILE_COMPACT))
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
	payload = report.to_dict(include_raw=include_raw, profile=report_profile)
	if kwargs.get("output_json"):
		write_output_json(kwargs["output_json"], payload, default_file_name="jenkins_artifact_report.json")
	return payload


def run_jenkins_artifact_tool_json(**kwargs: Any) -> str:
	return dumps_json(execute_jenkins_artifact_tool(**kwargs))


def execute_sonar_tool(**kwargs: Any) -> dict[str, Any]:
	load_env_file(kwargs.get("env_file", ".env"))
	operation = _resolve_sonar_operation(kwargs.get("operation", "remote_report"))
	credentials = resolve_sonar_credentials(
		base_url=kwargs.get("base_url", ""),
		token=kwargs.get("token", ""),
		timeout=kwargs.get("timeout"),
		require_base_url=operation != "local_report",
	)
	service = SonarCoverageService(credentials)
	if operation == "access_probe":
		payload = service.access_probe(
			project=kwargs.get("project", ""),
			branch=kwargs.get("branch", ""),
			project_query=kwargs.get("project_query", ""),
			include_projects=kwargs.get("include_projects", False),
		)
	elif operation == "projects":
		payload = service.list_projects(
			project_query=kwargs.get("project_query", ""),
			page=kwargs.get("page", 1),
			page_size=kwargs.get("page_size", 100),
			include_branches_for=kwargs.get("include_branches_for", ""),
		)
	elif operation == "file_detail":
		payload = service.file_coverage_detail(
			project=kwargs["project"],
			branch=kwargs.get("branch", ""),
			pull_request=kwargs.get("pull_request", ""),
			file=kwargs.get("file", ""),
			file_key=kwargs.get("file_key", ""),
			include_source=kwargs.get("include_source", True),
			include_line_details=kwargs.get("include_line_details", True),
			use_internal_fallbacks=kwargs.get("use_internal_fallbacks", False),
			include_raw=kwargs.get("include_raw", False),
		)
	elif operation == "local_report":
		payload = service.local_coverage_report(
			project=kwargs.get("project", ""),
			branch=kwargs.get("branch", ""),
			pull_request=kwargs.get("pull_request", ""),
			working_directory=kwargs.get("local_working_directory", ""),
			source_paths=kwargs.get("local_source_paths", ""),
			pytest_args=kwargs.get("local_pytest_args", ""),
			coverage_threshold=kwargs.get("coverage_threshold", 80.0),
			file_limit=kwargs.get("file_limit", 25),
			local_timeout=kwargs.get("local_timeout"),
			compare_with_remote=kwargs.get("compare_with_remote", False),
			include_raw=kwargs.get("include_raw", False),
		)
	else:
		payload = service.coverage_report(
			project=kwargs["project"],
			branch=kwargs.get("branch", ""),
			pull_request=kwargs.get("pull_request", ""),
			file_limit=kwargs.get("file_limit", 25),
			coverage_threshold=kwargs.get("coverage_threshold", 80.0),
			include_raw=kwargs.get("include_raw", False),
		)
	if kwargs.get("output_json"):
		default_file_name = {
			"access_probe": "sonar_access_probe_report.json",
			"projects": "sonar_projects_report.json",
			"remote_report": "sonar_coverage_report.json",
			"file_detail": "sonar_file_coverage_detail.json",
			"local_report": "sonar_local_coverage_report.json",
		}[operation]
		write_output_json(kwargs["output_json"], payload, default_file_name=default_file_name)
	return payload


def execute_sonar_access_probe_tool(**kwargs: Any) -> dict[str, Any]:
	legacy_kwargs = dict(kwargs)
	legacy_kwargs["operation"] = "access_probe"
	return execute_sonar_tool(**legacy_kwargs)


def execute_sonar_projects_tool(**kwargs: Any) -> dict[str, Any]:
	legacy_kwargs = dict(kwargs)
	legacy_kwargs["operation"] = "projects"
	return execute_sonar_tool(**legacy_kwargs)


def execute_sonar_coverage_report_tool(**kwargs: Any) -> dict[str, Any]:
	legacy_kwargs = dict(kwargs)
	legacy_kwargs["operation"] = "remote_report"
	return execute_sonar_tool(**legacy_kwargs)


def execute_sonar_file_coverage_detail_tool(**kwargs: Any) -> dict[str, Any]:
	legacy_kwargs = dict(kwargs)
	legacy_kwargs["operation"] = "file_detail"
	return execute_sonar_tool(**legacy_kwargs)


__all__ = [
	"CHECKMARX_PROJECT_SCAN_TOOL_DESCRIPTION",
	"CHECKMARX_PROJECT_SCAN_TOOL_NAME",
	"CHECKMARX_SCAN_TOOL_DESCRIPTION",
	"CHECKMARX_SCAN_TOOL_NAME",
	"JENKINS_ARTIFACT_TOOL_DESCRIPTION",
	"JENKINS_ARTIFACT_TOOL_NAME",
	"SONAR_TOOL_DESCRIPTION",
	"SONAR_TOOL_NAME",
	"execute_checkmarx_project_scan_tool",
	"execute_checkmarx_scan_tool",
	"execute_jenkins_artifact_tool",
	"execute_sonar_access_probe_tool",
	"execute_sonar_coverage_report_tool",
	"execute_sonar_file_coverage_detail_tool",
	"execute_sonar_projects_tool",
	"execute_sonar_tool",
	"run_checkmarx_project_scan_tool_json",
	"run_checkmarx_scan_tool_json",
	"run_jenkins_artifact_tool_json",
]