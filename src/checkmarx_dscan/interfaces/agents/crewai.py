from __future__ import annotations

from typing import Any

from .common import (
	CHECKMARX_PROJECT_SCAN_TOOL_DESCRIPTION,
	CHECKMARX_PROJECT_SCAN_TOOL_NAME,
	CHECKMARX_SCAN_TOOL_DESCRIPTION,
	CHECKMARX_SCAN_TOOL_NAME,
	JENKINS_ARTIFACT_TOOL_DESCRIPTION,
	JENKINS_ARTIFACT_TOOL_NAME,
	SONAR_TOOL_DESCRIPTION,
	SONAR_TOOL_NAME,
	run_checkmarx_scan_tool_json,
	run_jenkins_artifact_tool_json,
	run_sonar_tool_json,
)
from ...domain.errors import CrewAIToolDependencyError


def run_checkmarx_scan_tool(**kwargs: Any) -> str:
	return run_checkmarx_scan_tool_json(**kwargs)


def run_checkmarx_project_scan_tool(**kwargs: Any) -> str:
	legacy_kwargs = dict(kwargs)
	legacy_kwargs.setdefault("source", "")
	legacy_kwargs["scan_mode"] = "latest_project"
	return run_checkmarx_scan_tool_json(**legacy_kwargs)


def run_jenkins_artifact_tool(**kwargs: Any) -> str:
	return run_jenkins_artifact_tool_json(**kwargs)


def run_sonar_tool(**kwargs: Any) -> str:
	return run_sonar_tool_json(**kwargs)


try:
	from crewai.tools import BaseTool
	from pydantic import BaseModel, Field
except ImportError as exc:
	_IMPORT_ERROR = exc

	class CheckmarxScanTool:  # type: ignore[no-redef]
		def __init__(self, *args: Any, **kwargs: Any) -> None:
			raise CrewAIToolDependencyError(
				"Install the optional crewai dependencies with `pip install -e .[crewai]` to use CheckmarxScanTool."
			) from _IMPORT_ERROR

	class CheckmarxProjectScanTool:  # type: ignore[no-redef]
		def __init__(self, *args: Any, **kwargs: Any) -> None:
			raise CrewAIToolDependencyError(
				"Install the optional crewai dependencies with `pip install -e .[crewai]` to use CheckmarxProjectScanTool."
			) from _IMPORT_ERROR

	class JenkinsArtifactTool:  # type: ignore[no-redef]
		def __init__(self, *args: Any, **kwargs: Any) -> None:
			raise CrewAIToolDependencyError(
				"Install the optional crewai dependencies with `pip install -e .[crewai]` to use JenkinsArtifactTool."
			) from _IMPORT_ERROR

	class SonarTool:  # type: ignore[no-redef]
		def __init__(self, *args: Any, **kwargs: Any) -> None:
			raise CrewAIToolDependencyError(
				"Install the optional crewai dependencies with `pip install -e .[crewai]` to use SonarTool."
			) from _IMPORT_ERROR

else:
	class CheckmarxProjectScanToolInput(BaseModel):
		project: str = Field(..., description="Existing Checkmarx project name to inspect.")
		env_file: str = Field(default=".env", description="Path to a .env file containing Checkmarx settings.")
		branch: str = Field(default="", description="Optional branch name used to narrow the latest scan lookup.")
		timeout: int | None = Field(default=None, description="Per-request HTTP timeout in seconds.")
		results_page_size: int | None = Field(default=None, description="How many findings to request per results page.")
		include_raw: bool = Field(default=True, description="Include raw Checkmarx API payloads in the JSON response.")
		output_json: str | None = Field(default=None, description="Optional path where the JSON report should be written.")
		base_url: str = Field(default="", description="Optional override for CHECKMARX_BASE_URL.")
		api_token: str = Field(default="", description="Optional override for CHECKMARX_API_TOKEN.")
		auth_url: str = Field(default="", description="Optional override for CHECKMARX_AUTH_URL.")
		tenant: str = Field(default="", description="Optional override for CHECKMARX_TENANT.")
		prefer_terminal_scan: bool = Field(default=True, description="Prefer the latest terminal scan over a still-running scan.")
		scan_lookback: int | None = Field(default=None, description="How many recent scans to inspect when picking the latest scan.")

	class CheckmarxScanToolInput(BaseModel):
		project: str = Field(default="", description="Checkmarx project name to scan, or an approximate project query when scan_mode=projects.")
		project_query: str = Field(default="", description="Optional explicit project query used only when scan_mode=projects.")
		source: str = Field(default="", description="Directory, file, or zip archive to upload and scan. It is used only when scan_mode=upload.")
		env_file: str = Field(default=".env", description="Path to a .env file containing Checkmarx settings.")
		scan_mode: str = Field(default="auto", description="auto defaults to latest_project. Use upload only when the user explicitly wants to upload local source. Allowed values: auto, upload, latest_project, projects.")
		report_profile: str = Field(default="compact", description="Accepted for compatibility with MCP clients. Current responses are compact by default.")
		branch: str = Field(default="", description="Branch name associated with the scan.")
		scan_types: str = Field(default="", description="Comma-separated scan engines such as sast, sca, iac-security.")
		timeout: int | None = Field(default=None, description="Per-request HTTP timeout in seconds.")
		poll_interval: int | None = Field(default=None, description="Seconds between scan status checks.")
		poll_timeout: int | None = Field(default=None, description="Maximum wait time in seconds; 0 disables the timeout.")
		results_page_size: int | None = Field(default=None, description="How many findings to request per results page.")
		include_raw: bool = Field(default=True, description="Include raw Checkmarx API payloads in the JSON response.")
		keep_archive: bool = Field(default=False, description="Keep the generated temporary upload archive on disk.")
		output_json: str | None = Field(default=None, description="Optional path where the JSON report should be written.")
		base_url: str = Field(default="", description="Optional override for CHECKMARX_BASE_URL.")
		api_token: str = Field(default="", description="Optional override for CHECKMARX_API_TOKEN.")
		auth_url: str = Field(default="", description="Optional override for CHECKMARX_AUTH_URL.")
		tenant: str = Field(default="", description="Optional override for CHECKMARX_TENANT.")
		prefer_terminal_scan: bool = Field(default=True, description="For latest_project mode, prefer the latest terminal scan over a still-running scan.")
		scan_lookback: int | None = Field(default=None, description="For latest_project mode, how many recent scans to inspect when choosing the latest scan.")

	class CheckmarxScanTool(BaseTool):
		name: str = CHECKMARX_SCAN_TOOL_NAME
		description: str = CHECKMARX_SCAN_TOOL_DESCRIPTION
		args_schema: type[BaseModel] = CheckmarxScanToolInput

		def _run(self, **kwargs: Any) -> str:
			return run_checkmarx_scan_tool(**kwargs)

	class CheckmarxProjectScanTool(BaseTool):
		name: str = CHECKMARX_PROJECT_SCAN_TOOL_NAME
		description: str = CHECKMARX_PROJECT_SCAN_TOOL_DESCRIPTION
		args_schema: type[BaseModel] = CheckmarxProjectScanToolInput

		def _run(self, **kwargs: Any) -> str:
			return run_checkmarx_project_scan_tool(**kwargs)

	class JenkinsArtifactToolInput(BaseModel):
		job_url: str = Field(..., description="Full Jenkins job URL to inspect for the Checkmarx artifact.")
		env_file: str = Field(default=".env", description="Path to a .env file containing Jenkins settings.")
		pr_number: int | None = Field(default=None, description="PR number to resolve under a Jenkins change-requests view. If omitted, the latest PR job is used.")
		build_number: int | None = Field(default=None, description="Specific build number to inspect. If omitted, the tool tracks the active build or falls back to the latest completed build.")
		artifact_name: str = Field(default="", description="Exact artifact file name to retrieve. Defaults to checkmarx-ast-results.json.")
		report_profile: str = Field(default="compact", description="Accepted for compatibility with MCP clients. Current responses are compact by default.")
		timeout: int | None = Field(default=None, description="Per-request HTTP timeout in seconds.")
		poll_interval: int | None = Field(default=None, description="Seconds between Jenkins build and artifact checks.")
		poll_timeout: int | None = Field(default=None, description="Maximum wait time in seconds; 0 disables the timeout.")
		fallback_build_lookback: int | None = Field(default=None, description="How many prior build numbers to search automatically when the latest build did not archive the Checkmarx artifact.")
		include_raw: bool = Field(default=True, description="Include raw Jenkins API payloads in the JSON response.")
		output_json: str | None = Field(default=None, description="Optional path where the retrieved artifact bundle should be written.")
		base_url: str = Field(default="", description="Optional override for JENKINS_BASE_URL.")
		username: str = Field(default="", description="Optional override for JENKINS_USERNAME.")
		api_token: str = Field(default="", description="Optional override for JENKINS_API_TOKEN.")
		checkmarx_base_url: str = Field(default="", description="Optional override for CHECKMARX_BASE_URL used for findings enrichment.")
		checkmarx_api_token: str = Field(default="", description="Optional override for CHECKMARX_API_TOKEN used for findings enrichment.")
		checkmarx_auth_url: str = Field(default="", description="Optional override for CHECKMARX_AUTH_URL used for findings enrichment.")
		checkmarx_tenant: str = Field(default="", description="Optional override for CHECKMARX_TENANT used for findings enrichment.")
		prefer_running_build: bool = Field(default=True, description="Prefer the currently running build before falling back to the latest completed build.")

	class JenkinsArtifactTool(BaseTool):
		name: str = JENKINS_ARTIFACT_TOOL_NAME
		description: str = JENKINS_ARTIFACT_TOOL_DESCRIPTION
		args_schema: type[BaseModel] = JenkinsArtifactToolInput

		def _run(self, **kwargs: Any) -> str:
			return run_jenkins_artifact_tool(**kwargs)

	class SonarToolInput(BaseModel):
		operation: str = Field(default="remote_report", description="Sonar operation to run. Allowed values: access_probe, projects, remote_report, file_detail, local_report (Python convenience that runs pytest+coverage), local_quality_gate (stack-agnostic; does NOT run tests, supply local_metrics).")
		project: str = Field(default="", description="Sonar project key for remote_report, file_detail, or local_report comparison.")
		base_url: str = Field(default="", description="Optional override for SONAR_BASE_URL.")
		token: str = Field(default="", description="Optional override for SONAR_TOKEN.")
		env_file: str = Field(default=".env", description="Path to a .env file containing Sonar settings.")
		timeout: int | None = Field(default=None, description="Per-request HTTP timeout in seconds.")
		branch: str = Field(default="", description="Optional branch name for remote Sonar lookups.")
		pull_request: str = Field(default="", description="Optional pull request key for remote Sonar lookups.")
		project_query: str = Field(default="", description="Project search text used by access_probe or projects.")
		include_projects: bool = Field(default=False, description="For access_probe, include a sample of discovered projects.")
		page: int = Field(default=1, description="Page number for projects listing.")
		page_size: int = Field(default=100, description="Page size for projects listing.")
		include_branches_for: str = Field(default="", description="Optional project key whose branches should be included in projects mode.")
		file_limit: int = Field(default=25, description="Maximum number of files to return in remote_report or local_report.")
		coverage_threshold: float = Field(default=80.0, description="Coverage threshold used for prioritization and local pass/fail prediction.")
		file: str = Field(default="", description="Project-relative file path for file_detail.")
		file_key: str = Field(default="", description="Explicit Sonar component key for file_detail.")
		include_source: bool = Field(default=True, description="For file_detail, include source excerpt when accessible.")
		include_line_details: bool = Field(default=True, description="For file_detail, attempt to include covered and uncovered line numbers.")
		use_internal_fallbacks: bool = Field(default=False, description="For file_detail, use internal Sonar component endpoints to estimate line-level coverage.")
		local_working_directory: str = Field(default="", description="For local_report, working directory to run coverage from.")
		local_source_paths: str = Field(default="", description="For local_report, comma-separated source paths to pass to coverage.py.")
		local_pytest_args: str = Field(default="", description="For local_report, additional pytest arguments.")
		local_timeout: int | None = Field(default=None, description="For local_report, local command timeout in seconds.")
		local_metrics: dict[str, Any] | None = Field(default=None, description="For local_quality_gate, locally-measured metrics keyed by Sonar metric name (e.g. {'coverage': 78.5, 'line_coverage': 82.0, 'branch_coverage': 65.0}). Omit on the first call to receive measurement_instructions.")
		compare_with_remote: bool = Field(default=False, description="For local_report, compare local results with remote Sonar project coverage when available.")
		include_raw: bool = Field(default=False, description="Include raw Sonar or local coverage payloads in the JSON response.")
		output_json: str | None = Field(default=None, description="Optional path where the Sonar report should be written.")

	class SonarTool(BaseTool):
		name: str = SONAR_TOOL_NAME
		description: str = SONAR_TOOL_DESCRIPTION
		args_schema: type[BaseModel] = SonarToolInput

		def _run(self, **kwargs: Any) -> str:
			return run_sonar_tool(**kwargs)
