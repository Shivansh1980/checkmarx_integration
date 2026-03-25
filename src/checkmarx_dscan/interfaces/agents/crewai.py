from __future__ import annotations

from typing import Any

from .common import (
	CHECKMARX_PROJECT_SCAN_TOOL_DESCRIPTION,
	CHECKMARX_PROJECT_SCAN_TOOL_NAME,
	CHECKMARX_SCAN_TOOL_DESCRIPTION,
	CHECKMARX_SCAN_TOOL_NAME,
	JENKINS_ARTIFACT_TOOL_DESCRIPTION,
	JENKINS_ARTIFACT_TOOL_NAME,
	run_checkmarx_scan_tool_json,
	run_jenkins_artifact_tool_json,
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
		project: str = Field(..., description="Checkmarx project name to scan.")
		source: str = Field(default="", description="Directory, file, or zip archive to upload and scan. Leave empty to inspect the latest existing project scan.")
		env_file: str = Field(default=".env", description="Path to a .env file containing Checkmarx settings.")
		scan_mode: str = Field(default="auto", description="auto selects upload when source is provided, otherwise latest_project. Allowed values: auto, upload, latest_project.")
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
		build_number: int | None = Field(default=None, description="Specific build number to inspect. If omitted, the tool tracks the active build or falls back to the latest completed build.")
		artifact_name: str = Field(default="", description="Exact artifact file name to retrieve. Defaults to checkmarx-ast-results.json.")
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
