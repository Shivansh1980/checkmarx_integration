from __future__ import annotations

import sys
from typing import Any

from .common import (
	CHECKMARX_SCAN_TOOL_DESCRIPTION,
	CHECKMARX_SCAN_TOOL_NAME,
	JENKINS_ARTIFACT_TOOL_DESCRIPTION,
	JENKINS_ARTIFACT_TOOL_NAME,
	execute_checkmarx_scan_tool,
	execute_jenkins_artifact_tool,
)
from ...domain.errors import CheckmarxError, MCPServerDependencyError


SERVER_NAME = "checkmarx-dscan"
SERVER_INSTRUCTIONS = (
	"Use these tools to retrieve Checkmarx One vulnerability data in two ways: "
	"(1) checkmarx_scan for either creating a new upload scan from local source or, when source is omitted or "
	"scan_mode=latest_project, fetching the latest existing scan for a Checkmarx project and optional branch, and "
	"(2) jenkins_artifact for Jenkins-archived Checkmarx reports with optional Checkmarx enrichment. "
	"For agent-friendly consumption, start with agent_report.vulnerability_summary, agent_report.engine_coverage, "
	"agent_report.top_actionable_issues, and agent_report.top_fix_targets. If more detail is required, read "
	"agent_report.vulnerabilities or findings. If native Checkmarx payload detail is required, call the tool with "
	"include_raw=true and inspect raw.final_scan and raw.results. output_json only writes a local copy; the primary "
	"result for MCP clients is the structured tool response itself."
)


def _build_tool_error_response(tool_name: str, exc: Exception, **context: Any) -> dict[str, Any]:
	message = str(exc).strip() or exc.__class__.__name__
	lower_message = message.lower()
	error_code = "tool_execution_failed"
	error_category = "execution"
	retryable = False
	remediation: list[str] = []

	if "missing checkmarx api token" in lower_message:
		error_code = "missing_checkmarx_api_token"
		error_category = "configuration"
		remediation = [
			"Pass api_token in the tool call.",
			"Set CHECKMARX_API_TOKEN or CX_APIKEY in the MCP server process environment.",
			"If the token is stored in a workspace .env file, pass env_file as an absolute path or launch the MCP server from the workspace root.",
		]
	elif "unable to resolve the checkmarx base url" in lower_message:
		error_code = "missing_checkmarx_base_url"
		error_category = "configuration"
		remediation = [
			"Pass base_url in the tool call.",
			"Set CHECKMARX_BASE_URL or CX_BASE_URI in the MCP server process environment.",
			"If the base URL is stored in a workspace .env file, pass env_file as an absolute path or launch the MCP server from the workspace root.",
		]
	elif "timed out" in lower_message or "failed with 5" in lower_message:
		error_code = "upstream_service_failure"
		error_category = "upstream"
		retryable = True

	payload = {
		"ok": False,
		"tool": tool_name,
		"error": {
			"code": error_code,
			"category": error_category,
			"message": message,
			"retryable": retryable,
		},
		"remediation": remediation,
		"server": SERVER_NAME,
	}
	if context:
		payload["context"] = {key: value for key, value in context.items() if value not in (None, "", [], {}, ())}
	return payload


try:
	from mcp.server.fastmcp import FastMCP
except ImportError as exc:
	_IMPORT_ERROR = exc

	def create_mcp_server() -> Any:
		raise MCPServerDependencyError(
			"Install the optional MCP dependencies with `pip install -e .[mcp]` to use the MCP server adapter."
		) from _IMPORT_ERROR

	def main() -> int:
		raise MCPServerDependencyError(
			"Install the optional MCP dependencies with `pip install -e .[mcp]` to use the MCP server adapter."
		) from _IMPORT_ERROR

else:
	def create_mcp_server() -> FastMCP:
		server = FastMCP(
			SERVER_NAME,
			instructions=SERVER_INSTRUCTIONS,
			dependencies=["checkmarx-dscan"],
		)

		@server.tool(
			name=CHECKMARX_SCAN_TOOL_NAME,
			description=CHECKMARX_SCAN_TOOL_DESCRIPTION,
			structured_output=True,
		)
		def checkmarx_scan(
			project: str,
			source: str = "",
			env_file: str = ".env",
			scan_mode: str = "auto",
			branch: str = "",
			scan_types: str = "",
			timeout: int | None = None,
			poll_interval: int | None = None,
			poll_timeout: int | None = None,
			results_page_size: int | None = None,
			include_raw: bool = True,
			keep_archive: bool = False,
			output_json: str | None = None,
			base_url: str = "",
			api_token: str = "",
			auth_url: str = "",
			tenant: str = "",
			prefer_terminal_scan: bool = True,
			scan_lookback: int | None = None,
		) -> dict[str, Any]:
			try:
				return execute_checkmarx_scan_tool(
					project=project,
					source=source,
					env_file=env_file,
					scan_mode=scan_mode,
					branch=branch,
					scan_types=scan_types,
					timeout=timeout,
					poll_interval=poll_interval,
					poll_timeout=poll_timeout,
					results_page_size=results_page_size,
					include_raw=include_raw,
					keep_archive=keep_archive,
					output_json=output_json,
					base_url=base_url,
					api_token=api_token,
					auth_url=auth_url,
					tenant=tenant,
					prefer_terminal_scan=prefer_terminal_scan,
					scan_lookback=scan_lookback,
				)
			except CheckmarxError as exc:
				return _build_tool_error_response(
					CHECKMARX_SCAN_TOOL_NAME,
					exc,
					project=project,
					scan_mode=scan_mode,
					env_file=env_file,
				)

		@server.tool(
			name=JENKINS_ARTIFACT_TOOL_NAME,
			description=JENKINS_ARTIFACT_TOOL_DESCRIPTION,
			structured_output=True,
		)
		def jenkins_artifact(
			job_url: str,
			env_file: str = ".env",
			build_number: int | None = None,
			artifact_name: str = "",
			timeout: int | None = None,
			poll_interval: int | None = None,
			poll_timeout: int | None = None,
			fallback_build_lookback: int | None = None,
			include_raw: bool = True,
			output_json: str | None = None,
			base_url: str = "",
			username: str = "",
			api_token: str = "",
			checkmarx_base_url: str = "",
			checkmarx_api_token: str = "",
			checkmarx_auth_url: str = "",
			checkmarx_tenant: str = "",
			prefer_running_build: bool = True,
		) -> dict[str, Any]:
			try:
				return execute_jenkins_artifact_tool(
					job_url=job_url,
					env_file=env_file,
					build_number=build_number,
					artifact_name=artifact_name,
					timeout=timeout,
					poll_interval=poll_interval,
					poll_timeout=poll_timeout,
					fallback_build_lookback=fallback_build_lookback,
					include_raw=include_raw,
					output_json=output_json,
					base_url=base_url,
					username=username,
					api_token=api_token,
					checkmarx_base_url=checkmarx_base_url,
					checkmarx_api_token=checkmarx_api_token,
					checkmarx_auth_url=checkmarx_auth_url,
					checkmarx_tenant=checkmarx_tenant,
					prefer_running_build=prefer_running_build,
				)
			except CheckmarxError as exc:
				return _build_tool_error_response(
					JENKINS_ARTIFACT_TOOL_NAME,
					exc,
					job_url=job_url,
					env_file=env_file,
				)

		return server


	def main() -> int:
		create_mcp_server().run(transport="stdio")
		return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except MCPServerDependencyError as exc:
		print(f"Error: {exc}", file=sys.stderr)
		raise SystemExit(1)
	except KeyboardInterrupt:
		print("Error: interrupted", file=sys.stderr)
		raise SystemExit(130)