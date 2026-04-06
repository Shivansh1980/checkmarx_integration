from __future__ import annotations

import time
from pathlib import PurePosixPath
from typing import Any, Callable

from ...domain.errors import CheckmarxError, JenkinsError
from ...domain.models import (
	CheckmarxCredentials,
	JenkinsArtifactExecutionReport,
	JenkinsArtifactInfo,
	JenkinsArtifactRequest,
	JenkinsArtifactSummary,
	JenkinsBuildInfo,
	JenkinsCredentials,
)
from ...shared.utils import compact_dict, pick, pick_str, to_int, utc_now_iso
from ..reporting.report_builder import build_agent_report_from_jenkins_artifact, build_normalized_scan_results_view
from ...infrastructure.clients.checkmarx import CheckmarxClient
from ...infrastructure.clients.jenkins import JenkinsClient


ProgressCallback = Callable[[str], None]


def select_build_reference(
	job_payload: dict[str, Any],
	last_build_payload: dict[str, Any] | None = None,
) -> tuple[int | None, str]:
	if isinstance(last_build_payload, dict) and bool(pick(last_build_payload, "building", default=False)):
		running_number = to_int(pick(last_build_payload, "number"), default=None)
		if running_number is not None:
			return running_number, "lastBuild"

	last_completed = pick(job_payload, "lastCompletedBuild", default={})
	last_completed_number = to_int(pick(last_completed, "number"), default=None)
	if last_completed_number is not None:
		return last_completed_number, "lastCompletedBuild"

	last_build = pick(job_payload, "lastBuild", default={})
	last_build_number = to_int(pick(last_build, "number"), default=None)
	if last_build_number is not None:
		return last_build_number, "lastBuild"

	return None, ""


def select_build_payload(
	last_build_payload: dict[str, Any] | None,
	last_completed_build_payload: dict[str, Any] | None,
	*,
	prefer_running_build: bool,
) -> tuple[dict[str, Any] | None, str]:
	if prefer_running_build and isinstance(last_build_payload, dict) and bool(pick(last_build_payload, "building", default=False)):
		return last_build_payload, "lastBuild"
	if isinstance(last_completed_build_payload, dict) and to_int(pick(last_completed_build_payload, "number"), default=None) is not None:
		return last_completed_build_payload, "lastCompletedBuild"
	if isinstance(last_build_payload, dict) and to_int(pick(last_build_payload, "number"), default=None) is not None:
		return last_build_payload, "lastBuild"
	return None, ""


def find_artifact_by_name(artifacts: Any, artifact_name: str) -> dict[str, Any] | None:
	if not isinstance(artifacts, list):
		return None

	target = artifact_name.strip().casefold()
	if not target:
		return None

	for artifact in artifacts:
		if not isinstance(artifact, dict):
			continue
		candidates = [
			pick_str(artifact, "fileName", "filename"),
			pick_str(artifact, "displayPath", "displaypath"),
		]
		relative_path = pick_str(artifact, "relativePath", "relativepath")
		if relative_path:
			candidates.append(PurePosixPath(relative_path).name)
		if any(candidate.casefold() == target for candidate in candidates if candidate):
			return artifact
	return None


def locate_artifact_in_build(build_payload: dict[str, Any] | None, artifact_name: str) -> dict[str, Any] | None:
	if not isinstance(build_payload, dict):
		return None
	artifacts = pick(build_payload, "artifacts", default=[])
	return find_artifact_by_name(artifacts, artifact_name)


def _infer_report_kind(report_payload: Any) -> str:
	if isinstance(report_payload, dict):
		return "json_object"
	if isinstance(report_payload, list):
		return "json_array"
	return "json_value"


def _extract_report_total_findings(report_payload: Any) -> int | None:
	if isinstance(report_payload, dict):
		total_issues = to_int(pick(report_payload, "TotalIssues", "TotalFindings", "totalCount"), default=None)
		if total_issues is not None:
			return total_issues
		summary = pick(report_payload, "summary", default={})
		if isinstance(summary, dict):
			total_findings = to_int(pick(summary, "total_findings", "totalFindings"), default=None)
			if total_findings is not None:
				return total_findings
		findings = pick(report_payload, "findings", default=[])
		if isinstance(findings, list):
			return len(findings)
		raw = pick(report_payload, "raw", default={})
		if isinstance(raw, dict):
			raw_results = pick(raw, "results", default={})
			if isinstance(raw_results, dict):
				total_count = to_int(pick(raw_results, "totalCount", "total_count"), default=None)
				if total_count is not None:
					return total_count
		total_count = to_int(pick(report_payload, "totalCount", "total_count"), default=None)
		if total_count is not None:
			return total_count
	elif isinstance(report_payload, list):
		return len(report_payload)
	return None


def build_jenkins_artifact_execution_report(
	*,
	request: JenkinsArtifactRequest,
	job_payload: dict[str, Any],
	build_payload: dict[str, Any],
	artifact_payload: dict[str, Any],
	report_payload: Any,
	artifact_download_url: str,
	selected_from: str,
	include_raw: bool,
	agent_report: dict[str, Any] | None = None,
) -> JenkinsArtifactExecutionReport:
	build_number = to_int(pick(build_payload, "number"), default=0) or 0
	artifact_info = JenkinsArtifactInfo(
		file_name=pick_str(artifact_payload, "fileName", "filename") or request.artifact_name,
		relative_path=pick_str(artifact_payload, "relativePath", "relativepath"),
		display_path=pick_str(artifact_payload, "displayPath", "displaypath") or pick_str(artifact_payload, "relativePath", "relativepath"),
		download_url=artifact_download_url,
	)
	build_info = JenkinsBuildInfo(
		number=build_number,
		url=pick_str(build_payload, "url"),
		result=pick_str(build_payload, "result") or "UNKNOWN",
		building=bool(pick(build_payload, "building", default=False)),
		display_name=pick_str(build_payload, "displayName"),
		full_display_name=pick_str(build_payload, "fullDisplayName"),
		description=pick_str(build_payload, "description"),
		timestamp=to_int(pick(build_payload, "timestamp"), default=None),
		duration_ms=to_int(pick(build_payload, "duration"), default=None),
		artifact_count=len(pick(build_payload, "artifacts", default=[])) if isinstance(pick(build_payload, "artifacts", default=[]), list) else 0,
		selected_from=selected_from,
	)
	summary = JenkinsArtifactSummary(
		build_selected_from=selected_from,
		build_result=build_info.result,
		building=build_info.building,
		artifact_found=True,
		artifact_name=artifact_info.file_name,
		report_kind=_infer_report_kind(report_payload),
		report_total_findings=_extract_report_total_findings(report_payload),
		detail_source=pick_str(agent_report, "detail_source") or "artifact_summary_only",
		detailed_findings_available=bool(pick(agent_report, "detailed_findings_available", default=False)),
		detailed_findings_count=(
			len(pick(agent_report, "vulnerabilities", default=[]))
			if isinstance(pick(agent_report, "vulnerabilities", default=[]), list)
			else None
		),
	)
	job_info = compact_dict(
		{
			"url": pick_str(job_payload, "url") or request.job_url,
			"name": pick_str(job_payload, "name"),
			"full_name": pick_str(job_payload, "fullName"),
			"display_name": pick_str(job_payload, "displayName"),
			"in_queue": bool(pick(job_payload, "inQueue", default=False)),
		}
	)
	raw = None
	if include_raw:
		raw = {
			"job": job_payload,
			"build": build_payload,
			"artifact": artifact_payload,
		}
	return JenkinsArtifactExecutionReport(
		generated_at=utc_now_iso(),
		request=request.to_dict(),
		job=job_info,
		build=build_info,
		artifact=artifact_info,
		summary=summary,
		report=report_payload,
		agent_report=agent_report,
		raw=raw,
	)


def render_jenkins_artifact_console_report(report: JenkinsArtifactExecutionReport) -> str:
	report_total = report.summary.report_total_findings
	report_total_text = str(report_total) if report_total is not None else "unknown"
	detailed_count = report.summary.detailed_findings_count
	detailed_count_text = str(detailed_count) if detailed_count is not None else "unavailable"
	lines = [
		f"Jenkins job: {report.job.get('full_name') or report.job.get('name') or report.job.get('url', 'n/a')}",
		f"Build: {report.build.number} [{report.build.result or 'UNKNOWN'}] via {report.build.selected_from or 'unknown'}",
		f"Artifact: {report.artifact.file_name}",
		f"Artifact path: {report.artifact.relative_path}",
		f"Report findings: {report_total_text}",
		f"Detail source: {report.summary.detail_source}",
		f"Detailed vulnerabilities: {detailed_count_text}",
	]
	top_actionable_issues = pick(report.agent_report or {}, "top_actionable_issues", default=[])
	enrichment_error = pick_str(report.agent_report or {}, "enrichment_error")
	if enrichment_error:
		lines.append(f"Enrichment warning: {enrichment_error}")
	if isinstance(top_actionable_issues, list) and top_actionable_issues:
		lines.append("")
		lines.append(f"Top actionable issues: {min(5, len(top_actionable_issues))}")
		for issue in top_actionable_issues[:5]:
			if not isinstance(issue, dict):
				continue
			line = (
				f"- [{pick_str(issue, 'severity').upper() or 'UNKNOWN'}] "
				f"[{pick_str(issue, 'type') or 'unknown'}] "
				f"{pick_str(issue, 'title') or 'Unnamed issue'}"
			)
			location = pick_str(issue, "location")
			if location:
				line = f"{line} @ {location}"
			count = to_int(pick(issue, "vulnerability_count"), default=0) or 0
			if count > 1:
				line = f"{line} | vulnerabilities={count}"
			recommended_version = pick_str(issue, "recommended_version")
			if recommended_version:
				line = f"{line} | recommended={recommended_version}"
			lines.append(line)
	return "\n".join(lines)


class JenkinsArtifactService:
	def __init__(self, credentials: JenkinsCredentials, checkmarx_credentials: CheckmarxCredentials | None = None) -> None:
		self.credentials = credentials
		self.client = JenkinsClient(
			base_url=credentials.base_url,
			username=credentials.username,
			api_token=credentials.api_token,
			timeout=credentials.timeout,
		)
		self.checkmarx_client = None
		if checkmarx_credentials is not None:
			self.checkmarx_client = CheckmarxClient(
				base_url=checkmarx_credentials.base_url,
				api_token=checkmarx_credentials.api_token,
				auth_url=checkmarx_credentials.auth_url,
				tenant=checkmarx_credentials.tenant,
				timeout=checkmarx_credentials.timeout,
			)

	def _build_job_info(self, request: JenkinsArtifactRequest) -> dict[str, Any]:
		return {"url": request.job_url}

	def _find_recent_artifact_build(
		self,
		request: JenkinsArtifactRequest,
		*,
		start_build_number: int,
		progress_callback: ProgressCallback | None = None,
	) -> tuple[dict[str, Any], dict[str, Any], str] | None:
		lookback = max(0, request.fallback_build_lookback)
		if lookback <= 0:
			return None

		for candidate_number in range(start_build_number - 1, max(0, start_build_number - lookback) - 1, -1):
			if candidate_number <= 0:
				break
			candidate_build = self.client.get_build(request.job_url, candidate_number, not_found_is_none=True)
			if not isinstance(candidate_build, dict):
				continue
			artifact_payload = locate_artifact_in_build(candidate_build, request.artifact_name)
			if artifact_payload is None:
				continue
			if progress_callback is not None:
				progress_callback(
					f"Build {start_build_number} did not archive {request.artifact_name}; using Jenkins build {candidate_number} instead."
				)
			return candidate_build, artifact_payload, "artifactFallback"
		return None

	def _enrich_checkmarx_results(
		self,
		report_payload: Any,
		*,
		progress_callback: ProgressCallback | None = None,
	) -> tuple[dict[str, Any] | None, str]:
		if self.checkmarx_client is None or not isinstance(report_payload, dict):
			return None, ""

		scan_id = pick_str(report_payload, "ScanID", "scanId")
		if not scan_id:
			return None, ""

		try:
			if progress_callback is not None:
				progress_callback(f"Enriching Jenkins artifact with Checkmarx scan results for scan {scan_id}.")
			self.checkmarx_client.authenticate()
			final_scan = self.checkmarx_client.get_scan(scan_id)
			results_payload = self.checkmarx_client.get_all_results(scan_id)
			return build_normalized_scan_results_view(final_scan, results_payload, include_raw=False), ""
		except CheckmarxError as exc:
			return None, str(exc)

	def execute(
		self,
		request: JenkinsArtifactRequest,
		*,
		progress_callback: ProgressCallback | None = None,
	) -> JenkinsArtifactExecutionReport:
		deadline = time.time() + request.poll_timeout if request.poll_timeout > 0 else None
		last_status_message = ""
		job_payload: dict[str, Any] = self._build_job_info(request)

		while True:
			selected_from = "explicit"
			selected_build_number = request.build_number
			cached_last_build_payload: dict[str, Any] | None = None

			if selected_build_number is None:
				last_build_payload = self.client.get_build_reference(request.job_url, "lastBuild")
				last_completed_build_payload = self.client.get_build_reference(request.job_url, "lastCompletedBuild")
				selected_build_payload, selected_from = select_build_payload(
					last_build_payload,
					last_completed_build_payload,
					prefer_running_build=request.prefer_running_build,
				)
				if selected_build_payload is None:
					if deadline is not None and time.time() >= deadline:
						raise JenkinsError(f"Timed out waiting for a Jenkins build for {request.job_url}")
					message = "Waiting for Jenkins to expose a build for the job."
					if progress_callback is not None and message != last_status_message:
						progress_callback(message)
						last_status_message = message
					time.sleep(max(1, request.poll_interval))
					continue
				selected_build_number = to_int(pick(selected_build_payload, "number"), default=None)
				cached_last_build_payload = selected_build_payload if selected_from == "lastBuild" else None

			if cached_last_build_payload is not None and to_int(pick(cached_last_build_payload, "number"), default=None) == selected_build_number:
				build_payload = cached_last_build_payload
			else:
				build_payload = self.client.get_build(request.job_url, int(selected_build_number))

			artifact_payload = locate_artifact_in_build(build_payload, request.artifact_name)
			if artifact_payload is not None:
				artifact_relative_path = pick_str(artifact_payload, "relativePath", "relativepath")
				artifact_download_url = self.client.build_artifact_download_url(
					build_payload,
					artifact_relative_path,
					request.job_url,
					int(selected_build_number),
				)
				if progress_callback is not None:
					progress_callback(
						f"Found artifact {request.artifact_name} in Jenkins build {selected_build_number}; downloading report."
					)
				report_payload = self.client.download_artifact_json(artifact_download_url)
				detailed_view, enrichment_error = self._enrich_checkmarx_results(
					report_payload,
					progress_callback=progress_callback,
				)
				agent_report = build_agent_report_from_jenkins_artifact(
					report_payload,
					detailed_view=detailed_view,
					enrichment_error=enrichment_error,
				)
				return build_jenkins_artifact_execution_report(
					request=request,
					job_payload=job_payload,
					build_payload=build_payload,
					artifact_payload=artifact_payload,
					report_payload=report_payload,
					artifact_download_url=artifact_download_url,
					selected_from=selected_from,
					include_raw=request.include_raw,
					agent_report=agent_report,
				)

			building = bool(pick(build_payload, "building", default=False))
			build_result = pick_str(build_payload, "result") or "UNKNOWN"
			if not building:
				if request.build_number is None:
					fallback_match = self._find_recent_artifact_build(
						request,
						start_build_number=int(selected_build_number),
						progress_callback=progress_callback,
					)
					if fallback_match is not None:
						build_payload, artifact_payload, fallback_source = fallback_match
						artifact_relative_path = pick_str(artifact_payload, "relativePath", "relativepath")
						artifact_download_url = self.client.build_artifact_download_url(
							build_payload,
							artifact_relative_path,
							request.job_url,
							int(to_int(pick(build_payload, "number"), default=0) or 0),
						)
						report_payload = self.client.download_artifact_json(artifact_download_url)
						detailed_view, enrichment_error = self._enrich_checkmarx_results(
							report_payload,
							progress_callback=progress_callback,
						)
						agent_report = build_agent_report_from_jenkins_artifact(
							report_payload,
							detailed_view=detailed_view,
							enrichment_error=enrichment_error,
						)
						return build_jenkins_artifact_execution_report(
							request=request,
							job_payload=job_payload,
							build_payload=build_payload,
							artifact_payload=artifact_payload,
							report_payload=report_payload,
							artifact_download_url=artifact_download_url,
							selected_from=f"{selected_from}-{fallback_source}",
							include_raw=request.include_raw,
							agent_report=agent_report,
						)
				raise JenkinsError(
					f"Artifact {request.artifact_name} was not archived in Jenkins build {selected_build_number} "
					f"(result={build_result})."
				)

			if deadline is not None and time.time() >= deadline:
				raise JenkinsError(
					f"Timed out waiting for artifact {request.artifact_name} in Jenkins build {selected_build_number}"
				)

			message = (
				f"Tracking Jenkins build {selected_build_number} from {selected_from}; "
				f"waiting for artifact {request.artifact_name}."
			)
			if progress_callback is not None and message != last_status_message:
				progress_callback(message)
				last_status_message = message
			time.sleep(max(1, request.poll_interval))


def run_jenkins_artifact_retrieval(
	credentials: JenkinsCredentials,
	request: JenkinsArtifactRequest,
	*,
	progress_callback: ProgressCallback | None = None,
) -> JenkinsArtifactExecutionReport:
	return JenkinsArtifactService(credentials).execute(request, progress_callback=progress_callback)
