from __future__ import annotations

from typing import Callable

from ...domain.errors import CheckmarxError
from ...domain.models import CheckmarxCredentials, ProjectScanExecutionReport, ProjectScanRequest
from ...shared.utils import pick, pick_str, utc_now_iso
from ..reporting.report_builder import build_project_scan_execution_report, extract_scan_status, format_status_details
from ...infrastructure.clients.checkmarx import CheckmarxClient


ProgressCallback = Callable[[str], None]


class ProjectScanService:
    def __init__(self, credentials: CheckmarxCredentials) -> None:
        self.credentials = credentials
        self.client = CheckmarxClient(
            base_url=credentials.base_url,
            api_token=credentials.api_token,
            auth_url=credentials.auth_url,
            tenant=credentials.tenant,
            timeout=credentials.timeout,
        )

    def execute(
        self,
        request: ProjectScanRequest,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> ProjectScanExecutionReport:
        self.client.authenticate()
        project = self.client.get_project_by_name(request.project_name)
        if project is None:
            raise CheckmarxError(f"Checkmarx project was not found: {request.project_name}")

        project_id = pick_str(project, "id", "ID")
        if not project_id:
            raise CheckmarxError("Checkmarx did not return a project ID")
        if progress_callback is not None:
            progress_callback(f"Using project: {pick_str(project, 'name', 'Name') or request.project_name} ({project_id})")

        latest_scan = self.client.get_latest_project_scan(
            project_id,
            branch=request.branch,
            prefer_terminal_scan=request.prefer_terminal_scan,
            lookback=request.scan_lookback,
        )
        scan_id = pick_str(latest_scan, "id", "ID")
        if not scan_id:
            raise CheckmarxError("Checkmarx did not return a scan ID for the latest project scan")
        if progress_callback is not None:
            branch_text = pick_str(latest_scan, "branch", "Branch") or request.branch or "unknown"
            progress_callback(f"Selected scan: {scan_id} on branch {branch_text}")

        final_scan = self.client.get_scan(scan_id)
        final_status = extract_scan_status(final_scan)
        if progress_callback is not None:
            progress_callback(f"Latest scan status: {final_status}")

        if final_status not in {"Completed", "Partial"}:
            details = format_status_details(pick(final_scan, "statusDetails", "StatusDetails", default=[]))
            suffix = f" | {details}" if details else ""
            raise CheckmarxError(f"Latest scan {scan_id} ended with status {final_status}{suffix}")

        results_payload = self.client.get_all_results(scan_id, page_size=request.results_page_size)
        report = build_project_scan_execution_report(
            request=request,
            project=project,
            final_scan=final_scan,
            results_payload=results_payload,
            include_raw=request.include_raw,
            generated_at=utc_now_iso(),
        )
        if progress_callback is not None:
            progress_callback(f"Retrieved {report.summary.total_findings} findings from the latest project scan.")
        return report


def run_project_scan(
    credentials: CheckmarxCredentials,
    request: ProjectScanRequest,
    *,
    progress_callback: ProgressCallback | None = None,
) -> ProjectScanExecutionReport:
    return ProjectScanService(credentials).execute(request, progress_callback=progress_callback)
