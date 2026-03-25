from __future__ import annotations

from pathlib import Path
from typing import Callable

from ...domain.errors import CheckmarxError
from ...domain.models import ArchiveInfo, CheckmarxCredentials, ScanExecutionReport, ScanRequest
from ...shared.utils import format_bytes, pick, pick_str, utc_now_iso
from ..reporting.report_builder import build_execution_report, extract_scan_status, format_status_details
from ...infrastructure.clients.checkmarx import CheckmarxClient
from ...infrastructure.packaging.archive import build_zip_archive


ProgressCallback = Callable[[str], None]


class CheckmarxScanService:
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
        request: ScanRequest,
        *,
        progress_callback: ProgressCallback | None = None,
    ) -> ScanExecutionReport:
        source_path = Path(request.source_path).expanduser()
        if not source_path.exists():
            raise CheckmarxError(f"Source path does not exist: {source_path}")

        archive_path: Path | None = None
        created_archive = False
        archive_info: ArchiveInfo | None = None
        try:
            archive_path, created_archive = build_zip_archive(source_path)
            archive_info = ArchiveInfo(
                path=str(archive_path),
                created=created_archive,
                size_bytes=archive_path.stat().st_size,
                size_human=format_bytes(archive_path.stat().st_size),
                retained=(not created_archive) or request.keep_archive,
            )
            if progress_callback is not None:
                progress_callback(f"Prepared archive: {archive_info.path} ({archive_info.size_human})")

            self.client.authenticate()
            project, was_created = self.client.ensure_project(request.project_name, request.branch)
            project_id = pick_str(project, "id", "ID")
            if not project_id:
                raise CheckmarxError("Checkmarx did not return a project ID")
            if progress_callback is not None:
                action = "Created" if was_created else "Using"
                progress_callback(f"{action} project: {pick_str(project, 'name', 'Name') or request.project_name} ({project_id})")

            upload_url = self.client.get_presigned_upload_url()
            self.client.upload_archive(upload_url, archive_path)
            if progress_callback is not None:
                progress_callback("Uploaded source archive.")

            created_scan = self.client.create_scan(project_id, request.branch, upload_url, request.scan_types)
            scan_id = pick_str(created_scan, "id", "ID")
            if not scan_id:
                raise CheckmarxError("Checkmarx did not return a scan ID")
            if progress_callback is not None:
                progress_callback(f"Created scan: {scan_id}")

            final_scan = self.client.wait_for_scan(
                scan_id,
                request.poll_interval,
                request.poll_timeout,
                on_status=progress_callback,
            )
            final_status = extract_scan_status(final_scan)
            if progress_callback is not None:
                progress_callback(f"Final scan status: {final_status}")

            if final_status not in {"Completed", "Partial"}:
                details = format_status_details(pick(final_scan, "statusDetails", "StatusDetails", default=[]))
                suffix = f" | {details}" if details else ""
                raise CheckmarxError(f"Scan {scan_id} ended with status {final_status}{suffix}")

            results_payload = self.client.get_all_results(scan_id, page_size=request.results_page_size)
            report = build_execution_report(
                request=request,
                archive=archive_info,
                project=project,
                project_created=was_created,
                created_scan=created_scan,
                final_scan=final_scan,
                results_payload=results_payload,
                include_raw=request.include_raw,
                generated_at=utc_now_iso(),
            )
            if progress_callback is not None:
                progress_callback(f"Retrieved {report.summary.total_findings} findings.")
            return report
        finally:
            if created_archive and archive_path is not None and not request.keep_archive:
                archive_path.unlink(missing_ok=True)


def run_scan(
    credentials: CheckmarxCredentials,
    request: ScanRequest,
    *,
    progress_callback: ProgressCallback | None = None,
) -> ScanExecutionReport:
    return CheckmarxScanService(credentials).execute(request, progress_callback=progress_callback)