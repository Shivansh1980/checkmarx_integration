from __future__ import annotations

import argparse
import sys

from ...application.config.resolvers import load_env_file, resolve_credentials, resolve_project_scan_request, resolve_scan_request
from ...application.reporting.report_builder import render_console_report, render_project_scan_console_report
from ...application.services.checkmarx_scan import CheckmarxScanService
from ...application.services.project_scan import ProjectScanService
from ...domain.constants import DEFAULT_RESULTS_LIMIT
from ...domain.errors import CheckmarxError
from ...infrastructure.serialization.json import write_output_json
from ...shared.utils import first_non_empty


def parse_args(argv: list[str]) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Fetch the latest existing Checkmarx scan for a project by default, or explicitly upload local source when requested.",
	)
	parser.add_argument("project_name", nargs="?", help="Checkmarx project name")
	parser.add_argument("--project", help="Checkmarx project name override")
	parser.add_argument("--env-file", default=".env", help="Path to the .env file to load before reading settings")
	parser.add_argument("--source", help="Directory, source file, or zip archive to scan. Used only with --scan-mode upload.")
	parser.add_argument("--scan-mode", choices=["auto", "upload", "latest_project"], default="auto", help="auto defaults to latest_project. Use upload only when you explicitly want to send local source to Checkmarx")
	parser.add_argument("--branch", help="Branch name associated with the scan")
	parser.add_argument("--scan-types", help="Comma-separated scan engines. Supported values: sast, sca, iac-security")
	parser.add_argument("--timeout", type=int, help="Per-request timeout in seconds")
	parser.add_argument("--poll-interval", type=int, help="Seconds between scan status checks")
	parser.add_argument("--poll-timeout", type=int, help="Maximum time to wait for scan completion in seconds; 0 disables the timeout")
	parser.add_argument("--results-page-size", type=int, help="How many findings to request per API page")
	parser.add_argument("--results-limit", type=int, default=DEFAULT_RESULTS_LIMIT, help="How many findings to print to the console summary")
	parser.add_argument("--scan-lookback", type=int, help="How many recent scans to inspect when selecting the latest existing project scan")
	parser.add_argument("--prefer-running-scan", action="store_true", help="For latest_project mode, prefer the most recent scan even if it is still running")
	parser.add_argument("--output-json", help="Optional file path for the full project/scan/results JSON bundle")
	parser.add_argument("--keep-archive", action="store_true", help="Keep the temporary zip archive created for the upload")
	parser.add_argument("--omit-raw", action="store_true", help="Omit raw Checkmarx API payloads from the exported JSON")
	parser.add_argument("--base-url", help="Override CHECKMARX_BASE_URL or CX_BASE_URI")
	parser.add_argument("--api-token", help="Override CHECKMARX_API_TOKEN or CX_APIKEY")
	parser.add_argument("--auth-url", help="Override CHECKMARX_AUTH_URL, CHECKMARX_BASE_AUTH_URL, or CX_BASE_AUTH_URI")
	parser.add_argument("--tenant", help="Tenant name used only when auth URL must be derived from a base auth URL")
	return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
	args = parse_args(list(sys.argv[1:] if argv is None else argv))
	load_env_file(args.env_file)
	project_name = first_non_empty(args.project, args.project_name)
	credentials = resolve_credentials(
		base_url=args.base_url or "",
		api_token=args.api_token or "",
		auth_url=args.auth_url or "",
		tenant=args.tenant or "",
		timeout=args.timeout,
	)
	resolved_mode = args.scan_mode
	if resolved_mode == "auto":
		resolved_mode = "latest_project"

	if resolved_mode == "upload":
		request = resolve_scan_request(
			project_name=project_name,
			source=args.source or "",
			branch=args.branch or "",
			scan_types=args.scan_types or "",
			poll_interval=args.poll_interval,
			poll_timeout=args.poll_timeout,
			results_page_size=args.results_page_size,
			include_raw=not args.omit_raw,
			keep_archive=args.keep_archive,
		)

		service = CheckmarxScanService(credentials)
		report = service.execute(request, progress_callback=print)
		payload = report.to_dict(include_raw=not args.omit_raw)
		print(render_console_report(report, args.results_limit))
	else:
		request = resolve_project_scan_request(
			project_name=project_name,
			branch=args.branch or "",
			results_page_size=args.results_page_size,
			include_raw=not args.omit_raw,
			prefer_terminal_scan=not args.prefer_running_scan,
			scan_lookback=args.scan_lookback,
		)

		service = ProjectScanService(credentials)
		report = service.execute(request, progress_callback=print)
		payload = report.to_dict(include_raw=not args.omit_raw)
		print(render_project_scan_console_report(report, args.results_limit))

	if args.output_json:
		output_path = write_output_json(
			args.output_json,
			payload,
			default_file_name="checkmarx_scan_report.json",
		)
		print(f"Wrote JSON output: {output_path}")

	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except CheckmarxError as exc:
		print(f"Error: {exc}", file=sys.stderr)
		raise SystemExit(1)
	except KeyboardInterrupt:
		print("Error: interrupted", file=sys.stderr)
		raise SystemExit(130)
