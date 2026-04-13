from __future__ import annotations

import argparse
import sys

from ...application.config.resolvers import load_env_file, resolve_credentials, resolve_data_source, resolve_project_scan_request
from ...application.reporting.report_builder import render_project_scan_console_report
from ...application.services.project_scan import ProjectScanService
from ...domain.constants import DEFAULT_RESULTS_LIMIT
from ...domain.errors import CheckmarxError
from ...interfaces.agents.common import execute_checkmarx_project_scan_tool
from ...infrastructure.serialization.json import dumps_json
from ...infrastructure.serialization.json import write_output_json
from ...shared.utils import first_non_empty


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fetch the latest existing Checkmarx One scan for a project and emit an agent-friendly JSON report.",
    )
    parser.add_argument("project_name", nargs="?", help="Checkmarx project name")
    parser.add_argument("--project", help="Checkmarx project name override")
    parser.add_argument("--env-file", default=".env", help="Path to the .env file to load before reading settings")
    parser.add_argument("--branch", help="Optional branch name associated with the latest scan lookup")
    parser.add_argument("--timeout", type=int, help="Per-request timeout in seconds")
    parser.add_argument("--results-page-size", type=int, help="How many findings to request per API page")
    parser.add_argument("--results-limit", type=int, default=DEFAULT_RESULTS_LIMIT, help="How many findings to print to the console summary")
    parser.add_argument("--report-profile", choices=["compact", "full"], default="compact", help="compact removes duplicated report sections while keeping full vulnerability details")
    parser.add_argument("--scan-lookback", type=int, help="How many recent scans to inspect when selecting the latest scan")
    parser.add_argument("--prefer-running-scan", action="store_true", help="Prefer the most recent scan even if it is still running")
    parser.add_argument("--output-json", help="Optional file path for the full project/scan/results JSON bundle")
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
    data_source = resolve_data_source()
    if data_source == "mock":
        payload = execute_checkmarx_project_scan_tool(
            project=project_name,
            env_file=args.env_file,
            branch=args.branch or "",
            timeout=args.timeout,
            results_page_size=args.results_page_size,
            include_raw=not args.omit_raw,
            output_json=args.output_json,
            base_url=args.base_url or "",
            api_token=args.api_token or "",
            auth_url=args.auth_url or "",
            tenant=args.tenant or "",
            prefer_terminal_scan=not args.prefer_running_scan,
            scan_lookback=args.scan_lookback,
        )
        print(dumps_json(payload))
        return 0
    credentials = resolve_credentials(
        base_url=args.base_url or "",
        api_token=args.api_token or "",
        auth_url=args.auth_url or "",
        tenant=args.tenant or "",
        timeout=args.timeout,
    )
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
    payload = report.to_dict(include_raw=not args.omit_raw, profile=args.report_profile)
    print(render_project_scan_console_report(report, args.results_limit))

    if args.output_json:
        output_path = write_output_json(
            args.output_json,
            payload,
            default_file_name="checkmarx_project_scan_report.json",
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
