from __future__ import annotations

import argparse
import sys

from ...application.config.resolvers import load_env_file, resolve_credentials, resolve_jenkins_artifact_request, resolve_jenkins_credentials
from ...application.services.jenkins_artifact import JenkinsArtifactService, render_jenkins_artifact_console_report
from ...domain.errors import CheckmarxError, JenkinsError
from ...infrastructure.serialization.json import write_output_json
from ...shared.utils import first_non_empty


def parse_args(argv: list[str]) -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Retrieve an archived Checkmarx JSON report from a Jenkins pipeline build.",
	)
	parser.add_argument("job_url_positional", nargs="?", help="Full Jenkins job URL")
	parser.add_argument("--job-url", help="Full Jenkins job URL override")
	parser.add_argument("--env-file", default=".env", help="Path to the .env file to load before reading settings")
	parser.add_argument("--build-number", type=int, help="Specific Jenkins build number to inspect")
	parser.add_argument("--artifact-name", help="Exact archived file name to retrieve")
	parser.add_argument("--timeout", type=int, help="Per-request timeout in seconds")
	parser.add_argument("--poll-interval", type=int, help="Seconds between Jenkins build checks")
	parser.add_argument("--poll-timeout", type=int, help="Maximum wait time in seconds; 0 disables the timeout")
	parser.add_argument("--report-profile", choices=["compact", "full"], default="compact", help="compact removes duplicated report sections while keeping full vulnerability details")
	parser.add_argument("--fallback-build-lookback", type=int, help="How many prior build numbers to search when the newest build did not archive the Checkmarx artifact")
	parser.add_argument("--output-json", help="Optional file path for the retrieved Jenkins artifact bundle")
	parser.add_argument("--omit-raw", action="store_true", help="Omit raw Jenkins API payloads from the exported JSON")
	parser.add_argument("--base-url", help="Override JENKINS_BASE_URL or JENKINS_URL")
	parser.add_argument("--username", help="Override JENKINS_USERNAME or JENKINS_USER")
	parser.add_argument("--api-token", help="Override JENKINS_API_TOKEN")
	parser.add_argument("--checkmarx-base-url", help="Override CHECKMARX_BASE_URL for findings enrichment")
	parser.add_argument("--checkmarx-api-token", help="Override CHECKMARX_API_TOKEN for findings enrichment")
	parser.add_argument("--checkmarx-auth-url", help="Override CHECKMARX_AUTH_URL for findings enrichment")
	parser.add_argument("--checkmarx-tenant", help="Override CHECKMARX_TENANT for findings enrichment")
	parser.add_argument("--latest-completed-only", action="store_true", help="Skip the currently running build and use the latest completed build instead")
	return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
	args = parse_args(list(sys.argv[1:] if argv is None else argv))
	load_env_file(args.env_file)
	job_url = first_non_empty(args.job_url, args.job_url_positional)
	credentials = resolve_jenkins_credentials(
		base_url=args.base_url or "",
		username=args.username or "",
		api_token=args.api_token or "",
		timeout=args.timeout,
	)
	checkmarx_credentials = None
	try:
		checkmarx_credentials = resolve_credentials(
			base_url=args.checkmarx_base_url or "",
			api_token=args.checkmarx_api_token or "",
			auth_url=args.checkmarx_auth_url or "",
			tenant=args.checkmarx_tenant or "",
			timeout=args.timeout,
		)
	except CheckmarxError:
		checkmarx_credentials = None
	request = resolve_jenkins_artifact_request(
		job_url=job_url,
		build_number=args.build_number,
		artifact_name=args.artifact_name or "",
		poll_interval=args.poll_interval,
		poll_timeout=args.poll_timeout,
		fallback_build_lookback=args.fallback_build_lookback,
		include_raw=not args.omit_raw,
		prefer_running_build=not args.latest_completed_only,
		credentials=credentials,
	)
	report = JenkinsArtifactService(credentials, checkmarx_credentials=checkmarx_credentials).execute(request, progress_callback=print)
	print(render_jenkins_artifact_console_report(report))

	if args.output_json:
		output_path = write_output_json(
			args.output_json,
			report.to_dict(include_raw=not args.omit_raw, profile=args.report_profile),
			default_file_name="jenkins_artifact_report.json",
		)
		print(f"Wrote JSON output: {output_path}")

	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except (CheckmarxError, JenkinsError) as exc:
		print(f"Error: {exc}", file=sys.stderr)
		raise SystemExit(1)
	except KeyboardInterrupt:
		print("Error: interrupted", file=sys.stderr)
		raise SystemExit(130)
