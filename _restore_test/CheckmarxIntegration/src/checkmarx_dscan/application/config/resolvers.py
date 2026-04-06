from __future__ import annotations

import os
from pathlib import Path
from urllib import parse as urlparse

from ...domain.constants import (
    DEFAULT_JENKINS_ARTIFACT_NAME,
    DEFAULT_JENKINS_FALLBACK_BUILDS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_POLL_TIMEOUT,
    DEFAULT_RESULTS_PAGE_SIZE,
    DEFAULT_TIMEOUT,
)
from ...domain.errors import CheckmarxError, JenkinsError, SonarError
from ...domain.models import CheckmarxCredentials, JenkinsArtifactRequest, JenkinsCredentials, ProjectScanRequest, ScanRequest, SonarCredentials
from ...shared.utils import first_non_empty, join_url, load_env_file, normalize_scan_types, to_int


def resolve_credentials(
    *,
    base_url: str = "",
    api_token: str = "",
    auth_url: str = "",
    tenant: str = "",
    timeout: int | None = None,
) -> CheckmarxCredentials:
    resolved_base_url = first_non_empty(base_url, os.getenv("CHECKMARX_BASE_URL"), os.getenv("CX_BASE_URI"))
    resolved_api_token = first_non_empty(api_token, os.getenv("CHECKMARX_API_TOKEN"), os.getenv("CX_APIKEY"))
    resolved_auth_url = first_non_empty(
        auth_url,
        os.getenv("CHECKMARX_AUTH_URL"),
        os.getenv("CHECKMARX_BASE_AUTH_URL"),
        os.getenv("CX_BASE_AUTH_URI"),
    )
    resolved_tenant = first_non_empty(tenant, os.getenv("CHECKMARX_TENANT"), os.getenv("CX_TENANT"))
    resolved_timeout = timeout if timeout is not None else to_int(os.getenv("CHECKMARX_TIMEOUT"), default=DEFAULT_TIMEOUT)

    if not resolved_api_token:
        raise CheckmarxError("Missing Checkmarx API token. Set CHECKMARX_API_TOKEN in .env or pass --api-token.")

    return CheckmarxCredentials(
        base_url=resolved_base_url,
        api_token=resolved_api_token,
        auth_url=resolved_auth_url,
        tenant=resolved_tenant,
        timeout=max(1, int(resolved_timeout or DEFAULT_TIMEOUT)),
    )


def resolve_scan_request(
    *,
    project_name: str,
    source: str,
    branch: str = "",
    scan_types: str | list[str] | tuple[str, ...] = "",
    poll_interval: int | None = None,
    poll_timeout: int | None = None,
    results_page_size: int | None = None,
    include_raw: bool = True,
    keep_archive: bool = False,
) -> ScanRequest:
    if not project_name or not project_name.strip():
        raise CheckmarxError("A Checkmarx project name is required.")

    source_path = Path(source).expanduser()
    if not source_path.exists():
        raise CheckmarxError(f"Source path does not exist: {source_path}")

    resolved_branch = first_non_empty(branch, os.getenv("CHECKMARX_BRANCH"), os.getenv("CX_BRANCH"), "main")
    raw_scan_types: str | list[str] | tuple[str, ...]
    if isinstance(scan_types, (list, tuple)):
        raw_scan_types = scan_types
    else:
        raw_scan_types = first_non_empty(scan_types, os.getenv("CHECKMARX_SCAN_TYPES"), "sast,sca,iac-security")

    resolved_poll_interval = (
        poll_interval if poll_interval is not None else to_int(os.getenv("CHECKMARX_POLL_INTERVAL"), default=DEFAULT_POLL_INTERVAL)
    )
    resolved_poll_timeout = (
        poll_timeout if poll_timeout is not None else to_int(os.getenv("CHECKMARX_POLL_TIMEOUT"), default=DEFAULT_POLL_TIMEOUT)
    )
    resolved_results_page_size = (
        results_page_size
        if results_page_size is not None
        else to_int(os.getenv("CHECKMARX_RESULTS_PAGE_SIZE"), default=DEFAULT_RESULTS_PAGE_SIZE)
    )

    return ScanRequest(
        project_name=project_name.strip(),
        source_path=source_path,
        branch=resolved_branch,
        scan_types=normalize_scan_types(raw_scan_types),
        poll_interval=max(1, int(resolved_poll_interval or DEFAULT_POLL_INTERVAL)),
        poll_timeout=max(0, int(resolved_poll_timeout or DEFAULT_POLL_TIMEOUT)),
        results_page_size=max(1, int(resolved_results_page_size or DEFAULT_RESULTS_PAGE_SIZE)),
        include_raw=include_raw,
        keep_archive=keep_archive,
    )


def resolve_project_scan_request(
    *,
    project_name: str,
    branch: str = "",
    results_page_size: int | None = None,
    include_raw: bool = True,
    prefer_terminal_scan: bool = True,
    scan_lookback: int | None = None,
) -> ProjectScanRequest:
    if not project_name or not project_name.strip():
        raise CheckmarxError("A Checkmarx project name is required.")

    resolved_results_page_size = (
        results_page_size
        if results_page_size is not None
        else to_int(os.getenv("CHECKMARX_RESULTS_PAGE_SIZE"), default=DEFAULT_RESULTS_PAGE_SIZE)
    )
    resolved_scan_lookback = (
        scan_lookback if scan_lookback is not None else to_int(os.getenv("CHECKMARX_SCAN_LOOKBACK"), default=100)
    )

    return ProjectScanRequest(
        project_name=project_name.strip(),
        branch=branch.strip(),
        results_page_size=max(1, int(resolved_results_page_size or DEFAULT_RESULTS_PAGE_SIZE)),
        include_raw=include_raw,
        prefer_terminal_scan=prefer_terminal_scan,
        scan_lookback=max(1, int(resolved_scan_lookback or 100)),
    )


def resolve_jenkins_credentials(
    *,
    base_url: str = "",
    username: str = "",
    api_token: str = "",
    timeout: int | None = None,
) -> JenkinsCredentials:
    resolved_base_url = first_non_empty(base_url, os.getenv("JENKINS_BASE_URL"), os.getenv("JENKINS_URL"))
    resolved_username = first_non_empty(username, os.getenv("JENKINS_USERNAME"), os.getenv("JENKINS_USER"))
    resolved_api_token = first_non_empty(api_token, os.getenv("JENKINS_API_TOKEN"))
    resolved_timeout = timeout if timeout is not None else to_int(os.getenv("JENKINS_TIMEOUT"), default=DEFAULT_TIMEOUT)

    if resolved_api_token and not resolved_username:
        raise JenkinsError("Missing Jenkins username. Set JENKINS_USERNAME in .env or pass --username.")
    if resolved_username and not resolved_api_token:
        raise JenkinsError("Missing Jenkins API token. Set JENKINS_API_TOKEN in .env or pass --api-token.")

    return JenkinsCredentials(
        base_url=resolved_base_url.rstrip("/") if resolved_base_url else "",
        username=resolved_username,
        api_token=resolved_api_token,
        timeout=max(1, int(resolved_timeout or DEFAULT_TIMEOUT)),
    )


def resolve_sonar_credentials(
    *,
    base_url: str = "",
    token: str = "",
    timeout: int | None = None,
    require_base_url: bool = True,
) -> SonarCredentials:
    resolved_base_url = first_non_empty(base_url, os.getenv("SONAR_BASE_URL"), os.getenv("SONAR_HOST_URL"))
    resolved_token = first_non_empty(token, os.getenv("SONAR_TOKEN"), os.getenv("SONAR_API_TOKEN"))
    resolved_timeout = timeout if timeout is not None else to_int(os.getenv("SONAR_TIMEOUT"), default=DEFAULT_TIMEOUT)

    if require_base_url and not resolved_base_url:
        raise SonarError("Missing Sonar base URL. Set SONAR_BASE_URL in .env or pass base_url.")

    return SonarCredentials(
        base_url=resolved_base_url.rstrip("/"),
        token=resolved_token,
        timeout=max(1, int(resolved_timeout or DEFAULT_TIMEOUT)),
    )


def _resolve_absolute_jenkins_job_url(job_url: str, credentials: JenkinsCredentials | None = None) -> str:
    cleaned = job_url.strip()
    if not cleaned:
        return ""
    parsed = urlparse.urlsplit(cleaned)
    if parsed.scheme and parsed.netloc:
        return cleaned.rstrip("/")

    base_url = ""
    if credentials is not None:
        base_url = credentials.base_url
    if not base_url:
        base_url = first_non_empty(os.getenv("JENKINS_BASE_URL"), os.getenv("JENKINS_URL"))
    if not base_url:
        raise JenkinsError("Jenkins job URL must be absolute or JENKINS_BASE_URL must be configured.")
    return join_url(base_url, cleaned).rstrip("/")


def resolve_jenkins_artifact_request(
    *,
    job_url: str = "",
    build_number: int | str | None = None,
    artifact_name: str = "",
    poll_interval: int | None = None,
    poll_timeout: int | None = None,
    include_raw: bool = True,
    prefer_running_build: bool = True,
    fallback_build_lookback: int | None = None,
    credentials: JenkinsCredentials | None = None,
) -> JenkinsArtifactRequest:
    resolved_job_url = first_non_empty(job_url, os.getenv("JENKINS_JOB_URL"))
    if not resolved_job_url:
        raise JenkinsError("A Jenkins job URL is required. Set JENKINS_JOB_URL in .env or pass --job-url.")

    resolved_artifact_name = first_non_empty(artifact_name, os.getenv("JENKINS_ARTIFACT_NAME"), DEFAULT_JENKINS_ARTIFACT_NAME)
    resolved_poll_interval = (
        poll_interval if poll_interval is not None else to_int(os.getenv("JENKINS_POLL_INTERVAL"), default=DEFAULT_POLL_INTERVAL)
    )
    resolved_poll_timeout = (
        poll_timeout if poll_timeout is not None else to_int(os.getenv("JENKINS_POLL_TIMEOUT"), default=DEFAULT_POLL_TIMEOUT)
    )
    resolved_fallback_build_lookback = (
        fallback_build_lookback
        if fallback_build_lookback is not None
        else to_int(os.getenv("JENKINS_FALLBACK_BUILDS"), default=DEFAULT_JENKINS_FALLBACK_BUILDS)
    )
    resolved_build_number = to_int(build_number, default=None)

    return JenkinsArtifactRequest(
        job_url=_resolve_absolute_jenkins_job_url(resolved_job_url, credentials),
        build_number=resolved_build_number,
        artifact_name=resolved_artifact_name,
        poll_interval=max(1, int(resolved_poll_interval or DEFAULT_POLL_INTERVAL)),
        poll_timeout=max(0, int(resolved_poll_timeout or DEFAULT_POLL_TIMEOUT)),
        include_raw=include_raw,
        prefer_running_build=prefer_running_build,
        fallback_build_lookback=max(0, int(resolved_fallback_build_lookback or DEFAULT_JENKINS_FALLBACK_BUILDS)),
    )


__all__ = [
    "load_env_file",
    "resolve_credentials",
    "resolve_jenkins_artifact_request",
    "resolve_jenkins_credentials",
    "resolve_project_scan_request",
    "resolve_scan_request",
	"resolve_sonar_credentials",
]