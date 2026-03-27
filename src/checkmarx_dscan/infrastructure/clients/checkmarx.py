from __future__ import annotations

import http.client
import json
import time
from pathlib import Path
from typing import Any, Callable
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from ...domain.constants import DEFAULT_CLIENT_ID, DEFAULT_RESULTS_PAGE_SIZE, MAX_SINGLE_UPLOAD_BYTES, TERMINAL_SCAN_STATUSES, USER_AGENT
from ...domain.errors import CheckmarxError
from ...shared.utils import claim_as_string, ensure_token_endpoint, join_url, pick, pick_str, sanitize_url, to_int, with_query
from ...application.reporting.report_builder import extract_scan_status, format_status_details


class CheckmarxClient:
	def __init__(
		self,
		*,
		base_url: str,
		api_token: str,
		auth_url: str,
		tenant: str,
		timeout: int,
	) -> None:
		self.base_url = base_url.rstrip("/") if base_url else ""
		self.api_token = api_token.strip()
		self.auth_url = auth_url.strip()
		self.tenant = tenant.strip()
		self.timeout = timeout
		self._access_token = ""
		self._access_token_expires_at = 0.0

	def _decode_json(self, raw_body: bytes, source_url: str) -> dict[str, Any]:
		if not raw_body:
			return {}
		try:
			parsed = json.loads(raw_body.decode("utf-8"))
		except (UnicodeDecodeError, json.JSONDecodeError) as exc:
			raise CheckmarxError(f"Response from {sanitize_url(source_url)} was not valid JSON") from exc
		if not isinstance(parsed, dict):
			raise CheckmarxError(f"Response from {sanitize_url(source_url)} was not a JSON object")
		return parsed

	def _extract_error_message(self, body: bytes) -> str:
		if not body:
			return ""
		decoded = body.decode("utf-8", errors="replace").strip()
		try:
			parsed = json.loads(decoded)
		except json.JSONDecodeError:
			return decoded[:240]

		if isinstance(parsed, dict):
			for key in ("message", "Message", "error_description", "description", "error", "details", "Details"):
				value = parsed.get(key)
				if value:
					return str(value)[:240]
			errors_value = parsed.get("errors") or parsed.get("Errors")
			if isinstance(errors_value, list) and errors_value:
				return str(errors_value[0])[:240]
		return decoded[:240]

	def _raise_http_error(self, method: str, url: str, status_code: int, body: bytes) -> None:
		message = self._extract_error_message(body)
		if message:
			raise CheckmarxError(f"{method} {sanitize_url(url)} failed with {status_code}: {message}")
		raise CheckmarxError(f"{method} {sanitize_url(url)} failed with {status_code}")

	def _resolve_token_endpoint(self) -> str:
		if self.auth_url:
			token_endpoint = ensure_token_endpoint(self.auth_url, self.tenant)
			if token_endpoint:
				return token_endpoint

		aud_claim = claim_as_string(self.api_token, "aud")
		if aud_claim and ("://" in aud_claim or "/realms/" in aud_claim):
			token_endpoint = ensure_token_endpoint(aud_claim)
			if token_endpoint:
				return token_endpoint

		if self.base_url and self.tenant:
			token_endpoint = ensure_token_endpoint(self.base_url, self.tenant)
			if token_endpoint:
				return token_endpoint

		raise CheckmarxError(
			"Unable to resolve the Checkmarx auth endpoint. Set CHECKMARX_AUTH_URL or CHECKMARX_TENANT in .env."
		)

	def authenticate(self, force: bool = False) -> str:
		if not force and self._access_token and time.time() < self._access_token_expires_at:
			return self._access_token

		payload = urlparse.urlencode(
			{
				"grant_type": "refresh_token",
				"client_id": claim_as_string(self.api_token, "azp") or DEFAULT_CLIENT_ID,
				"refresh_token": self.api_token,
			}
		).encode("utf-8")
		token_url = self._resolve_token_endpoint()
		raw_body = self._request(
			"POST",
			token_url,
			data=payload,
			headers={
				"Content-Type": "application/x-www-form-urlencoded",
				"Accept": "application/json",
			},
			auth=False,
			expected_status=(200,),
		)
		token_payload = self._decode_json(raw_body, token_url)
		access_token = pick_str(token_payload, "access_token")
		expires_in = to_int(pick(token_payload, "expires_in"), default=300) or 300
		if not access_token:
			raise CheckmarxError("Authentication succeeded but no access token was returned")

		self._access_token = access_token
		self._access_token_expires_at = time.time() + max(30, expires_in - 30)

		if not self.base_url:
			self.base_url = claim_as_string(access_token, "ast-base-url").rstrip("/")
		if not self.base_url:
			self.base_url = claim_as_string(self.api_token, "ast-base-url").rstrip("/")
		if not self.base_url:
			raise CheckmarxError("Unable to resolve the Checkmarx base URL. Set CHECKMARX_BASE_URL in .env.")

		return self._access_token

	def _request(
		self,
		method: str,
		url: str,
		*,
		data: bytes | None = None,
		headers: dict[str, str] | None = None,
		auth: bool,
		expected_status: tuple[int, ...],
		retry_on_401: bool = True,
	) -> bytes:
		request_headers = {"User-Agent": USER_AGENT}
		if headers:
			request_headers.update(headers)

		if auth:
			token = self.authenticate()
			request_headers["Authorization"] = f"Bearer {token}"

		req = urlrequest.Request(url, data=data, method=method, headers=request_headers)
		try:
			with urlrequest.urlopen(req, timeout=self.timeout) as response:
				status_code = response.getcode()
				raw_body = response.read()
		except urlerror.HTTPError as exc:
			raw_body = exc.read()
			if auth and exc.code == 401 and retry_on_401:
				self.authenticate(force=True)
				return self._request(
					method,
					url,
					data=data,
					headers=headers,
					auth=auth,
					expected_status=expected_status,
					retry_on_401=False,
				)
			self._raise_http_error(method, url, exc.code, raw_body)
		except urlerror.URLError as exc:
			raise CheckmarxError(f"{method} {sanitize_url(url)} failed: {exc.reason}") from exc

		if status_code not in expected_status:
			self._raise_http_error(method, url, status_code, raw_body)
		return raw_body

	def _request_json(
		self,
		method: str,
		url: str,
		*,
		payload: dict[str, Any] | None = None,
		auth: bool,
		expected_status: tuple[int, ...],
	) -> dict[str, Any]:
		data = None
		headers = {"Accept": "application/json"}
		if payload is not None:
			data = json.dumps(payload).encode("utf-8")
			headers["Content-Type"] = "application/json"
		raw_body = self._request(method, url, data=data, headers=headers, auth=auth, expected_status=expected_status)
		return self._decode_json(raw_body, url)

	def _extract_projects(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
		projects = pick(payload, "projects", "Projects", default=[])
		return [item for item in projects if isinstance(item, dict)] if isinstance(projects, list) else []

	def list_projects(
		self,
		*,
		limit: int = 100,
		offset: int = 0,
		name: str = "",
	) -> dict[str, Any]:
		query = {
			"limit": max(1, int(limit)),
			"offset": max(0, int(offset)),
		}
		if name.strip():
			query["name"] = name.strip()
		url = with_query(join_url(self.base_url, "api/projects"), query)
		return self._request_json("GET", url, auth=True, expected_status=(200,))

	def get_all_projects(self, *, page_size: int = 100, max_projects: int = 1000) -> list[dict[str, Any]]:
		projects: list[dict[str, Any]] = []
		offset = 0
		resolved_page_size = max(1, int(page_size))
		resolved_max_projects = max(1, int(max_projects))
		seen_ids: set[str] = set()

		while len(projects) < resolved_max_projects:
			payload = self.list_projects(limit=resolved_page_size, offset=offset)
			batch = self._extract_projects(payload)
			if not batch:
				break

			for project in batch:
				project_id = pick_str(project, "id", "ID")
				if project_id and project_id in seen_ids:
					continue
				if project_id:
					seen_ids.add(project_id)
				projects.append(project)
				if len(projects) >= resolved_max_projects:
					break

			total_count = to_int(pick(payload, "totalCount", "TotalCount"), default=None)
			offset += len(batch)
			if len(batch) < resolved_page_size:
				break
			if total_count is not None and offset >= total_count:
				break

		return projects

	def get_project_by_name(self, project_name: str) -> dict[str, Any] | None:
		payload = self.list_projects(name=project_name, limit=100)
		for project in self._extract_projects(payload):
			if pick_str(project, "name", "Name") == project_name:
				return project
		return None

	def list_scans(
		self,
		project_id: str,
		*,
		branch: str = "",
		limit: int = 100,
		offset: int = 0,
	) -> dict[str, Any]:
		query = {
			"project-id": project_id,
			"limit": max(1, int(limit)),
			"offset": max(0, int(offset)),
		}
		if branch:
			query["branch"] = branch
		url = with_query(join_url(self.base_url, "api/scans"), query)
		return self._request_json("GET", url, auth=True, expected_status=(200,))

	def get_latest_project_scan(
		self,
		project_id: str,
		*,
		branch: str = "",
		prefer_terminal_scan: bool = True,
		lookback: int = 100,
	) -> dict[str, Any]:
		payload = self.list_scans(project_id, branch=branch, limit=max(1, int(lookback)), offset=0)
		scans = pick(payload, "scans", "Scans", default=[])
		if not isinstance(scans, list):
			scans = []

		candidate_scans = [item for item in scans if isinstance(item, dict)]
		if branch:
			candidate_scans = [item for item in candidate_scans if pick_str(item, "branch", "Branch") == branch]
		if not candidate_scans:
			raise CheckmarxError(
				f"No Checkmarx scans were found for project {project_id}" + (f" on branch {branch}" if branch else "")
			)

		candidate_scans.sort(
			key=lambda scan: (
				pick_str(scan, "createdAt", "CreatedAt"),
				pick_str(scan, "updatedAt", "UpdatedAt"),
				pick_str(scan, "id", "ID"),
			),
			reverse=True,
		)

		if prefer_terminal_scan:
			for scan in candidate_scans:
				if extract_scan_status(scan) in TERMINAL_SCAN_STATUSES:
					return scan
		return candidate_scans[0]

	def create_project(self, project_name: str, branch: str) -> dict[str, Any]:
		payload = {
			"name": project_name,
			"mainBranch": branch,
		}
		try:
			return self._request_json(
				"POST",
				join_url(self.base_url, "api/projects"),
				payload=payload,
				auth=True,
				expected_status=(201,),
			)
		except CheckmarxError as exc:
			if "already exists" in str(exc).lower():
				existing_project = self.get_project_by_name(project_name)
				if existing_project is not None:
					return existing_project
			raise

	def ensure_project(self, project_name: str, branch: str) -> tuple[dict[str, Any], bool]:
		project = self.get_project_by_name(project_name)
		if project is not None:
			return project, False
		return self.create_project(project_name, branch), True

	def get_presigned_upload_url(self) -> str:
		payload = self._request_json(
			"POST",
			join_url(self.base_url, "api/uploads"),
			auth=True,
			expected_status=(200,),
		)
		upload_url = pick_str(payload, "url", "URL")
		if not upload_url:
			raise CheckmarxError("Checkmarx did not return a presigned upload URL")
		return upload_url

	def upload_archive(self, upload_url: str, archive_path: Path) -> None:
		file_size = archive_path.stat().st_size
		if file_size >= MAX_SINGLE_UPLOAD_BYTES:
			raise CheckmarxError(
				"The generated archive is 5 GiB or larger. This package only supports the single-part upload flow."
			)

		for attempt in range(2):
			headers = {
				"Content-Type": "application/zip",
				"Content-Length": str(file_size),
				"User-Agent": USER_AGENT,
			}
			if attempt == 1:
				headers["Authorization"] = f"Bearer {self.authenticate(force=True)}"

			parsed_url = urlparse.urlsplit(upload_url)
			if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
				raise CheckmarxError("The presigned upload URL returned by Checkmarx was invalid")

			path = parsed_url.path or "/"
			if parsed_url.query:
				path = f"{path}?{parsed_url.query}"
			connection_class = http.client.HTTPSConnection if parsed_url.scheme == "https" else http.client.HTTPConnection
			connection = connection_class(parsed_url.hostname, parsed_url.port, timeout=self.timeout)
			try:
				with archive_path.open("rb") as handle:
					connection.request("PUT", path, body=handle, headers=headers)
					response = connection.getresponse()
					response_body = response.read()
			except OSError as exc:
				raise CheckmarxError(f"Uploading {archive_path} failed: {exc}") from exc
			finally:
				connection.close()

			if response.status in {200, 201, 204}:
				return
			if response.status == 401 and attempt == 0:
				continue
			self._raise_http_error("PUT", upload_url, response.status, response_body)

		raise CheckmarxError("Uploading the source archive failed")

	def create_scan(self, project_id: str, branch: str, upload_url: str, scan_types: list[str]) -> dict[str, Any]:
		payload = {
			"type": "upload",
			"handler": {
				"branch": branch,
				"uploadUrl": upload_url,
			},
			"project": {
				"id": project_id,
			},
			"config": [{"type": scan_type, "value": {}} for scan_type in scan_types],
		}
		return self._request_json(
			"POST",
			join_url(self.base_url, "api/scans"),
			payload=payload,
			auth=True,
			expected_status=(200, 201),
		)

	def get_scan(self, scan_id: str) -> dict[str, Any]:
		return self._request_json(
			"GET",
			join_url(self.base_url, f"api/scans/{scan_id}"),
			auth=True,
			expected_status=(200,),
		)

	def wait_for_scan(
		self,
		scan_id: str,
		poll_interval: int,
		poll_timeout: int,
		*,
		on_status: Callable[[str], None] | None = None,
	) -> dict[str, Any]:
		deadline = time.time() + poll_timeout if poll_timeout > 0 else None
		last_status = ""
		while True:
			scan = self.get_scan(scan_id)
			status = extract_scan_status(scan)
			if status != last_status:
				details = format_status_details(pick(scan, "statusDetails", "StatusDetails", default=[]))
				if on_status is not None:
					message = f"Scan status: {status}"
					if details:
						message = f"{message} | {details}"
					on_status(message)
				last_status = status

			if status in TERMINAL_SCAN_STATUSES:
				return scan

			if deadline is not None and time.time() >= deadline:
				raise CheckmarxError(f"Timed out waiting for scan {scan_id} after {poll_timeout} seconds")

			time.sleep(max(1, poll_interval))

	def get_all_results(self, scan_id: str, page_size: int = DEFAULT_RESULTS_PAGE_SIZE) -> dict[str, Any]:
		all_results: list[dict[str, Any]] = []
		total_count: int | None = None
		offset = 0

		while True:
			url = with_query(
				join_url(self.base_url, "api/results"),
				{
					"scan-id": scan_id,
					"limit": page_size,
					"offset": offset,
					"sort": "-severity",
					"include-nodes": "true",
				},
			)
			payload = self._request_json("GET", url, auth=True, expected_status=(200,))
			page_results = pick(payload, "results", "Results", default=[])
			if not isinstance(page_results, list):
				page_results = []

			for item in page_results:
				if isinstance(item, dict):
					all_results.append(item)

			if total_count is None:
				total_count = to_int(pick(payload, "totalCount", "TotalCount"), default=len(all_results)) or len(all_results)

			if not page_results or len(page_results) < page_size or len(all_results) >= total_count:
				return {
					"scanID": pick_str(payload, "scanID", "scanId", "ScanID") or scan_id,
					"totalCount": total_count,
					"results": all_results,
				}

			offset += len(page_results)
