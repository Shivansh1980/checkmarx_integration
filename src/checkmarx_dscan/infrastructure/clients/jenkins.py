from __future__ import annotations

import base64
import json
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

from ...domain.errors import JenkinsError
from ...shared.utils import join_url, pick_str, sanitize_url, with_query


class JenkinsClient:
	def __init__(self, *, base_url: str, username: str, api_token: str, timeout: int) -> None:
		self.base_url = base_url.rstrip("/") if base_url else ""
		self.username = username.strip()
		self.api_token = api_token.strip()
		self.timeout = timeout

	def _authorization_header(self) -> str | None:
		if not self.username and not self.api_token:
			return None
		token = base64.b64encode(f"{self.username}:{self.api_token}".encode("utf-8")).decode("ascii")
		return f"Basic {token}"

	def _decode_json(self, raw_body: bytes, source_url: str) -> dict[str, Any]:
		if not raw_body:
			return {}
		try:
			parsed = json.loads(raw_body.decode("utf-8"))
		except (UnicodeDecodeError, json.JSONDecodeError) as exc:
			raise JenkinsError(f"Response from {sanitize_url(source_url)} was not valid JSON") from exc
		if not isinstance(parsed, dict):
			raise JenkinsError(f"Response from {sanitize_url(source_url)} was not a JSON object")
		return parsed

	def _decode_json_payload(self, raw_body: bytes, source_url: str) -> Any:
		if not raw_body:
			raise JenkinsError(f"Response from {sanitize_url(source_url)} was empty")
		try:
			return json.loads(raw_body.decode("utf-8"))
		except (UnicodeDecodeError, json.JSONDecodeError) as exc:
			raise JenkinsError(f"Artifact response from {sanitize_url(source_url)} was not valid JSON") from exc

	def _extract_error_message(self, body: bytes) -> str:
		if not body:
			return ""
		decoded = body.decode("utf-8", errors="replace").strip()
		try:
			parsed = json.loads(decoded)
		except json.JSONDecodeError:
			return decoded[:240]

		if isinstance(parsed, dict):
			for key in ("message", "error", "description", "details"):
				value = parsed.get(key)
				if value:
					return str(value)[:240]
		return decoded[:240]

	def _raise_http_error(self, method: str, url: str, status_code: int, body: bytes) -> None:
		message = self._extract_error_message(body)
		if message:
			raise JenkinsError(f"{method} {sanitize_url(url)} failed with {status_code}: {message}")
		raise JenkinsError(f"{method} {sanitize_url(url)} failed with {status_code}")

	def _request(
		self,
		method: str,
		url: str,
		*,
		expected_status: tuple[int, ...],
		headers: dict[str, str] | None = None,
		include_auth: bool = True,
		retry_anonymous_on_auth_failure: bool = True,
		not_found_is_none: bool = False,
	) -> bytes:
		request_headers = {
			"Accept": "application/json",
		}
		auth_header = self._authorization_header() if include_auth else None
		if auth_header:
			request_headers["Authorization"] = auth_header
		if headers:
			request_headers.update(headers)

		req = urlrequest.Request(url, method=method, headers=request_headers)
		try:
			with urlrequest.urlopen(req, timeout=self.timeout) as response:
				status_code = response.getcode()
				raw_body = response.read()
		except urlerror.HTTPError as exc:
			raw_body = exc.read()
			if not_found_is_none and exc.code == 404:
				return b""
			if auth_header and include_auth and retry_anonymous_on_auth_failure and exc.code in {401, 403}:
				return self._request(
					method,
					url,
					expected_status=expected_status,
					headers=headers,
					include_auth=False,
					retry_anonymous_on_auth_failure=False,
					not_found_is_none=not_found_is_none,
				)
			self._raise_http_error(method, url, exc.code, raw_body)
		except urlerror.URLError as exc:
			raise JenkinsError(f"{method} {sanitize_url(url)} failed: {exc.reason}") from exc

		if status_code not in expected_status:
			self._raise_http_error(method, url, status_code, raw_body)
		return raw_body

	def _api_url(self, resource_url: str, *, tree: str) -> str:
		return with_query(join_url(resource_url.rstrip("/"), "api/json"), {"tree": tree})

	def get_job(self, job_url: str) -> dict[str, Any]:
		tree = "name,fullName,url,displayName,inQueue,lastBuild[number,url],lastCompletedBuild[number,url,result]"
		raw_body = self._request("GET", self._api_url(job_url, tree=tree), expected_status=(200,))
		return self._decode_json(raw_body, job_url)

	def list_jobs(self, resource_url: str) -> list[dict[str, Any]]:
		raw_body = self._request("GET", self._api_url(resource_url, tree="jobs[name,url]"), expected_status=(200,))
		payload = self._decode_json(raw_body, resource_url)
		jobs = payload.get("jobs")
		if not isinstance(jobs, list):
			return []
		return [job for job in jobs if isinstance(job, dict)]

	def get_build_reference(self, job_url: str, reference: str) -> dict[str, Any] | None:
		build_url = join_url(job_url.rstrip("/"), reference)
		tree = "number,url,result,building,displayName,fullDisplayName,description,timestamp,duration,artifacts[fileName,relativePath,displayPath]"
		raw_body = self._request(
			"GET",
			self._api_url(build_url, tree=tree),
			expected_status=(200,),
			not_found_is_none=True,
		)
		if not raw_body:
			return None
		return self._decode_json(raw_body, build_url)

	def get_build(self, job_url: str, build_number: int, *, not_found_is_none: bool = False) -> dict[str, Any] | None:
		build_url = join_url(job_url.rstrip("/"), str(build_number))
		tree = "number,url,result,building,displayName,fullDisplayName,description,timestamp,duration,artifacts[fileName,relativePath,displayPath]"
		raw_body = self._request(
			"GET",
			self._api_url(build_url, tree=tree),
			expected_status=(200,),
			not_found_is_none=not_found_is_none,
		)
		if not raw_body:
			return None
		return self._decode_json(raw_body, build_url)

	def download_artifact_json(self, download_url: str) -> Any:
		raw_body = self._request("GET", download_url, expected_status=(200,), headers={"Accept": "application/json"})
		return self._decode_json_payload(raw_body, download_url)

	def build_artifact_download_url(self, build_payload: dict[str, Any], relative_path: str, job_url: str, build_number: int) -> str:
		build_url = pick_str(build_payload, "url") or join_url(job_url.rstrip("/"), f"{build_number}/")
		return join_url(build_url, f"artifact/{relative_path}")
