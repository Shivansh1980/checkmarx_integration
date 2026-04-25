from __future__ import annotations

import json
from typing import Any
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from ...domain.constants import SONAR_COVERAGE_METRIC_KEYS, SONAR_FILE_PAGE_SIZE, SONAR_FILE_QUALIFIER, SONAR_PROJECTS_PAGE_SIZE, USER_AGENT
from ...domain.errors import SonarAuthenticationError, SonarError, SonarHttpError, SonarPermissionError
from ...shared.utils import compact_dict, join_url, sanitize_url, with_query


class SonarClient:
	def __init__(self, *, base_url: str, token: str, timeout: int) -> None:
		self.base_url = base_url.rstrip("/")
		self.token = token.strip()
		self.timeout = timeout

	def _decode_json(self, raw_body: bytes, source_url: str) -> dict[str, Any]:
		if not raw_body:
			return {}
		try:
			parsed = json.loads(raw_body.decode("utf-8"))
		except (UnicodeDecodeError, json.JSONDecodeError) as exc:
			raise SonarError(f"Response from {sanitize_url(source_url)} was not valid JSON") from exc
		if not isinstance(parsed, dict):
			raise SonarError(f"Response from {sanitize_url(source_url)} was not a JSON object")
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
			for key in ("errors", "error", "message"):
				value = parsed.get(key)
				if isinstance(value, list) and value:
					first = value[0]
					if isinstance(first, dict):
						for nested_key in ("msg", "message", "error"):
							nested_value = first.get(nested_key)
							if nested_value:
								return str(nested_value)[:240]
					return str(first)[:240]
				if isinstance(value, dict):
					for nested_key in ("msg", "message", "error"):
						nested_value = value.get(nested_key)
						if nested_value:
							return str(nested_value)[:240]
				if value:
					return str(value)[:240]
		return decoded[:240]

	def _raise_http_error(self, method: str, url: str, status_code: int, body: bytes, *, auth_mode: str) -> None:
		message = self._extract_error_message(body)
		base_message = f"{method} {sanitize_url(url)} failed with {status_code}"
		full_message = f"{base_message}: {message}" if message else base_message
		error_type = SonarHttpError
		if status_code == 401:
			error_type = SonarAuthenticationError
		elif status_code == 403:
			error_type = SonarPermissionError
		raise error_type(full_message, status_code=status_code, url=sanitize_url(url), auth_mode=auth_mode)

	def _open(self, req: urlrequest.Request, *, auth_mode: str) -> tuple[bytes, dict[str, str], int]:
		try:
			with urlrequest.urlopen(req, timeout=self.timeout) as response:
				return response.read(), dict(response.headers.items()), response.getcode()
		except urlerror.HTTPError as exc:
			raw_body = exc.read()
			self._raise_http_error(req.get_method(), req.full_url, exc.code, raw_body, auth_mode=auth_mode)
		except urlerror.URLError as exc:
			raise SonarError(f"{req.get_method()} {sanitize_url(req.full_url)} failed: {exc.reason}") from exc

	def _request(
		self,
		method: str,
		url: str,
		*,
		headers: dict[str, str] | None = None,
		auth_mode: str = "prefer_auth",
		allow_anonymous_fallback: bool = True,
	) -> tuple[bytes, dict[str, Any]]:
		request_headers = {
			"Accept": "application/json",
			"User-Agent": USER_AGENT,
		}
		if headers:
			request_headers.update(headers)

		def send(mode: str) -> tuple[bytes, dict[str, Any]]:
			mode_headers = dict(request_headers)
			if mode == "authenticated":
				if not self.token:
					raise SonarAuthenticationError(
						"No Sonar token was configured for authenticated access.",
						status_code=401,
						url=sanitize_url(url),
						auth_mode=mode,
					)
				mode_headers["Authorization"] = f"Bearer {self.token}"
			req = urlrequest.Request(url, method=method, headers=mode_headers)
			raw_body, response_headers, status_code = self._open(req, auth_mode=mode)
			return raw_body, {
				"used_auth_mode": mode,
				"status_code": status_code,
				"anonymous_fallback_used": False,
				"token_expiration": response_headers.get("SonarQube-Authentication-Token-Expiration", ""),
			}

		if auth_mode == "anonymous":
			return send("anonymous")
		if auth_mode == "authenticated":
			return send("authenticated")

		if self.token:
			try:
				return send("authenticated")
			except SonarHttpError as exc:
				if allow_anonymous_fallback and exc.status_code in (401, 403):
					raw_body, meta = send("anonymous")
					meta["anonymous_fallback_used"] = True
					meta["authenticated_error_status"] = exc.status_code
					return raw_body, meta
				raise
		return send("anonymous")

	def _request_json(
		self,
		path: str,
		*,
		params: dict[str, Any] | None = None,
		headers: dict[str, str] | None = None,
		auth_mode: str = "prefer_auth",
		allow_anonymous_fallback: bool = True,
	) -> tuple[dict[str, Any], dict[str, Any]]:
		url = join_url(self.base_url, path)
		if params:
			url = with_query(url, params)
		raw_body, meta = self._request(
			"GET",
			url,
			headers=headers,
			auth_mode=auth_mode,
			allow_anonymous_fallback=allow_anonymous_fallback,
		)
		return self._decode_json(raw_body, url), meta

	def validate_token(self) -> dict[str, Any]:
		if not self.token:
			return {
				"token_configured": False,
				"token_valid": False,
				"token_expiration": "",
				"error": "",
			}
		try:
			_, meta = self._request_json(
				"api/authentication/validate",
				auth_mode="authenticated",
				allow_anonymous_fallback=False,
			)
			return {
				"token_configured": True,
				"token_valid": True,
				"token_expiration": meta.get("token_expiration", ""),
				"error": "",
			}
		except SonarHttpError as exc:
			return {
				"token_configured": True,
				"token_valid": False,
				"token_expiration": "",
				"error": str(exc),
			}

	def list_projects(
		self,
		*,
		query: str = "",
		page: int = 1,
		page_size: int = SONAR_PROJECTS_PAGE_SIZE,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params = {"p": max(1, int(page)), "ps": max(1, int(page_size))}
		if query.strip():
			params["q"] = query.strip()
		try:
			return self._request_json("api/projects/search", params=params, auth_mode=auth_mode)
		except SonarHttpError as exc:
			if exc.status_code not in (403, 404):
				raise
			try:
				return self._request_json("api/components/search_projects", params=params, auth_mode=auth_mode)
			except SonarHttpError as fallback_exc:
				if fallback_exc.status_code not in (403, 404):
					raise
				components_params = dict(params)
				components_params["qualifiers"] = "TRK"
				return self._request_json("api/components/search", params=components_params, auth_mode=auth_mode)

	def list_project_branches(
		self,
		project: str,
		*,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		return self._request_json("api/project_branches/list", params={"project": project}, auth_mode=auth_mode)

	def list_project_pull_requests(
		self,
		project: str,
		*,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		return self._request_json("api/project_pull_requests/list", params={"project": project}, auth_mode=auth_mode)

	def get_quality_gate_status(
		self,
		*,
		project_key: str = "",
		project_id: str = "",
		analysis_id: str = "",
		branch: str = "",
		pull_request: str = "",
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params: dict[str, Any] = {}
		if analysis_id:
			params["analysisId"] = analysis_id
		elif project_id:
			params["projectId"] = project_id
		elif project_key:
			params["projectKey"] = project_key
		else:
			raise SonarError("A Sonar projectKey, projectId, or analysisId is required for quality gate status.")
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		return self._request_json("api/qualitygates/project_status", params=params, auth_mode=auth_mode)

	def get_component_measures(
		self,
		component: str,
		*,
		branch: str = "",
		pull_request: str = "",
		metric_keys: tuple[str, ...] = SONAR_COVERAGE_METRIC_KEYS,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params = {
			"component": component,
			"metricKeys": ",".join(metric_keys),
		}
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		return self._request_json("api/measures/component", params=params, auth_mode=auth_mode)

	def get_component_tree(
		self,
		component: str,
		*,
		branch: str = "",
		pull_request: str = "",
		query: str = "",
		page: int = 1,
		page_size: int = SONAR_FILE_PAGE_SIZE,
		qualifiers: str = SONAR_FILE_QUALIFIER,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params: dict[str, Any] = {
			"component": component,
			"p": max(1, int(page)),
			"ps": max(1, int(page_size)),
			"qualifiers": qualifiers,
		}
		if query.strip():
			params["q"] = query.strip()
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		return self._request_json("api/components/tree", params=params, auth_mode=auth_mode)

	def get_measures_component_tree(
		self,
		component: str,
		*,
		branch: str = "",
		pull_request: str = "",
		page: int = 1,
		page_size: int = SONAR_FILE_PAGE_SIZE,
		metric_keys: tuple[str, ...] = SONAR_COVERAGE_METRIC_KEYS,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params: dict[str, Any] = {
			"component": component,
			"metricKeys": ",".join(metric_keys),
			"qualifiers": SONAR_FILE_QUALIFIER,
			"p": max(1, int(page)),
			"ps": max(1, int(page_size)),
		}
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		return self._request_json("api/measures/component_tree", params=params, auth_mode=auth_mode)

	def show_component(
		self,
		component: str,
		*,
		branch: str = "",
		pull_request: str = "",
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params = {"component": component}
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		return self._request_json("api/components/show", params=params, auth_mode=auth_mode)

	def show_source(
		self,
		component_key: str,
		*,
		branch: str = "",
		pull_request: str = "",
		raw: bool = False,
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params = {"key": component_key}
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		endpoint = "api/sources/raw" if raw else "api/sources/show"
		return self._request_json(endpoint, params=params, auth_mode=auth_mode)

	def get_component_app(
		self,
		component_key: str,
		*,
		branch: str = "",
		pull_request: str = "",
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		params = {"component": component_key}
		if branch:
			params["branch"] = branch
		if pull_request:
			params["pullRequest"] = pull_request
		return self._request_json("api/components/app", params=params, auth_mode=auth_mode)

	def resolve_file_component(
		self,
		project: str,
		*,
		file_path: str = "",
		file_key: str = "",
		branch: str = "",
		pull_request: str = "",
		auth_mode: str = "prefer_auth",
	) -> tuple[dict[str, Any], dict[str, Any]]:
		if file_key:
			payload, meta = self.show_component(file_key, branch=branch, pull_request=pull_request, auth_mode=auth_mode)
			component = payload.get("component") if isinstance(payload.get("component"), dict) else {}
			if not component:
				raise SonarError(f"Sonar component was not found: {file_key}")
			return component, meta

		search_value = file_path.strip()
		if not search_value:
			raise SonarError("Either file or file_key is required.")

		def normalize(value: Any) -> str:
			return str(value or "").replace("\\", "/").strip().lower()

		def matches(component: dict[str, Any], needle: str) -> bool:
			path = normalize(component.get("path"))
			key = normalize(component.get("key"))
			name = normalize(component.get("name"))
			leaf = needle.split("/")[-1]
			return path == needle or key.endswith(needle) or name == leaf or path.endswith(needle)

		payload, meta = self.get_component_tree(
			project,
			branch=branch,
			pull_request=pull_request,
			query=search_value,
			page=1,
			page_size=100,
			auth_mode=auth_mode,
		)
		components = payload.get("components") if isinstance(payload.get("components"), list) else []
		needle = normalize(search_value)
		for component in components:
			if not isinstance(component, dict):
				continue
			if matches(component, needle):
				return component, meta

		# Some SonarQube versions do not match full repository paths well with q-based search.
		# Fall back to scanning the file tree page by page when the direct search returns no exact hit.
		page = 1
		while True:
			fallback_payload, fallback_meta = self.get_component_tree(
				project,
				branch=branch,
				pull_request=pull_request,
				page=page,
				page_size=SONAR_FILE_PAGE_SIZE,
				auth_mode=auth_mode,
			)
			fallback_components = fallback_payload.get("components") if isinstance(fallback_payload.get("components"), list) else []
			for component in fallback_components:
				if isinstance(component, dict) and matches(component, needle):
					return component, fallback_meta
			paging = fallback_payload.get("paging") if isinstance(fallback_payload.get("paging"), dict) else {}
			total = int(paging.get("total") or 0)
			page_size_value = int(paging.get("pageSize") or SONAR_FILE_PAGE_SIZE)
			page_index = int(paging.get("pageIndex") or page)
			if not fallback_components or (total and page_index * page_size_value >= total):
				break
			page += 1
		raise SonarError(f"Sonar file component was not found for '{search_value}'.")

	def normalize_project_list(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
		projects = payload.get("components") or payload.get("projects") or []
		return [item for item in projects if isinstance(item, dict)] if isinstance(projects, list) else []

	def normalize_branches(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
		branches = payload.get("branches") or []
		return [item for item in branches if isinstance(item, dict)] if isinstance(branches, list) else []

	def normalize_pull_requests(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
		pull_requests = payload.get("pullRequests") or []
		return [item for item in pull_requests if isinstance(item, dict)] if isinstance(pull_requests, list) else []

	def normalize_components(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
		components = payload.get("components") or []
		return [item for item in components if isinstance(item, dict)] if isinstance(components, list) else []

	@staticmethod
	def parse_measures(component: dict[str, Any]) -> dict[str, Any]:
		measures = component.get("measures")
		parsed: dict[str, Any] = {}
		if not isinstance(measures, list):
			return parsed
		for item in measures:
			if not isinstance(item, dict):
				continue
			metric = str(item.get("metric") or "").strip()
			if not metric:
				continue
			value = item.get("value")
			if value in (None, ""):
				parsed[metric] = None
				continue
			try:
				if metric.endswith("lines") or metric.endswith("conditions"):
					parsed[metric] = int(float(value))
				else:
					parsed[metric] = float(value)
			except (TypeError, ValueError):
				parsed[metric] = value
		return parsed

	@staticmethod
	def build_auth_section(validation: dict[str, Any], metas: list[dict[str, Any]]) -> dict[str, Any]:
		anonymous_fallback_used = any(bool(meta.get("anonymous_fallback_used")) for meta in metas)
		return compact_dict(
			{
				"token_configured": validation.get("token_configured", False),
				"token_valid": validation.get("token_valid", False),
				"token_expiration": validation.get("token_expiration", ""),
				"anonymous_fallback_used": anonymous_fallback_used,
				"validation_error": validation.get("error", ""),
			}
		)