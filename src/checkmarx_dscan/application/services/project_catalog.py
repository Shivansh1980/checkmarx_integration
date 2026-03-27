from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any, Callable

from ...domain.models import CheckmarxCredentials
from ...infrastructure.clients.checkmarx import CheckmarxClient
from ...shared.utils import compact_dict, pick, pick_str, utc_now_iso


ProgressCallback = Callable[[str], None]


def _project_name(project: dict[str, Any]) -> str:
    return pick_str(project, "name", "Name")


def _project_id(project: dict[str, Any]) -> str:
    return pick_str(project, "id", "ID")


def _project_repo_url(project: dict[str, Any]) -> str:
    return pick_str(project, "repo_url", "repoUrl", "RepoUrl", "originUrl", "OriginUrl")


def _normalize_project_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").strip().lower()).strip()


def _compute_match(project: dict[str, Any], query: str) -> dict[str, Any] | None:
    normalized_query = _normalize_project_text(query)
    if not normalized_query:
        return None

    name = _project_name(project)
    project_id = _project_id(project)
    repo_url = _project_repo_url(project)
    normalized_name = _normalize_project_text(name)
    normalized_id = _normalize_project_text(project_id)
    normalized_repo_url = _normalize_project_text(repo_url)

    score = 0.0
    match_type = "similar"
    if normalized_name == normalized_query:
        score = 1.0
        match_type = "exact_name"
    elif normalized_id and normalized_id == normalized_query:
        score = 0.99
        match_type = "exact_id"
    elif normalized_name and normalized_query in normalized_name:
        score = 0.95 if normalized_name.startswith(normalized_query) else 0.9
        match_type = "name_contains"
    elif normalized_repo_url and normalized_query and normalized_query in normalized_repo_url:
        score = 0.88
        match_type = "repo_url_contains"
    else:
        name_ratio = SequenceMatcher(None, normalized_query, normalized_name).ratio() if normalized_name else 0.0
        repo_ratio = SequenceMatcher(None, normalized_query, normalized_repo_url).ratio() if normalized_repo_url else 0.0
        id_ratio = SequenceMatcher(None, normalized_query, normalized_id).ratio() if normalized_id else 0.0
        score = max(name_ratio, repo_ratio * 0.92, id_ratio * 0.9)
        if score < 0.45:
            return None

    return {
        "score": round(score, 4),
        "match_type": match_type,
        "project": project,
    }


def summarize_project(project: dict[str, Any]) -> dict[str, Any]:
    return compact_dict(
        {
            "id": _project_id(project),
            "name": _project_name(project),
            "main_branch": pick_str(project, "mainBranch", "MainBranch", "main_branch"),
            "repo_url": _project_repo_url(project),
            "groups": pick(project, "groups", "Groups", default=[]),
            "tags": pick(project, "tags", "Tags", default=[]),
        }
    )


def rank_project_matches(projects: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    matches = [match for match in (_compute_match(project, query) for project in projects) if match is not None]
    matches.sort(key=lambda item: (item["score"], _project_name(item["project"]).lower()), reverse=True)
    return matches


def resolve_project_match(projects: list[dict[str, Any]], query: str) -> dict[str, Any] | None:
    matches = rank_project_matches(projects, query)
    if not matches:
        return None

    best_match = matches[0]
    second_match = matches[1] if len(matches) > 1 else None
    if best_match["match_type"] in {"exact_name", "exact_id"}:
        return best_match

    score_gap = best_match["score"] - (second_match["score"] if second_match is not None else 0.0)
    if best_match["match_type"] == "name_contains" and best_match["score"] >= 0.9 and score_gap >= 0.05:
        return best_match
    return None


def build_project_lookup_error(project_query: str, matches: list[dict[str, Any]]) -> str:
    if matches:
        suggestions = ", ".join(_project_name(item["project"]) for item in matches[:5] if _project_name(item["project"]))
        if suggestions:
            return (
                f"Checkmarx project was not found: {project_query}. Closest accessible projects: {suggestions}. "
                "Call checkmarx_scan with scan_mode=projects to inspect the full project list."
            )
    return (
        f"Checkmarx project was not found: {project_query}. "
        "Call checkmarx_scan with scan_mode=projects to inspect the accessible project list."
    )


class CheckmarxProjectCatalogService:
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
        *,
        project_query: str = "",
        include_raw: bool = True,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        self.client.authenticate()
        raw_projects = self.client.get_all_projects()
        projects = [summarize_project(project) for project in raw_projects]
        projects.sort(key=lambda item: (item.get("name", "").lower(), item.get("id", "").lower()))
        matches = rank_project_matches(projects, project_query)

        if progress_callback is not None:
            progress_callback(f"Enumerated {len(projects)} accessible Checkmarx projects.")
            if project_query.strip():
                progress_callback(f"Found {len(matches)} candidate matches for query: {project_query.strip()}")

        best_match = matches[0] if matches else None
        payload = compact_dict(
            {
                "ok": True,
                "mode": "projects",
                "generated_at": utc_now_iso(),
                "project_query": project_query.strip(),
                "summary": {
                    "accessible_projects": len(projects),
                    "match_count": len(matches),
                },
                "project_resolution": compact_dict(
                    {
                        "matched": bool(matches),
                        "best_match": compact_dict(
                            {
                                "score": best_match["score"],
                                "match_type": best_match["match_type"],
                                "project": best_match["project"],
                            }
                        )
                        if best_match is not None
                        else None,
                    }
                ),
                "matches": [
                    {
                        "score": item["score"],
                        "match_type": item["match_type"],
                        "project": item["project"],
                    }
                    for item in matches[:10]
                ],
                "projects": projects,
                "raw": {"projects": raw_projects} if include_raw else None,
            }
        )
        return payload