from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

from ...domain.models import REPORT_PROFILE_FULL, normalize_report_profile, serialize_agent_report
from ...shared.utils import utc_now_iso


_MOCK_DEMO_PROJECT_ROOT = "demo/mock_providerportal_web"
_MOCK_DEMO_PACKAGE_JSON = f"{_MOCK_DEMO_PROJECT_ROOT}/package.json"
_MOCK_DEMO_PACKAGE_LOCK = f"{_MOCK_DEMO_PROJECT_ROOT}/package-lock.json"
_MOCK_DEMO_DOCKERFILE = f"{_MOCK_DEMO_PROJECT_ROOT}/Dockerfile"
_MOCK_DEMO_RESET_COMMAND = "python tools/mock_demo_project.py reset"
_MOCK_DEMO_INJECT_COMMAND = "python tools/mock_demo_project.py inject"


_CHECKMARX_FINDINGS = [
    {
        "index": 1,
        "id": "CVE-2026-10001",
        "type": "sca",
        "severity": "critical",
        "state": "TO_VERIFY",
        "title": "axios",
        "description": "Mock dependency vulnerability retained for demo workflows.",
        "location": {
            "filename": _MOCK_DEMO_PACKAGE_JSON,
            "display": f"{_MOCK_DEMO_PACKAGE_JSON}:12",
            "line": 12,
        },
        "package_name": "axios",
        "package_version": "0.16.2",
        "recommended_version": "1.12.2",
        "fix_recommendation": "Upgrade axios to 1.12.2 or newer in package.json and regenerate package-lock.json.",
        "references": ["https://example.test/advisories/CVE-2026-10001"],
    },
    {
        "index": 2,
        "id": "KICS-2026-0009",
        "type": "kics",
        "severity": "medium",
        "state": "TO_VERIFY",
        "title": "Container runs as root",
        "description": "Mock infrastructure finding for demo workflows.",
        "location": {
            "filename": _MOCK_DEMO_DOCKERFILE,
            "display": f"{_MOCK_DEMO_DOCKERFILE}:12",
            "line": 12,
        },
        "category": "Docker",
        "fix_recommendation": "Create a non-root user and switch to it before runtime.",
        "references": ["https://example.test/kics/non-root"],
    },
]


def _mock_demo_project_details() -> dict[str, Any]:
    return {
        "name": "mock_providerportal_web",
        "root": _MOCK_DEMO_PROJECT_ROOT,
        "managed_files": [_MOCK_DEMO_PACKAGE_JSON, _MOCK_DEMO_PACKAGE_LOCK, _MOCK_DEMO_DOCKERFILE],
        "reset_command": _MOCK_DEMO_RESET_COMMAND,
        "inject_command": _MOCK_DEMO_INJECT_COMMAND,
        "notes": [
            "This project is intentionally vulnerable for mock-only demos.",
            "Let Copilot apply fixes to the files listed in managed_files, then run the reset command to restore the vulnerable baseline.",
        ],
    }


def _checkmarx_agent_report() -> dict[str, Any]:
    return {
        "project_id": "demo-project-id",
        "project_name": "demo-providerportal-web",
        "scan_id": "demo-scan-id",
        "branch_name": "release_1",
        "status": "Completed",
        "status_details": "general Completed; sca Completed; kics Completed",
        "engines_enabled": ["sca", "kics"],
        "detail_source": "mock_report",
        "detailed_findings_available": True,
        "vulnerability_summary": {
            "total_findings": 2,
            "highest_severity": "critical",
            "severity_counts": {"critical": 1, "medium": 1},
            "engine_counts": {"sca": 1, "kics": 1},
            "terminal_status": "Completed",
        },
        "engine_coverage": {
            "engines_enabled": ["sca", "kics"],
            "engines_with_findings": ["sca", "kics"],
            "engines_without_findings": [],
        },
        "top_actionable_issues": [
            {
                "type": "sca",
                "severity": "critical",
                "title": "axios 0.16.2",
                "package_name": "axios",
                "package_version": "0.16.2",
                "recommended_version": "1.12.2",
                "location": f"{_MOCK_DEMO_PACKAGE_JSON}:12",
                "vulnerability_count": 1,
                "fix_recommendation": "Upgrade axios to 1.12.2 or newer in package.json and regenerate package-lock.json.",
            }
        ],
        "top_fix_targets": [
            {
                "type": "package",
                "target": "axios",
                "current_version": "0.16.2",
                "recommended_version": "1.12.2",
                "reason": "Clears the highest-severity dependency issue in the demo project.",
                "files": [_MOCK_DEMO_PACKAGE_JSON, _MOCK_DEMO_PACKAGE_LOCK],
            }
        ],
        "dependency_issues": [_CHECKMARX_FINDINGS[0]],
        "infrastructure_issues": [_CHECKMARX_FINDINGS[1]],
        "vulnerabilities": deepcopy(_CHECKMARX_FINDINGS),
    }


def _build_checkmarx_report_payload(*, include_archive: bool) -> dict[str, Any]:
    payload = {
        "generated_at": utc_now_iso(),
        "request": {
            "project_name": "demo-providerportal-web",
            "branch": "release_1",
            "results_page_size": 500,
            "include_raw": True,
            "prefer_terminal_scan": True,
            "scan_lookback": 100,
        },
        "project": {
            "id": "demo-project-id",
            "name": "demo-providerportal-web",
            "main_branch": "release_1",
        },
        "scan": {
            "id": "demo-scan-id",
            "branch": "release_1",
            "status": "Completed",
            "status_details": "general Completed; sca Completed; kics Completed",
            "engines": ["sca", "kics"],
            "total_results": 2,
            "created_at": "2026-04-10T09:30:00Z",
            "completed_at": "2026-04-10T09:34:00Z",
        },
        "summary": {
            "total_findings": 2,
            "terminal_status": "Completed",
            "status_details": "general Completed; sca Completed; kics Completed",
            "successful": True,
            "severity_counts": {"critical": 1, "medium": 1},
            "engine_counts": {"sca": 1, "kics": 1},
            "highest_severity": "critical",
        },
        "findings": deepcopy(_CHECKMARX_FINDINGS),
        "agent_report": _checkmarx_agent_report(),
        "demo_project": _mock_demo_project_details(),
        "raw": {
            "project": {"id": "demo-project-id", "name": "demo-providerportal-web"},
            "final_scan": {"id": "demo-scan-id", "status": {"value": "Completed"}},
            "results": {"totalCount": 2, "results": deepcopy(_CHECKMARX_FINDINGS)},
        },
    }
    if include_archive:
        payload["archive"] = {
            "path": "C:/temp/demo-providerportal-web.zip",
            "created": True,
            "size_bytes": 8192,
            "size_human": "8.0 KB",
            "retained": False,
        }
        payload["request"].update(
            {
                "source_path": f"./{_MOCK_DEMO_PROJECT_ROOT}",
                "scan_types": ["sca", "kics"],
                "poll_interval": 15,
                "poll_timeout": 7200,
                "keep_archive": False,
            }
        )
    return payload


_CHECKMARX_PROJECTS = [
    {
        "id": "demo-project-id",
        "name": "demo-providerportal-web",
        "main_branch": "release_1",
        "repo_url": "https://github.example.test/demo/providerportal-web",
        "groups": ["CIS", "ProviderPortal"],
        "tags": ["demo", "release_1"],
    },
    {
        "id": "demo-project-alt",
        "name": "demo-providerportal-api",
        "main_branch": "main",
        "repo_url": "https://github.example.test/demo/providerportal-api",
        "groups": ["CIS"],
        "tags": ["demo"],
    },
]


def _build_mock_pr_job_url(job_url: str, pr_number: int | None) -> str:
    cleaned = (job_url or "").strip().rstrip("/")
    if not cleaned:
        cleaned = "http://jenkins.example.test/job/demo/view/change-requests"
    if pr_number is not None:
        match = re.search(r"(?P<prefix>.*/job/PR-)(?P<number>\d+)/?$", cleaned, re.IGNORECASE)
        if match is not None:
            return f"{match.group('prefix')}{int(pr_number)}"
        return f"{cleaned}/job/PR-{int(pr_number)}"
    if re.search(r"/job/PR-\d+/?$", cleaned, re.IGNORECASE):
        return cleaned
    if "/view/change-requests" in cleaned.lower():
        return f"{cleaned}/job/PR-112"
    return cleaned


_JENKINS_FIXTURE = {
    "generated_at": utc_now_iso(),
    "request": {
        "job_url": "http://jenkins.example.test/job/demo/release_1",
        "build_number": 167,
        "artifact_name": "checkmarx-ast-results.json",
        "poll_interval": 15,
        "poll_timeout": 7200,
        "include_raw": True,
        "prefer_running_build": True,
        "fallback_build_lookback": 10,
    },
    "job": {
        "url": "http://jenkins.example.test/job/demo/release_1",
        "name": "release_1",
        "full_name": "Demo/release_1",
        "in_queue": False,
    },
    "build": {
        "number": 167,
        "url": "http://jenkins.example.test/job/demo/release_1/167/",
        "result": "FAILURE",
        "building": False,
        "display_name": "0.0-167-demo",
        "full_display_name": "Demo » release_1 0.0-167-demo",
        "timestamp": 1775813400000,
        "duration_ms": 972781,
        "artifact_count": 1,
        "selected_from": "explicit",
    },
    "artifact": {
        "file_name": "checkmarx-ast-results.json",
        "relative_path": "cx.tmp/demo/checkmarx-ast-results.json",
        "display_path": "checkmarx-ast-results.json",
        "download_url": "http://jenkins.example.test/job/demo/release_1/167/artifact/cx.tmp/demo/checkmarx-ast-results.json",
    },
    "summary": {
        "build_selected_from": "explicit",
        "build_result": "FAILURE",
        "building": False,
        "artifact_found": True,
        "artifact_name": "checkmarx-ast-results.json",
        "report_kind": "json_object",
        "report_total_findings": 2,
        "detail_source": "mock_report",
        "detailed_findings_available": True,
        "detailed_findings_count": 2,
    },
    "report": {
        "TotalIssues": 2,
        "CriticalIssues": 1,
        "MediumIssues": 1,
        "RiskStyle": "critical",
        "RiskMsg": "Critical Risk",
        "Status": "Completed",
        "ScanID": "demo-scan-id",
        "CreatedAt": "2026-04-10, 09:30:00",
        "ProjectID": "demo-project-id",
        "BaseURI": "https://us.ast.checkmarx.net/projects/demo-project-id/scans?id=demo-scan-id&branch=release_1",
        "ProjectName": "demo-providerportal-web",
        "BranchName": "release_1",
        "EnginesEnabled": ["sca", "kics"],
        "Policies": {"status": "NONE", "breakBuild": False, "policies": None},
    },
    "agent_report": {
        "scan_id": "demo-scan-id",
        "project_id": "demo-project-id",
        "project_name": "demo-providerportal-web",
        "branch_name": "release_1",
        "status": "Completed",
        "risk_style": "critical",
        "risk_message": "Critical Risk",
        "created_at": "2026-04-10T09:30:00Z",
        "base_uri": "https://us.ast.checkmarx.net/projects/demo-project-id/scans?id=demo-scan-id&branch=release_1",
        "engines_enabled": ["sca", "kics"],
        "policies": {"status": "NONE", "breakBuild": False, "policies": None},
        "detail_source": "mock_report",
        "detailed_findings_available": True,
        "artifact_vulnerability_summary": {
            "total_findings": 2,
            "highest_severity": "critical",
        },
        "api_vulnerability_summary": {
            "total_findings": 2,
            "highest_severity": "critical",
        },
        "normalized_scan": {
            "scan_id": "demo-scan-id",
            "branch_name": "release_1",
            "status": "Completed",
        },
        "top_actionable_issues": [
            {
                "type": "sca",
                "severity": "critical",
                "title": "axios 0.16.2",
                "location": f"{_MOCK_DEMO_PACKAGE_JSON}:12",
                "vulnerability_count": 1,
                "recommended_version": "1.12.2",
            }
        ],
        "top_fix_targets": [
            {
                "target": "axios",
                "recommended_version": "1.12.2",
                "reason": "Clears the highest-severity dependency issue in the demo project.",
                "files": [_MOCK_DEMO_PACKAGE_JSON, _MOCK_DEMO_PACKAGE_LOCK],
            }
        ],
        "vulnerabilities": deepcopy(_CHECKMARX_FINDINGS),
    },
    "raw": {
        "job": {"name": "release_1", "url": "http://jenkins.example.test/job/demo/release_1"},
        "build": {"number": 167, "result": "FAILURE"},
        "artifact": {"fileName": "checkmarx-ast-results.json"},
    },
}


_SONAR_ACCESS_PROBE = {
    "ok": True,
    "server": "sonar",
    "generated_at": utc_now_iso(),
    "access_mode": "authenticated",
    "authentication": {
        "token_configured": True,
        "token_valid": True,
        "anonymous_fallback_used": False,
    },
    "capabilities": {
        "can_list_projects": "confirmed",
        "can_list_branches": "confirmed",
        "can_read_project_measures": "confirmed",
        "can_read_file_measures": "confirmed",
        "can_read_source": "confirmed",
        "can_read_line_level_coverage": "confirmed",
    },
    "permission_gaps": [],
    "projects": [
        {
            "key": "demo-providerportal-web",
            "name": "Demo Provider Portal Web",
            "qualifier": "TRK",
            "visibility": "private",
            "last_analysis_date": "2026-04-10T09:45:00+0000",
        }
    ],
    "branches": [
        {
            "name": "release_1",
            "is_main": False,
            "analysis_date": "2026-04-10T09:45:00+0000",
        }
    ],
}


_SONAR_PROJECTS = {
    "ok": True,
    "server": "sonar",
    "generated_at": utc_now_iso(),
    "access_mode": "authenticated",
    "authentication": {
        "token_configured": True,
        "token_valid": True,
        "anonymous_fallback_used": False,
    },
    "projects": [
        {
            "key": "demo-providerportal-web",
            "name": "Demo Provider Portal Web",
            "qualifier": "TRK",
            "visibility": "private",
            "last_analysis_date": "2026-04-10T09:45:00+0000",
        },
        {
            "key": "demo-providerportal-api",
            "name": "Demo Provider Portal API",
            "qualifier": "TRK",
            "visibility": "private",
            "last_analysis_date": "2026-04-10T09:42:00+0000",
        },
    ],
    "branches": [],
    "page": 1,
    "page_size": 100,
}


_SONAR_REMOTE_REPORT = {
    "ok": True,
    "server": "sonar",
    "report_type": "coverage_improvement",
    "generated_at": utc_now_iso(),
    "access_mode": "authenticated",
    "project_summary": {
        "project_key": "demo-providerportal-web",
        "project_name": "Demo Provider Portal Web",
        "branch_name": "release_1",
        "pull_request": "",
        "overall_coverage_pct": 71.4,
        "line_coverage_pct": 73.1,
        "branch_coverage_pct": 58.2,
        "total_lines_considered": 420,
        "total_covered_lines": 300,
        "total_uncovered_lines": 120,
        "total_files_analyzed": 12,
        "total_files_with_uncovered_lines": 5,
        "total_files_with_executable_coverage": 10,
    },
    "files": [
        {
            "file_key": "demo-providerportal-web:src/checkmarx_dscan/interfaces/agents/common.py",
            "file_path": "src/checkmarx_dscan/interfaces/agents/common.py",
            "file_name": "common.py",
            "coverage_pct": 42.0,
            "line_coverage_pct": 44.0,
            "branch_coverage_pct": 30.0,
            "total_lines_considered": 80,
            "covered_lines_count": 34,
            "uncovered_lines_count": 46,
            "uncovered_line_numbers": [85, 93, 147, 190],
            "covered_line_numbers": [84, 86, 87],
            "priority_score": 46.2,
            "priority": "high",
            "estimated_project_impact_pct": 38.33,
            "should_target_first": True,
            "why": "This file carries a large uncovered line count relative to the project.",
            "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
            "has_executable_coverage_metrics": True,
            "line_number_quality": "estimated",
        },
        {
            "file_key": "demo-providerportal-web:src/checkmarx_dscan/application/services/sonar.py",
            "file_path": "src/checkmarx_dscan/application/services/sonar.py",
            "file_name": "sonar.py",
            "coverage_pct": 63.5,
            "line_coverage_pct": 66.0,
            "branch_coverage_pct": 49.0,
            "total_lines_considered": 140,
            "covered_lines_count": 89,
            "uncovered_lines_count": 51,
            "uncovered_line_numbers": [453, 605, 817],
            "covered_line_numbers": [434, 454, 455],
            "priority_score": 34.1,
            "priority": "high",
            "estimated_project_impact_pct": 42.5,
            "should_target_first": True,
            "why": "Improving this file should lift coverage with focused unit or path tests.",
            "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
            "has_executable_coverage_metrics": True,
            "line_number_quality": "estimated",
        },
    ],
    "priority": {
        "top_files_to_target": [
            {
                "rank": 1,
                "file_path": "src/checkmarx_dscan/interfaces/agents/common.py",
                "file_name": "common.py",
                "coverage_pct": 42.0,
                "uncovered_lines_count": 46,
                "uncovered_line_numbers": [85, 93, 147, 190],
                "priority_score": 46.2,
                "priority": "high",
                "expected_coverage_gain_pct": 38.33,
                "why": "This file carries a large uncovered line count relative to the project.",
                "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
            }
        ]
    },
}


_SONAR_FILE_DETAIL = {
    "ok": True,
    "server": "sonar",
    "report_type": "file_coverage_improvement",
    "generated_at": utc_now_iso(),
    "access_mode": "authenticated",
    "project_summary": {
        "project_key": "demo-providerportal-web",
        "branch_name": "release_1",
        "pull_request": "",
    },
    "file": {
        "file_key": "demo-providerportal-web:src/checkmarx_dscan/interfaces/agents/common.py",
        "file_path": "src/checkmarx_dscan/interfaces/agents/common.py",
        "file_name": "common.py",
        "coverage_pct": 42.0,
        "line_coverage_pct": 44.0,
        "branch_coverage_pct": 30.0,
        "total_lines_considered": 80,
        "covered_lines_count": 34,
        "uncovered_lines_count": 46,
        "uncovered_line_numbers": [85, 93, 147, 190],
        "covered_line_numbers": [84, 86, 87],
        "priority_score": 46.2,
        "priority": "high",
        "estimated_project_impact_pct": None,
        "should_target_first": True,
        "why": "This file carries a large uncovered line count relative to the project.",
        "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
        "has_executable_coverage_metrics": True,
        "line_number_quality": "estimated",
    },
    "priority": {
        "top_files_to_target": [
            {
                "rank": 1,
                "file_path": "src/checkmarx_dscan/interfaces/agents/common.py",
                "file_name": "common.py",
                "coverage_pct": 42.0,
                "uncovered_lines_count": 46,
                "uncovered_line_numbers": [85, 93, 147, 190],
                "priority_score": 46.2,
                "priority": "high",
                "why": "This file carries a large uncovered line count relative to the project.",
                "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
            }
        ]
    },
    "permission_gaps": [],
}


_SONAR_LOCAL_REPORT = {
    "ok": True,
    "server": "sonar",
    "operation": "local_report",
    "report_type": "local_coverage_prediction",
    "generated_at": utc_now_iso(),
    "project_summary": {
        "project_key": "local-workspace",
        "project_name": "CheckmarxIntegration",
        "branch_name": "local",
        "pull_request": "",
        "overall_coverage_pct": 86.0,
        "line_coverage_pct": 86.0,
        "branch_coverage_pct": None,
        "total_lines_considered": 100,
        "total_covered_lines": 86,
        "total_uncovered_lines": 14,
        "total_files_analyzed": 2,
        "total_files_with_uncovered_lines": 1,
        "total_files_with_executable_coverage": 2,
    },
    "threshold_pct": 80.0,
    "would_meet_threshold": True,
    "predicted_sonar_outcome": "pass",
    "prediction_basis": "Local pytest coverage via coverage.py. SonarQube can still differ if exclusions, imported reports, or branch settings are different.",
    "workspace_root": ".",
    "test_command": "python -m coverage run -m pytest",
    "source_paths": ["src"],
    "files": [
        {
            "file_key": "src/demo.py",
            "file_path": "src/demo.py",
            "file_name": "demo.py",
            "coverage_pct": 66.67,
            "line_coverage_pct": 66.67,
            "branch_coverage_pct": 25.0,
            "total_lines_considered": 9,
            "covered_lines_count": 6,
            "uncovered_lines_count": 3,
            "uncovered_line_numbers": [5, 6, 7],
            "covered_line_numbers": [1, 2, 3, 4, 8, 9],
            "priority_score": 42.5,
            "priority": "high",
            "estimated_project_impact_pct": 21.43,
            "should_target_first": True,
            "why": "This file carries a large uncovered line count relative to the project.",
            "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
            "has_executable_coverage_metrics": True,
            "line_number_quality": "confirmed",
        }
    ],
    "priority": {
        "top_files_to_target": [
            {
                "rank": 1,
                "file_path": "src/demo.py",
                "file_name": "demo.py",
                "coverage_pct": 66.67,
                "uncovered_lines_count": 3,
                "uncovered_line_numbers": [5, 6, 7],
                "priority_score": 42.5,
                "priority": "high",
                "expected_coverage_gain_pct": 21.43,
                "why": "This file carries a large uncovered line count relative to the project.",
                "suggested_test_focus": "Target decision branches, error paths, and boolean edge cases first.",
            }
        ]
    },
}


def _apply_report_options(payload: dict[str, Any], *, include_raw: bool, profile: str | None = None) -> dict[str, Any]:
    result = deepcopy(payload)
    result["generated_at"] = utc_now_iso()
    resolved_profile = normalize_report_profile(profile)
    if not include_raw:
        result.pop("raw", None)
    if "agent_report" in result and isinstance(result["agent_report"], dict):
        result["agent_report"] = serialize_agent_report(result["agent_report"], resolved_profile)
    if resolved_profile != REPORT_PROFILE_FULL and "findings" in result:
        result.pop("findings", None)
        result["report_profile"] = resolved_profile
    return result


def _update_checkmarx_request(payload: dict[str, Any], *, project: str = "", project_query: str = "", branch: str = "", source: str = "") -> None:
    if payload.get("mode") == "projects":
        query = project_query.strip() or project.strip()
        payload["project_query"] = query
        if query:
            summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
            summary["match_count"] = 1
            payload["summary"] = summary
        return

    request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
    project_info = payload.get("project") if isinstance(payload.get("project"), dict) else {}
    scan_info = payload.get("scan") if isinstance(payload.get("scan"), dict) else {}
    if project.strip():
        request["project_name"] = project.strip()
        project_info["name"] = project.strip()
        if isinstance(payload.get("agent_report"), dict):
            payload["agent_report"]["project_name"] = project.strip()
    if branch.strip():
        request["branch"] = branch.strip()
        project_info["main_branch"] = branch.strip()
        scan_info["branch"] = branch.strip()
        if isinstance(payload.get("agent_report"), dict):
            payload["agent_report"]["branch_name"] = branch.strip()
    if source.strip() and "source_path" in request:
        request["source_path"] = source.strip()


def _update_demo_project_metadata(payload: dict[str, Any], *, source: str = "") -> None:
    demo_project = payload.get("demo_project") if isinstance(payload.get("demo_project"), dict) else None
    if demo_project is None:
        return
    resolved_root = source.strip() or _MOCK_DEMO_PROJECT_ROOT
    demo_project["root"] = resolved_root
    managed_files = []
    for file_name in ("package.json", "package-lock.json", "Dockerfile"):
        managed_files.append(f"{resolved_root.rstrip('/')}/{file_name}")
    demo_project["managed_files"] = managed_files


def load_mock_checkmarx_payload(*, scan_mode: str, include_raw: bool, profile: str | None = None, project: str = "", project_query: str = "", branch: str = "", source: str = "") -> dict[str, Any]:
    if scan_mode == "projects":
        payload = {
            "ok": True,
            "mode": "projects",
            "generated_at": utc_now_iso(),
            "project_query": project_query.strip() or project.strip(),
            "summary": {
                "accessible_projects": len(_CHECKMARX_PROJECTS),
                "match_count": 1,
            },
            "project_resolution": {
                "matched": True,
                "best_match": {
                    "score": 1.0,
                    "match_type": "exact_name",
                    "project": deepcopy(_CHECKMARX_PROJECTS[0]),
                },
            },
            "matches": [
                {
                    "score": 1.0,
                    "match_type": "exact_name",
                    "project": deepcopy(_CHECKMARX_PROJECTS[0]),
                }
            ],
            "projects": deepcopy(_CHECKMARX_PROJECTS),
            "raw": {"projects": deepcopy(_CHECKMARX_PROJECTS)},
        }
    elif scan_mode == "upload":
        payload = _build_checkmarx_report_payload(include_archive=True)
    else:
        payload = _build_checkmarx_report_payload(include_archive=False)
    _update_checkmarx_request(payload, project=project, project_query=project_query, branch=branch, source=source)
    _update_demo_project_metadata(payload, source=source)
    return _apply_report_options(payload, include_raw=include_raw, profile=profile)


def load_mock_jenkins_payload(*, include_raw: bool, profile: str | None = None, job_url: str = "", build_number: int | None = None, artifact_name: str = "", pr_number: int | None = None) -> dict[str, Any]:
    payload = deepcopy(_JENKINS_FIXTURE)
    payload["generated_at"] = utc_now_iso()
    request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
    resolved_job_url = _build_mock_pr_job_url(job_url, pr_number)
    if resolved_job_url:
        request["job_url"] = resolved_job_url
        if isinstance(payload.get("job"), dict):
            payload["job"]["url"] = resolved_job_url
            payload["job"]["name"] = resolved_job_url.rstrip("/").split("/")[-1]
        if isinstance(payload.get("raw"), dict) and isinstance(payload["raw"].get("job"), dict):
            payload["raw"]["job"]["url"] = resolved_job_url
            payload["raw"]["job"]["name"] = resolved_job_url.rstrip("/").split("/")[-1]
    if build_number is not None:
        request["build_number"] = int(build_number)
        if isinstance(payload.get("build"), dict):
            payload["build"]["number"] = int(build_number)
            payload["build"]["url"] = f"{request.get('job_url', payload['build']['url']).rstrip('/')}/{int(build_number)}/"
        if isinstance(payload.get("raw"), dict) and isinstance(payload["raw"].get("build"), dict):
            payload["raw"]["build"]["number"] = int(build_number)
    if artifact_name.strip():
        request["artifact_name"] = artifact_name.strip()
        if isinstance(payload.get("artifact"), dict):
            payload["artifact"]["file_name"] = artifact_name.strip()
        if isinstance(payload.get("summary"), dict):
            payload["summary"]["artifact_name"] = artifact_name.strip()
    if pr_number is not None:
        request["pr_number"] = int(pr_number)
    return _apply_report_options(payload, include_raw=include_raw, profile=profile)


def load_mock_sonar_payload(*, operation: str, include_raw: bool = False, project: str = "", branch: str = "", file_path: str = "", file_key: str = "", coverage_threshold: float | None = None, local_working_directory: str = "", compare_with_remote: bool = False) -> dict[str, Any]:
    if operation == "access_probe":
        payload = deepcopy(_SONAR_ACCESS_PROBE)
    elif operation == "projects":
        payload = deepcopy(_SONAR_PROJECTS)
    elif operation == "file_detail":
        payload = deepcopy(_SONAR_FILE_DETAIL)
    elif operation == "local_report":
        payload = deepcopy(_SONAR_LOCAL_REPORT)
    else:
        payload = deepcopy(_SONAR_REMOTE_REPORT)

    payload["generated_at"] = utc_now_iso()
    project_summary = payload.get("project_summary") if isinstance(payload.get("project_summary"), dict) else None
    if project_summary is not None and project.strip():
        project_summary["project_key"] = project.strip()
        if "project_name" in project_summary:
            project_summary["project_name"] = project.strip()
    if project_summary is not None and branch.strip():
        project_summary["branch_name"] = branch.strip()
    if operation == "file_detail":
        file_entry = payload.get("file") if isinstance(payload.get("file"), dict) else {}
        resolved_path = file_path.strip() or file_entry.get("file_path") or "src/checkmarx_dscan/interfaces/agents/common.py"
        resolved_key = file_key.strip() or file_entry.get("file_key") or f"{project.strip() or 'demo-providerportal-web'}:{resolved_path}"
        file_entry["file_path"] = resolved_path
        file_entry["file_key"] = resolved_key
        file_entry["file_name"] = resolved_path.replace("\\", "/").split("/")[-1]
        payload["file"] = file_entry
        priority = payload.get("priority") if isinstance(payload.get("priority"), dict) else {}
        top = priority.get("top_files_to_target") if isinstance(priority.get("top_files_to_target"), list) and priority.get("top_files_to_target") else []
        if top:
            top[0]["file_path"] = resolved_path
            top[0]["file_name"] = file_entry["file_name"]
    if operation == "local_report":
        if coverage_threshold is not None:
            payload["threshold_pct"] = float(coverage_threshold)
            overall = payload.get("project_summary", {}).get("overall_coverage_pct")
            if isinstance(overall, (int, float)):
                payload["would_meet_threshold"] = float(overall) >= float(coverage_threshold)
                payload["predicted_sonar_outcome"] = "pass" if payload["would_meet_threshold"] else "fail"
        if local_working_directory.strip():
            payload["workspace_root"] = local_working_directory.strip()
        if compare_with_remote:
            payload["remote_comparison"] = {
                "remote_project_summary": deepcopy(_SONAR_REMOTE_REPORT["project_summary"]),
                "local_minus_remote_coverage_pct": round(float(payload["project_summary"]["overall_coverage_pct"]) - float(_SONAR_REMOTE_REPORT["project_summary"]["overall_coverage_pct"]), 2),
            }
    if not include_raw:
        payload.pop("raw", None)
    return payload