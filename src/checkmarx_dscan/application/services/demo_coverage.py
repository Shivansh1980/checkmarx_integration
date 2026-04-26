"""Helpers for surfacing the demo project's real Jest coverage in mock mode.

When the bundled demo project under ``demo/mock_providerportal_web`` has been
exercised with ``npm test`` (which runs Jest with ``--coverage``), it produces
two artefacts that this module reads:

* ``coverage/coverage-summary.json`` — overall and per-file coverage summary.
* ``coverage/lcov.info`` — per-line hit counts (line-level detail).

The mock SonarQube tool overlays these real numbers onto its canned response
so a demo can show:

1. Initial low coverage that fails the quality gate.
2. The exact uncovered line numbers an agent should target.
3. The same tool reporting a passing gate after tests are added.

If the demo project has not been built yet (no ``coverage/`` folder), this
module returns ``None`` and the caller keeps using the static fixture.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


_DEFAULT_DEMO_RELATIVE_ROOT = Path("demo") / "mock_providerportal_web"


def _candidate_workspace_roots() -> list[Path]:
    roots: list[Path] = []
    cwd = Path.cwd().resolve()
    roots.append(cwd)
    for parent in cwd.parents:
        roots.append(parent)
    here = Path(__file__).resolve()
    for parent in here.parents:
        roots.append(parent)
    seen: set[Path] = set()
    deduped: list[Path] = []
    for candidate in roots:
        if candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def _resolve_demo_root() -> Path | None:
    override = os.getenv("CHECKMARX_DSCAN_DEMO_PROJECT_ROOT")
    if override and override.strip():
        candidate = Path(override).expanduser().resolve()
        if candidate.is_dir():
            return candidate
    for root in _candidate_workspace_roots():
        candidate = root / _DEFAULT_DEMO_RELATIVE_ROOT
        if candidate.is_dir():
            return candidate
    return None


def _normalize_relative_path(absolute_path: str, demo_root: Path) -> str:
    raw = str(absolute_path or "").replace("\\", "/")
    if not raw:
        return ""
    try:
        relative = Path(absolute_path).resolve().relative_to(demo_root)
    except (OSError, ValueError):
        marker = "demo/mock_providerportal_web/"
        idx = raw.lower().find(marker.lower())
        if idx >= 0:
            return raw[idx + len(marker):]
        return raw
    return relative.as_posix()


def _parse_lcov(lcov_path: Path, demo_root: Path) -> dict[str, dict[str, list[int]]]:
    """Return ``{relative_path: {"covered": [...], "uncovered": [...]}}``.

    ``lcov.info`` records line hit counts as ``DA:<line>,<hits>`` blocks under
    a ``SF:<absolute_path>`` header. Anything that cannot be parsed is skipped.
    """
    if not lcov_path.is_file():
        return {}
    try:
        text = lcov_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    result: dict[str, dict[str, list[int]]] = {}
    current_file: str | None = None
    covered: list[int] = []
    uncovered: list[int] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("SF:"):
            if current_file is not None:
                result[current_file] = {"covered": sorted(set(covered)), "uncovered": sorted(set(uncovered))}
            current_file = _normalize_relative_path(line[3:], demo_root)
            covered = []
            uncovered = []
            continue
        if line == "end_of_record":
            if current_file is not None:
                result[current_file] = {"covered": sorted(set(covered)), "uncovered": sorted(set(uncovered))}
            current_file = None
            covered = []
            uncovered = []
            continue
        if current_file is None:
            continue
        if line.startswith("DA:"):
            payload = line[3:]
            parts = payload.split(",")
            if len(parts) < 2:
                continue
            try:
                line_number = int(parts[0])
                hits = int(parts[1])
            except ValueError:
                continue
            if hits > 0:
                covered.append(line_number)
            else:
                uncovered.append(line_number)
    if current_file is not None and current_file not in result:
        result[current_file] = {"covered": sorted(set(covered)), "uncovered": sorted(set(uncovered))}
    return result


def _safe_pct(value: Any) -> float | None:
    try:
        if isinstance(value, str) and value.lower() == "unknown":
            return None
        return round(float(value), 2)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def load_demo_jest_coverage(demo_root: Path | None = None) -> dict[str, Any] | None:
    """Return normalized coverage data for the demo project, or ``None``.

    The shape returned mirrors what the mock SonarQube fixture expects, so
    callers can splice it into the ``project_summary``/``files``/``priority``
    sections without further conversion.
    """
    resolved_root = demo_root if demo_root is not None else _resolve_demo_root()
    if resolved_root is None:
        return None
    summary_path = resolved_root / "coverage" / "coverage-summary.json"
    lcov_path = resolved_root / "coverage" / "lcov.info"
    if not summary_path.is_file():
        return None
    try:
        summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(summary_payload, dict):
        return None

    totals = summary_payload.get("total") if isinstance(summary_payload.get("total"), dict) else {}
    statements = totals.get("statements") if isinstance(totals.get("statements"), dict) else {}
    lines_total = totals.get("lines") if isinstance(totals.get("lines"), dict) else {}
    branches_total = totals.get("branches") if isinstance(totals.get("branches"), dict) else {}
    functions_total = totals.get("functions") if isinstance(totals.get("functions"), dict) else {}

    overall_pct = _safe_pct(statements.get("pct"))
    line_pct = _safe_pct(lines_total.get("pct"))
    branch_pct = _safe_pct(branches_total.get("pct"))
    functions_pct = _safe_pct(functions_total.get("pct"))

    total_lines_considered = _safe_int(statements.get("total")) or _safe_int(lines_total.get("total"))
    total_covered_lines = _safe_int(statements.get("covered")) or _safe_int(lines_total.get("covered"))
    total_uncovered_lines = max(0, total_lines_considered - total_covered_lines)

    line_details = _parse_lcov(lcov_path, resolved_root)

    files: list[dict[str, Any]] = []
    files_with_uncovered = 0
    for absolute_path, file_summary in summary_payload.items():
        if absolute_path == "total" or not isinstance(file_summary, dict):
            continue
        relative_path = _normalize_relative_path(absolute_path, resolved_root)
        if not relative_path:
            continue
        file_statements = file_summary.get("statements") if isinstance(file_summary.get("statements"), dict) else {}
        file_lines = file_summary.get("lines") if isinstance(file_summary.get("lines"), dict) else {}
        file_branches = file_summary.get("branches") if isinstance(file_summary.get("branches"), dict) else {}

        file_total = _safe_int(file_statements.get("total")) or _safe_int(file_lines.get("total"))
        file_covered = _safe_int(file_statements.get("covered")) or _safe_int(file_lines.get("covered"))
        file_uncovered = max(0, file_total - file_covered)
        file_coverage_pct = _safe_pct(file_statements.get("pct"))
        if file_coverage_pct is None:
            file_coverage_pct = _safe_pct(file_lines.get("pct"))
        file_branch_pct = _safe_pct(file_branches.get("pct"))

        line_info = line_details.get(relative_path, {"covered": [], "uncovered": []})
        uncovered_line_numbers = list(line_info.get("uncovered", []))
        covered_line_numbers = list(line_info.get("covered", []))

        if file_uncovered > 0:
            files_with_uncovered += 1

        files.append(
            {
                "file_path": relative_path,
                "file_name": relative_path.split("/")[-1],
                "coverage_pct": file_coverage_pct,
                "line_coverage_pct": _safe_pct(file_lines.get("pct")),
                "branch_coverage_pct": file_branch_pct,
                "total_lines_considered": file_total,
                "covered_lines_count": file_covered,
                "uncovered_lines_count": file_uncovered,
                "uncovered_line_numbers": uncovered_line_numbers,
                "covered_line_numbers": covered_line_numbers,
                "has_executable_coverage_metrics": file_total > 0,
                "line_number_quality": "confirmed" if uncovered_line_numbers or covered_line_numbers else "unavailable",
            }
        )

    files.sort(key=lambda item: (-int(item["uncovered_lines_count"] or 0), item["file_path"]))

    return {
        "demo_root": str(resolved_root),
        "overall_coverage_pct": overall_pct,
        "line_coverage_pct": line_pct,
        "branch_coverage_pct": branch_pct,
        "functions_coverage_pct": functions_pct,
        "total_lines_considered": total_lines_considered,
        "total_covered_lines": total_covered_lines,
        "total_uncovered_lines": total_uncovered_lines,
        "total_files_analyzed": len(files),
        "total_files_with_uncovered_lines": files_with_uncovered,
        "total_files_with_executable_coverage": len([item for item in files if item["has_executable_coverage_metrics"]]),
        "files": files,
    }


__all__ = ["load_demo_jest_coverage"]
