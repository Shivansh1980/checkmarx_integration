from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib import parse as urlparse

from ..domain.constants import SCAN_TYPE_ALIASES, TOKEN_ENDPOINT_SUFFIX
from ..domain.errors import CheckmarxError


def _iter_env_search_paths(env_path: str) -> list[Path]:
    requested = Path(env_path).expanduser()
    if requested.is_absolute():
        return [requested]

    candidates: list[Path] = []
    seen: set[Path] = set()
    search_roots = [Path.cwd(), *Path.cwd().parents, *Path(__file__).resolve().parents]
    for root in search_roots:
        candidate = (root / requested).resolve()
        if candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates


def load_env_file(env_path: str) -> None:
    path = next((candidate for candidate in _iter_env_search_paths(env_path) if candidate.is_file()), None)
    if path is None:
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue

        if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()

        os.environ.setdefault(key, value)


def first_non_empty(*values: str | None) -> str:
    for value in values:
        if value is None:
            continue
        stripped = value.strip()
        if stripped:
            return stripped
    return ""


def join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def with_query(url: str, params: dict[str, Any]) -> str:
    parts = list(urlparse.urlsplit(url))
    query = dict(urlparse.parse_qsl(parts[3], keep_blank_values=True))
    for key, value in params.items():
        if value is None:
            continue
        query[key] = str(value)
    parts[3] = urlparse.urlencode(query)
    return urlparse.urlunsplit(parts)


def sanitize_url(url: str) -> str:
    parts = urlparse.urlsplit(url)
    return urlparse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}

    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("utf-8"))
        claims = json.loads(decoded.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}

    return claims if isinstance(claims, dict) else {}


def claim_as_string(token: str, claim_name: str) -> str:
    value = decode_jwt_claims(token).get(claim_name)
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        options = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        if not options:
            return ""
        url_option = next((item for item in options if "://" in item), "")
        return url_option or options[0]
    return ""


def ensure_token_endpoint(url: str, tenant: str = "") -> str:
    cleaned = (url or "").strip().rstrip("/")
    if not cleaned:
        return ""
    if cleaned.endswith(TOKEN_ENDPOINT_SUFFIX):
        return cleaned
    if cleaned.endswith("/auth") and tenant:
        cleaned = f"{cleaned}/realms/{tenant.lower()}"
    elif "/realms/" not in cleaned and tenant:
        cleaned = f"{cleaned}/auth/realms/{tenant.lower()}"
    return f"{cleaned}/{TOKEN_ENDPOINT_SUFFIX}"


def to_int(value: Any, default: int | None = 0) -> int | None:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def to_float(value: Any, default: float | None = None) -> float | None:
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def pick(mapping: dict[str, Any] | None, *keys: str, default: Any = None) -> Any:
    if not isinstance(mapping, dict):
        return default
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def pick_str(mapping: dict[str, Any] | None, *keys: str, default: str = "") -> str:
    value = pick(mapping, *keys, default=default)
    if value is None:
        return default
    return str(value).strip()


def truncate(text: str, limit: int) -> str:
    cleaned = " ".join((text or "").split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{size} B"


def normalize_scan_types(raw_value: str | Iterable[str]) -> list[str]:
    if isinstance(raw_value, str):
        candidates = raw_value.replace(";", ",").split(",")
    else:
        candidates = [str(item) for item in raw_value]

    seen: set[str] = set()
    normalized: list[str] = []
    for item in candidates:
        candidate = item.strip().lower()
        if not candidate:
            continue
        if candidate not in SCAN_TYPE_ALIASES:
            allowed = ", ".join(sorted(SCAN_TYPE_ALIASES))
            raise CheckmarxError(f"Unsupported scan type '{candidate}'. Allowed values: {allowed}")
        scan_type = SCAN_TYPE_ALIASES[candidate]
        if scan_type not in seen:
            normalized.append(scan_type)
            seen.add(scan_type)

    if not normalized:
        raise CheckmarxError("At least one scan type is required")
    return normalized


def compact_dict(mapping: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in mapping.items()
        if value not in (None, "", [], {}, ())
    }


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        cleaned = str(value).strip()
        if not cleaned or cleaned in seen:
            continue
        deduped.append(cleaned)
        seen.add(cleaned)
    return deduped


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
