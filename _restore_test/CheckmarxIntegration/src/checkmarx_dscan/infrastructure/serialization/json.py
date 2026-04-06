from __future__ import annotations

import json
from pathlib import Path
from typing import Any


OUTPUT_DIRECTORY_NAME = "output"


def get_workspace_root() -> Path:
	return Path(__file__).resolve().parents[4]


def get_output_directory() -> Path:
	return get_workspace_root() / OUTPUT_DIRECTORY_NAME


def resolve_output_path(output_path: str | Path, default_file_name: str = "report.json") -> Path:
	path = Path(output_path).expanduser()
	if not path.is_absolute():
		output_dir = get_output_directory()
		parts = path.parts
		if parts and parts[0] == OUTPUT_DIRECTORY_NAME:
			path = get_workspace_root() / path
		else:
			path = output_dir / path
	if path.suffix == "":
		path = path / default_file_name
	return path


def dumps_json(payload: dict[str, Any]) -> str:
	return json.dumps(payload, indent=2, ensure_ascii=False)


def write_output_json(output_path: str | Path, payload: dict[str, Any], *, default_file_name: str = "report.json") -> Path:
	path = resolve_output_path(output_path, default_file_name=default_file_name)
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(dumps_json(payload), encoding="utf-8")
	return path
