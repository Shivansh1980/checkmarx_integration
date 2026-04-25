from __future__ import annotations

import argparse
import filecmp
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "demo" / "mock_providerportal_web"
VULNERABLE_TEMPLATE_ROOT = DEMO_ROOT / ".mock_templates" / "vulnerable"
MANAGED_FILES = ["package.json", "package-lock.json", "Dockerfile"]
MANAGED_FILES = ["package.json", "package-lock.json", "Dockerfile", "src/server.js"]


def _copy_vulnerable_baseline() -> list[Path]:
    updated_files: list[Path] = []
    for relative_name in MANAGED_FILES:
        source = VULNERABLE_TEMPLATE_ROOT / relative_name
        target = DEMO_ROOT / relative_name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        updated_files.append(target)
    return updated_files


def _status_text() -> str:
    for relative_name in MANAGED_FILES:
        source = VULNERABLE_TEMPLATE_ROOT / relative_name
        target = DEMO_ROOT / relative_name
        if not target.exists():
            return "missing"
        if not filecmp.cmp(source, target, shallow=False):
            return "modified"
    return "vulnerable"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the resettable mock demo project used by mock Checkmarx findings.")
    parser.add_argument("command", choices=["status", "inject", "reset"], help="status reports the current state; inject/reset restore the vulnerable baseline")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "status":
        print(_status_text())
        return 0

    updated_files = _copy_vulnerable_baseline()
    print("Restored vulnerable mock demo project:")
    for file_path in updated_files:
        print(f"- {file_path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())