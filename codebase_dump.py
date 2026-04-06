#!/usr/bin/env python3
"""
Codebase Dumper / Loader

Serialize the entire project into a single text file and restore it back
to the exact same folder structure with identical content.

Usage:
    python codebase_dump.py dump                      # dumps to codebase_dump.txt
    python codebase_dump.py dump -o my_dump.txt       # dumps to custom file
    python codebase_dump.py load codebase_dump.txt    # restores into ./restored/
    python codebase_dump.py load codebase_dump.txt -o /path/to/target  # custom target
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path


# ─── Configuration ───────────────────────────────────────────────────────────

# Directories to always skip (anywhere in the tree).
EXCLUDED_DIRS: frozenset[str] = frozenset({
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "env",
    "ENV",
    "node_modules",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".eggs",
    "build",
    "dist",
    "htmlcov",
    ".vscode",
    "output",
})

# Exact file names to skip (matched at any level).
EXCLUDED_FILES: frozenset[str] = frozenset({
    ".env",
    ".coverage",
    "Thumbs.db",
    "Desktop.ini",
    "codebase_dump.py",   # don't bundle ourselves
    "codebase_dump.txt",  # don't bundle a previous dump
})

# Glob suffixes to skip.
EXCLUDED_SUFFIXES: tuple[str, ...] = (
    ".pyc",
    ".pyo",
    ".pyd",
    ".egg-info",
)

# Filename patterns to skip.
EXCLUDED_PATTERNS: tuple[str, ...] = (
    ".env.",      # .env.local, .env.production, etc.
)

# Top-level directory names to skip entirely.
EXCLUDED_TOP_DIRS: frozenset[str] = frozenset({
    "output",
    ".vscode",
})

# ─── Format constants ────────────────────────────────────────────────────────

DUMP_HEADER = "### CODEBASE DUMP v1 ###"
FILE_BEGIN  = "===== FILE_BEGIN ====="
FILE_END    = "===== FILE_END ====="
METADATA_SEPARATOR = "--- CONTENT ---"


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _should_exclude_dir(dir_name: str, rel_parts: tuple[str, ...]) -> bool:
    """Return True if a directory should be skipped during walk."""
    if dir_name in EXCLUDED_DIRS:
        return True
    # Any path component ending with .egg-info
    if dir_name.endswith(".egg-info"):
        return True
    # Top-level exclusions
    if len(rel_parts) == 0 and dir_name in EXCLUDED_TOP_DIRS:
        return True
    return False


def _should_exclude_file(file_name: str, rel_path: str) -> bool:
    """Return True if a file should be skipped."""
    if file_name in EXCLUDED_FILES:
        return True
    for suffix in EXCLUDED_SUFFIXES:
        if file_name.endswith(suffix):
            return True
    for pattern in EXCLUDED_PATTERNS:
        if pattern in file_name:
            return True
    # Skip anything inside a .egg-info directory
    if ".egg-info" in rel_path:
        return True
    return False


def _is_binary(data: bytes) -> bool:
    """Heuristic: if the first 8 KB contain a null byte, treat as binary."""
    return b"\x00" in data[:8192]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─── Dump ────────────────────────────────────────────────────────────────────

def collect_files(root: Path) -> list[Path]:
    """Walk the project tree and return sorted list of files to include."""
    collected: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        rel_to_root = current.relative_to(root)
        rel_parts = rel_to_root.parts

        # Prune excluded directories in-place so os.walk doesn't descend.
        dirnames[:] = sorted(
            d for d in dirnames
            if not _should_exclude_dir(d, rel_parts)
        )

        for fname in sorted(filenames):
            rel_file = (rel_to_root / fname).as_posix()
            if _should_exclude_file(fname, rel_file):
                continue
            collected.append(current / fname)

    return collected


def dump_codebase(root: Path, output_path: Path) -> None:
    """Serialize all project files into a single text dump."""
    root = root.resolve()
    files = collect_files(root)

    if not files:
        print("No files found to dump.", file=sys.stderr)
        raise SystemExit(1)

    lines: list[str] = []
    lines.append(DUMP_HEADER)
    lines.append(f"root: {root.name}")
    lines.append(f"file_count: {len(files)}")
    lines.append("")

    for filepath in files:
        rel = filepath.relative_to(root).as_posix()
        raw = filepath.read_bytes()
        checksum = _sha256(raw)
        binary = _is_binary(raw)

        lines.append(FILE_BEGIN)
        lines.append(f"path: {rel}")
        lines.append(f"size: {len(raw)}")
        lines.append(f"sha256: {checksum}")
        lines.append(f"encoding: {'base64' if binary else 'utf-8'}")
        lines.append(METADATA_SEPARATOR)

        if binary:
            # Base64-encode binary files, wrap at 76 chars.
            encoded = base64.b64encode(raw).decode("ascii")
            for i in range(0, len(encoded), 76):
                lines.append(encoded[i : i + 76])
        else:
            # Store text content as-is. Normalize line endings to \n for the
            # dump file, but the original bytes are what the checksum covers,
            # so we re-encode from the decoded text on restore.
            text = raw.decode("utf-8")
            # Ensure no trailing newline ambiguity: store exactly what's there.
            lines.append(text)

        lines.append(FILE_END)
        lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")

    print(f"Dumped {len(files)} files from '{root}' into '{output_path}'")
    print(f"Dump size: {output_path.stat().st_size:,} bytes")


# ─── Load ────────────────────────────────────────────────────────────────────

def load_codebase(dump_path: Path, target_dir: Path) -> None:
    """Deserialize a dump file back into the original folder structure."""
    dump_path = dump_path.resolve()
    if not dump_path.is_file():
        print(f"Dump file not found: {dump_path}", file=sys.stderr)
        raise SystemExit(1)

    content = dump_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    if not lines or lines[0].strip() != DUMP_HEADER:
        print("Invalid dump file: missing header.", file=sys.stderr)
        raise SystemExit(1)

    # Parse header.
    root_name = ""
    expected_count = 0
    idx = 1
    while idx < len(lines):
        line = lines[idx].strip()
        if line == "":
            idx += 1
            break
        if line.startswith("root: "):
            root_name = line[len("root: "):]
        elif line.startswith("file_count: "):
            expected_count = int(line[len("file_count: "):])
        idx += 1

    # The restore root is target_dir / original_root_name.
    restore_root = target_dir.resolve() / root_name if root_name else target_dir.resolve()
    restore_root.mkdir(parents=True, exist_ok=True)

    restored = 0
    errors: list[str] = []

    while idx < len(lines):
        line = lines[idx].strip()

        # Skip blank lines between file blocks.
        if line == "":
            idx += 1
            continue

        if line != FILE_BEGIN:
            idx += 1
            continue

        # Parse file metadata.
        idx += 1
        file_path = ""
        file_size = 0
        file_sha256 = ""
        file_encoding = "utf-8"

        while idx < len(lines):
            meta_line = lines[idx]
            if meta_line.strip() == METADATA_SEPARATOR:
                idx += 1
                break
            if meta_line.startswith("path: "):
                file_path = meta_line[len("path: "):]
            elif meta_line.startswith("size: "):
                file_size = int(meta_line[len("size: "):])
            elif meta_line.startswith("sha256: "):
                file_sha256 = meta_line[len("sha256: "):]
            elif meta_line.startswith("encoding: "):
                file_encoding = meta_line[len("encoding: "):].strip()
            idx += 1

        if not file_path:
            continue

        # Collect content lines until FILE_END.
        content_lines: list[str] = []
        while idx < len(lines):
            if lines[idx].rstrip("\r\n") == FILE_END:
                idx += 1
                break
            content_lines.append(lines[idx])
            idx += 1

        # Reconstruct file bytes.
        if file_encoding == "base64":
            encoded_str = "".join(line.strip() for line in content_lines)
            raw = base64.b64decode(encoded_str)
        else:
            # The content was stored with \n joins. Rejoin exactly.
            text = "\n".join(content_lines)
            raw = text.encode("utf-8")

        # Verify checksum.
        actual_sha256 = _sha256(raw)
        if file_sha256 and actual_sha256 != file_sha256:
            errors.append(
                f"  CHECKSUM MISMATCH: {file_path}\n"
                f"    expected: {file_sha256}\n"
                f"    actual:   {actual_sha256}"
            )

        # Write file.
        dest = restore_root / file_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        restored += 1

    print(f"Restored {restored} files into '{restore_root}'")
    if expected_count and restored != expected_count:
        print(
            f"WARNING: expected {expected_count} files but restored {restored}",
            file=sys.stderr,
        )
    if errors:
        print(f"\n{len(errors)} checksum error(s):", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        raise SystemExit(1)
    else:
        print("All checksums verified OK.")


# ─── Verify ──────────────────────────────────────────────────────────────────

def verify_dump(root: Path, dump_path: Path) -> None:
    """Compare the original codebase against a dump file to ensure fidelity."""
    root = root.resolve()
    dump_path = dump_path.resolve()

    if not dump_path.is_file():
        print(f"Dump file not found: {dump_path}", file=sys.stderr)
        raise SystemExit(1)

    # Collect original files.
    original_files = collect_files(root)
    original_map: dict[str, bytes] = {}
    for f in original_files:
        rel = f.relative_to(root).as_posix()
        original_map[rel] = f.read_bytes()

    # Parse dump to get the stored checksums.
    content = dump_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    dumped_paths: set[str] = set()
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        if line == FILE_BEGIN:
            idx += 1
            file_path = ""
            file_sha256 = ""
            while idx < len(lines):
                meta_line = lines[idx]
                if meta_line.strip() == METADATA_SEPARATOR:
                    idx += 1
                    break
                if meta_line.startswith("path: "):
                    file_path = meta_line[len("path: "):]
                elif meta_line.startswith("sha256: "):
                    file_sha256 = meta_line[len("sha256: "):]
                idx += 1
            if file_path:
                dumped_paths.add(file_path)
            # Skip content.
            while idx < len(lines):
                if lines[idx].rstrip("\r\n") == FILE_END:
                    idx += 1
                    break
                idx += 1
        else:
            idx += 1

    missing_from_dump = set(original_map.keys()) - dumped_paths
    extra_in_dump = dumped_paths - set(original_map.keys())
    ok = True

    if missing_from_dump:
        print(f"Files in codebase but MISSING from dump ({len(missing_from_dump)}):")
        for p in sorted(missing_from_dump):
            print(f"  - {p}")
        ok = False

    if extra_in_dump:
        print(f"Files in dump but NOT in codebase ({len(extra_in_dump)}):")
        for p in sorted(extra_in_dump):
            print(f"  + {p}")
        ok = False

    if ok:
        print(
            f"Verification passed: {len(original_map)} files in codebase, "
            f"{len(dumped_paths)} files in dump. All matched."
        )
    else:
        raise SystemExit(1)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Serialize / restore a codebase to / from a single text file.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # dump
    dump_parser = subparsers.add_parser("dump", help="Dump the codebase into a single text file.")
    dump_parser.add_argument(
        "-r", "--root",
        default=".",
        help="Project root directory (default: current directory).",
    )
    dump_parser.add_argument(
        "-o", "--output",
        default="codebase_dump.txt",
        help="Output dump file path (default: codebase_dump.txt).",
    )

    # load
    load_parser = subparsers.add_parser("load", help="Restore a codebase from a dump file.")
    load_parser.add_argument(
        "dump_file",
        help="Path to the dump text file.",
    )
    load_parser.add_argument(
        "-o", "--output",
        default="restored",
        help="Target directory for the restored codebase (default: ./restored/).",
    )

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify a dump matches the current codebase.")
    verify_parser.add_argument(
        "-r", "--root",
        default=".",
        help="Project root directory (default: current directory).",
    )
    verify_parser.add_argument(
        "dump_file",
        nargs="?",
        default="codebase_dump.txt",
        help="Dump file to verify against (default: codebase_dump.txt).",
    )

    args = parser.parse_args(argv)

    if args.command == "dump":
        dump_codebase(Path(args.root), Path(args.output))
    elif args.command == "load":
        load_codebase(Path(args.dump_file), Path(args.output))
    elif args.command == "verify":
        verify_dump(Path(args.root), Path(args.dump_file))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
