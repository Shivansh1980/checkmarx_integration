from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterable
from zipfile import ZIP_DEFLATED, ZipFile

from ...domain.constants import DEFAULT_EXCLUDED_DIRS
from ...domain.errors import CheckmarxError


def iter_source_files(source_root: Path) -> Iterable[Path]:
	for root, dirs, files in os.walk(source_root):
		dirs[:] = [directory for directory in dirs if directory not in DEFAULT_EXCLUDED_DIRS]
		for filename in files:
			yield Path(root) / filename


def build_zip_archive(source_path: Path) -> tuple[Path, bool]:
	source_path = source_path.resolve()
	if source_path.is_file() and source_path.suffix.lower() == ".zip":
		return source_path, False

	fd, archive_name = tempfile.mkstemp(prefix="checkmarx-scan-", suffix=".zip")
	os.close(fd)
	archive_path = Path(archive_name)
	files_added = 0
	try:
		with ZipFile(archive_path, mode="w", compression=ZIP_DEFLATED) as archive:
			if source_path.is_file():
				archive.write(source_path, arcname=source_path.name)
				files_added = 1
			else:
				for file_path in iter_source_files(source_path):
					archive.write(file_path, arcname=file_path.relative_to(source_path).as_posix())
					files_added += 1
		if files_added == 0:
			raise CheckmarxError("The selected source path did not produce any files for the upload archive")
		return archive_path, True
	except Exception:
		archive_path.unlink(missing_ok=True)
		raise
