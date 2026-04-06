from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.infrastructure.serialization.json import resolve_output_path, write_output_json


class SerializationTests(unittest.TestCase):
	def test_resolve_output_path_places_relative_files_under_output_directory(self) -> None:
		with tempfile.TemporaryDirectory() as temp_dir:
			base = Path(temp_dir)
			with mock.patch("checkmarx_dscan.infrastructure.serialization.json.get_output_directory", return_value=base / "output"):
				resolved = resolve_output_path("report.json")

		self.assertEqual(resolved, base / "output" / "report.json")

	def test_resolve_output_path_uses_default_name_for_directory_like_path(self) -> None:
		with tempfile.TemporaryDirectory() as temp_dir:
			base = Path(temp_dir)
			with mock.patch("checkmarx_dscan.infrastructure.serialization.json.get_output_directory", return_value=base / "output"):
				resolved = resolve_output_path("jenkins-run", default_file_name="jenkins_artifact_report.json")

		self.assertEqual(resolved, base / "output" / "jenkins-run" / "jenkins_artifact_report.json")

	def test_resolve_output_path_does_not_duplicate_output_prefix(self) -> None:
		with tempfile.TemporaryDirectory() as temp_dir:
			base = Path(temp_dir)
			with mock.patch("checkmarx_dscan.infrastructure.serialization.json.get_workspace_root", return_value=base), \
				mock.patch("checkmarx_dscan.infrastructure.serialization.json.get_output_directory", return_value=base / "output"):
				resolved = resolve_output_path("output/latest_auto_report.json")

		self.assertEqual(resolved, base / "output" / "latest_auto_report.json")

	def test_write_output_json_creates_parent_directories_under_output(self) -> None:
		with tempfile.TemporaryDirectory() as temp_dir:
			base = Path(temp_dir)
			with mock.patch("checkmarx_dscan.infrastructure.serialization.json.get_output_directory", return_value=base / "output"):
				path = write_output_json("scan-run", {"summary": {"total_findings": 0}}, default_file_name="checkmarx_scan_report.json")
				self.assertTrue(path.exists())
				self.assertEqual(path, base / "output" / "scan-run" / "checkmarx_scan_report.json")


if __name__ == "__main__":
	unittest.main()