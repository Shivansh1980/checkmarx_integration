from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.config.resolvers import (
    load_env_file,
    resolve_credentials,
    resolve_data_source,
    resolve_data_source_for,
    resolve_jenkins_artifact_request,
    resolve_jenkins_credentials,
    resolve_project_scan_request,
    resolve_scan_request,
)
from checkmarx_dscan.domain.errors import CheckmarxError, JenkinsError


class ResolveConfigTests(unittest.TestCase):
    def test_resolve_scan_request_normalizes_aliases(self) -> None:
        request = resolve_scan_request(
            project_name="demo-project",
            source=str(ROOT),
            scan_types="sast, iac-security, sca",
        )
        self.assertEqual(request.scan_types, ["sast", "kics", "sca"])

    def test_resolve_credentials_requires_token(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(CheckmarxError):
                resolve_credentials()

    def test_resolve_jenkins_credentials_require_matching_username_and_token(self) -> None:
        with mock.patch.dict(os.environ, {"JENKINS_API_TOKEN": "token-only"}, clear=True):
            with self.assertRaises(JenkinsError):
                resolve_jenkins_credentials()

    def test_resolve_jenkins_artifact_request_uses_default_artifact_name(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "JENKINS_BASE_URL": "http://jenkins.example",
                "JENKINS_JOB_URL": "job/demo/job/release_1",
            },
            clear=True,
        ):
            request = resolve_jenkins_artifact_request()
        self.assertEqual(request.job_url, "http://jenkins.example/job/demo/job/release_1")
        self.assertEqual(request.artifact_name, "checkmarx-ast-results.json")

    def test_resolve_jenkins_artifact_request_uses_fallback_build_lookback(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "JENKINS_BASE_URL": "http://jenkins.example",
                "JENKINS_JOB_URL": "job/demo/job/release_1",
                "JENKINS_FALLBACK_BUILDS": "7",
            },
            clear=True,
        ):
            request = resolve_jenkins_artifact_request()
        self.assertEqual(request.fallback_build_lookback, 7)

    def test_resolve_jenkins_artifact_request_reads_pr_number(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "JENKINS_BASE_URL": "http://jenkins.example",
                "JENKINS_JOB_URL": "view/change-requests",
                "JENKINS_PR_NUMBER": "112",
            },
            clear=True,
        ):
            request = resolve_jenkins_artifact_request()
        self.assertEqual(request.pr_number, 112)

    def test_resolve_project_scan_request_uses_defaults(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            request = resolve_project_scan_request(project_name="demo-project")
        self.assertEqual(request.project_name, "demo-project")
        self.assertEqual(request.branch, "")
        self.assertTrue(request.prefer_terminal_scan)

    def test_resolve_data_source_uses_environment_only(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True):
            resolved = resolve_data_source()
        self.assertEqual(resolved, "live")

    def test_resolve_data_source_defaults_to_mock(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            resolved = resolve_data_source()
        self.assertEqual(resolved, "mock")

    def test_resolve_data_source_rejects_invalid_environment_value(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKMARX_DSCAN_DATA_SOURCE": "demo"}, clear=True):
            with self.assertRaises(CheckmarxError):
                resolve_data_source()

    def test_resolve_data_source_for_uses_per_tool_override_when_present(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "CHECKMARX_DSCAN_DATA_SOURCE": "live",
                "CHECKMARX_DSCAN_DATA_SOURCE_JENKINS": "mock",
                "CHECKMARX_DSCAN_DATA_SOURCE_SONAR": "mock",
            },
            clear=True,
        ):
            self.assertEqual(resolve_data_source_for("checkmarx"), "live")
            self.assertEqual(resolve_data_source_for("jenkins"), "mock")
            self.assertEqual(resolve_data_source_for("sonar"), "mock")

    def test_resolve_data_source_for_falls_back_to_global(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True):
            self.assertEqual(resolve_data_source_for("jenkins"), "live")
            self.assertEqual(resolve_data_source_for("sonar"), "live")

    def test_resolve_data_source_for_rejects_invalid_override(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"CHECKMARX_DSCAN_DATA_SOURCE_JENKINS": "demo"},
            clear=True,
        ):
            with self.assertRaises(CheckmarxError):
                resolve_data_source_for("jenkins")

    def test_load_env_file_searches_parent_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            nested = root / "deep" / "child"
            nested.mkdir(parents=True)
            env_path = root / ".env"
            env_path.write_text("CHECKMARX_API_TOKEN=from-parent\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {}, clear=True):
                original_cwd = Path.cwd()
                try:
                    os.chdir(nested)
                    load_env_file(".env")
                    self.assertEqual(os.getenv("CHECKMARX_API_TOKEN"), "from-parent")
                finally:
                    os.chdir(original_cwd)

    def test_load_env_file_uses_configured_env_file_override(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env_path = root / "workspace.env"
            env_path.write_text("CHECKMARX_API_TOKEN=from-configured-env\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {"CHECKMARX_DSCAN_ENV_FILE": str(env_path)}, clear=True):
                load_env_file(".env")
                self.assertEqual(os.getenv("CHECKMARX_API_TOKEN"), "from-configured-env")


if __name__ == "__main__":
    unittest.main()