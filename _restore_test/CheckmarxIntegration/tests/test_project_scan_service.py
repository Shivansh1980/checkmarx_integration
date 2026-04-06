from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.services.project_scan import ProjectScanService
from checkmarx_dscan.domain.models import CheckmarxCredentials, ProjectScanRequest


class ProjectScanServiceTests(unittest.TestCase):
    def test_execute_uses_latest_terminal_scan_for_branch(self) -> None:
        class FakeClient:
            def authenticate(self) -> str:
                return "token"

            def get_all_projects(self, *, page_size: int = 100, max_projects: int = 1000) -> list[dict[str, object]]:
                return [{"id": "proj-1", "name": "demo-project", "mainBranch": "release_1"}]

            def get_latest_project_scan(
                self,
                project_id: str,
                *,
                branch: str = "",
                prefer_terminal_scan: bool = True,
                lookback: int = 100,
            ) -> dict[str, object]:
                return {"id": "scan-2", "branch": branch, "status": "Completed"}

            def get_scan(self, scan_id: str) -> dict[str, object]:
                return {
                    "id": scan_id,
                    "branch": "release_1",
                    "status": "Completed",
                    "engines": ["sast", "sca"],
                    "projectName": "demo-project",
                }

            def get_all_results(self, scan_id: str, page_size: int = 500) -> dict[str, object]:
                return {
                    "scanID": scan_id,
                    "totalCount": 1,
                    "results": [
                        {
                            "id": "finding-1",
                            "type": "sast",
                            "severity": "High",
                            "description": "SQL injection in request handler",
                            "data": {
                                "queryName": "SQL Injection",
                                "languageName": "C#",
                                "nodes": [{"fileName": "Controllers/HomeController.cs", "line": 17, "column": 9}],
                            },
                        }
                    ],
                }

        service = ProjectScanService(CheckmarxCredentials(api_token="token", base_url="https://us.ast.checkmarx.net"))
        service.client = FakeClient()

        report = service.execute(
            ProjectScanRequest(
                project_name="demo-project",
                branch="release_1",
                include_raw=False,
            )
        )

        payload = report.to_dict(include_raw=False)
        self.assertEqual(payload["project"]["name"], "demo-project")
        self.assertEqual(payload["scan"]["id"], "scan-2")
        self.assertEqual(payload["summary"]["total_findings"], 1)
        self.assertEqual(payload["findings"][0]["type"], "sast")
        self.assertEqual(payload["findings"][0]["location"]["display"], "Controllers/HomeController.cs:17:9")
        self.assertEqual(payload["agent_report"]["code_issues"][0]["type"], "sast")
        self.assertEqual(payload["agent_report"]["top_fix_targets"][0]["location"], "Controllers/HomeController.cs:17:9")

    def test_execute_resolves_close_project_name_from_accessible_projects(self) -> None:
        class FakeClient:
            def authenticate(self) -> str:
                return "token"

            def get_all_projects(self, *, page_size: int = 100, max_projects: int = 1000) -> list[dict[str, object]]:
                return [
                    {"id": "proj-1", "name": "demo-project", "mainBranch": "release_1"},
                    {"id": "proj-2", "name": "demo-worker", "mainBranch": "main"},
                ]

            def get_latest_project_scan(
                self,
                project_id: str,
                *,
                branch: str = "",
                prefer_terminal_scan: bool = True,
                lookback: int = 100,
            ) -> dict[str, object]:
                return {"id": "scan-2", "branch": branch, "status": "Completed"}

            def get_scan(self, scan_id: str) -> dict[str, object]:
                return {
                    "id": scan_id,
                    "branch": "release_1",
                    "status": "Completed",
                    "engines": ["sast"],
                    "projectName": "demo-project",
                }

            def get_all_results(self, scan_id: str, page_size: int = 500) -> dict[str, object]:
                return {"scanID": scan_id, "totalCount": 0, "results": []}

        service = ProjectScanService(CheckmarxCredentials(api_token="token", base_url="https://us.ast.checkmarx.net"))
        service.client = FakeClient()

        report = service.execute(ProjectScanRequest(project_name="demo-project", include_raw=False))
        payload = report.to_dict(include_raw=False)

        self.assertEqual(payload["project"]["name"], "demo-project")


if __name__ == "__main__":
    unittest.main()
