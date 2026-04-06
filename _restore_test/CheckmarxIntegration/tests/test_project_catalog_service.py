from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.services.project_catalog import CheckmarxProjectCatalogService
from checkmarx_dscan.domain.models import CheckmarxCredentials


class ProjectCatalogServiceTests(unittest.TestCase):
    def test_execute_returns_projects_and_best_match(self) -> None:
        class FakeClient:
            def authenticate(self) -> str:
                return "token"

            def get_all_projects(self, *, page_size: int = 100, max_projects: int = 1000) -> list[dict[str, object]]:
                return [
                    {"id": "1", "name": "alpha-service", "mainBranch": "main", "repoUrl": "https://git/alpha-service"},
                    {"id": "2", "name": "portal-web", "mainBranch": "release", "repoUrl": "https://git/portal-web"},
                    {"id": "3", "name": "billing-api", "mainBranch": "main", "repoUrl": "https://git/billing-api"},
                ]

        service = CheckmarxProjectCatalogService(
            CheckmarxCredentials(api_token="token", base_url="https://us.ast.checkmarx.net")
        )
        service.client = FakeClient()

        payload = service.execute(project_query="portal", include_raw=False)

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "projects")
        self.assertEqual(payload["summary"]["accessible_projects"], 3)
        self.assertEqual(payload["summary"]["match_count"], 1)
        self.assertEqual(payload["project_resolution"]["best_match"]["project"]["name"], "portal-web")
        self.assertEqual(payload["matches"][0]["match_type"], "name_contains")
        self.assertEqual(payload["projects"][0]["name"], "alpha-service")
        self.assertNotIn("raw", payload)


if __name__ == "__main__":
    unittest.main()