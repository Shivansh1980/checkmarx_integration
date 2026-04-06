from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.services.checkmarx_scan import CheckmarxScanService
from checkmarx_dscan.domain.models import CheckmarxCredentials, ScanRequest


class CheckmarxScanServiceTests(unittest.TestCase):
    def test_execute_reuses_resolved_existing_project_before_creating_new_one(self) -> None:
        class FakeClient:
            def __init__(self) -> None:
                self.ensure_project_called = False

            def authenticate(self) -> str:
                return "token"

            def get_all_projects(self, *, page_size: int = 100, max_projects: int = 1000) -> list[dict[str, object]]:
                return [{"id": "proj-1", "name": "demo-project", "mainBranch": "main"}]

            def ensure_project(self, project_name: str, branch: str) -> tuple[dict[str, object], bool]:
                self.ensure_project_called = True
                return {"id": "proj-created", "name": project_name, "mainBranch": branch}, True

            def get_presigned_upload_url(self) -> str:
                return "https://upload-url.example.com"

            def upload_archive(self, upload_url: str, archive_path: Path) -> None:
                return None

            def create_scan(self, project_id: str, branch: str, upload_url: str, scan_types: list[str]) -> dict[str, object]:
                return {"id": "scan-1"}

            def wait_for_scan(
                self,
                scan_id: str,
                poll_interval: int,
                poll_timeout: int,
                on_status=None,
            ) -> dict[str, object]:
                return {"id": scan_id, "status": "Completed"}

            def get_all_results(self, scan_id: str, page_size: int = 500) -> dict[str, object]:
                return {"scanID": scan_id, "totalCount": 0, "results": []}

        service = CheckmarxScanService(CheckmarxCredentials(api_token="token", base_url="https://us.ast.checkmarx.net"))
        fake_client = FakeClient()
        service.client = fake_client

        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir)
            (source_dir / "app.py").write_text("print('ok')\n", encoding="utf-8")

            report = service.execute(
                ScanRequest(project_name="demo-project", source_path=source_dir, include_raw=False)
            )

        payload = report.to_dict(include_raw=False)
        self.assertEqual(payload["project"]["name"], "demo-project")
        self.assertFalse(fake_client.ensure_project_called)


if __name__ == "__main__":
    unittest.main()