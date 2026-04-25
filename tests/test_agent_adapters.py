from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.domain.errors import CheckmarxError
from checkmarx_dscan.interfaces.agents.common import (
	execute_checkmarx_project_scan_tool,
	execute_checkmarx_scan_tool,
	execute_jenkins_artifact_tool,
	execute_sonar_tool,
)
from checkmarx_dscan.interfaces.agents.crewai import run_sonar_tool
from checkmarx_dscan.interfaces.agents.mcp import create_mcp_server


class AgentAdapterTests(unittest.TestCase):
	def test_execute_checkmarx_scan_tool_returns_report_dict(self) -> None:
		mock_report = mock.Mock()
		mock_report.to_dict.return_value = {"summary": {"total_findings": 0}}

		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_scan_request", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.CheckmarxScanService") as service_cls:
			service_cls.return_value.execute.return_value = mock_report
			payload = execute_checkmarx_scan_tool(project="demo", source=".", scan_mode="upload", include_raw=False)

		self.assertEqual(payload["summary"]["total_findings"], 0)
		service_cls.return_value.execute.assert_called_once()
		mock_report.to_dict.assert_called_once_with(include_raw=False, profile="compact")

	def test_execute_checkmarx_scan_tool_auto_mode_prefers_latest_project_even_with_source(self) -> None:
		mock_report = mock.Mock()
		mock_report.to_dict.return_value = {"summary": {"total_findings": 4}}

		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_project_scan_request", return_value=object()) as resolve_request_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.ProjectScanService") as service_cls:
			service_cls.return_value.execute.return_value = mock_report
			payload = execute_checkmarx_scan_tool(project="demo", source=".", include_raw=False)

		self.assertEqual(payload["summary"]["total_findings"], 4)
		resolve_request_mock.assert_called_once()
		service_cls.return_value.execute.assert_called_once()
		mock_report.to_dict.assert_called_once_with(include_raw=False, profile="compact")

	def test_execute_checkmarx_scan_tool_without_source_uses_latest_project_scan(self) -> None:
		mock_report = mock.Mock()
		mock_report.to_dict.return_value = {"summary": {"total_findings": 4}}

		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_project_scan_request", return_value=object()) as resolve_request_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.ProjectScanService") as service_cls:
			service_cls.return_value.execute.return_value = mock_report
			payload = execute_checkmarx_scan_tool(project="demo", branch="main", include_raw=False)

		self.assertEqual(payload["summary"]["total_findings"], 4)
		resolve_request_mock.assert_called_once()
		service_cls.return_value.execute.assert_called_once()
		mock_report.to_dict.assert_called_once_with(include_raw=False, profile="compact")

	def test_execute_checkmarx_scan_tool_projects_mode_returns_catalog(self) -> None:
		catalog_payload = {
			"ok": True,
			"mode": "projects",
			"summary": {"accessible_projects": 2, "match_count": 1},
			"matches": [{"match_type": "exact_name", "project": {"name": "demo-project"}}],
		}

		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.CheckmarxProjectCatalogService") as service_cls:
			service_cls.return_value.execute.return_value = catalog_payload
			payload = execute_checkmarx_scan_tool(
				scan_mode="projects",
				project_query="demo",
				include_raw=False,
			)

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["mode"], "projects")
		self.assertEqual(payload["summary"]["accessible_projects"], 2)
		service_cls.return_value.execute.assert_called_once_with(project_query="demo", include_raw=False)

	def test_execute_checkmarx_project_scan_tool_returns_report_dict(self) -> None:
		mock_report = mock.Mock()
		mock_report.to_dict.return_value = {"summary": {"total_findings": 4}}

		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_project_scan_request", return_value=object()) as resolve_request_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.ProjectScanService") as service_cls:
			service_cls.return_value.execute.return_value = mock_report
			payload = execute_checkmarx_project_scan_tool(project="demo", branch="main", include_raw=False)

		self.assertEqual(payload["summary"]["total_findings"], 4)
		resolve_request_mock.assert_called_once()
		service_cls.return_value.execute.assert_called_once()
		mock_report.to_dict.assert_called_once_with(include_raw=False, profile="compact")

	def test_execute_jenkins_artifact_tool_returns_report_dict(self) -> None:
		mock_report = mock.Mock()
		mock_report.to_dict.return_value = {"summary": {"report_total_findings": 3}}

		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_jenkins_credentials", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials", side_effect=CheckmarxError("skip cx creds")) as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_jenkins_artifact_request", return_value=object()), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.JenkinsArtifactService") as service_cls:
			service_cls.return_value.execute.return_value = mock_report
			payload = execute_jenkins_artifact_tool(
				job_url="http://jenkins/job/demo",
				include_raw=False,
				checkmarx_base_url="https://us.ast.checkmarx.net",
				checkmarx_api_token="token",
				checkmarx_auth_url="https://iam.checkmarx.net/auth/realms/demo",
				checkmarx_tenant="demo",
			)

		self.assertEqual(payload["summary"]["report_total_findings"], 3)
		resolve_credentials_mock.assert_called_once_with(
			base_url="https://us.ast.checkmarx.net",
			api_token="token",
			auth_url="https://iam.checkmarx.net/auth/realms/demo",
			tenant="demo",
			timeout=None,
		)
		service_cls.return_value.execute.assert_called_once()
		mock_report.to_dict.assert_called_once_with(include_raw=False, profile="compact")

	def test_create_mcp_server_registers_expected_tools(self) -> None:
		server = create_mcp_server()
		tools = asyncio.run(server.list_tools())
		tool_names = {tool.name for tool in tools}

		self.assertIn("checkmarx_scan", tool_names)
		self.assertIn("jenkins_artifact", tool_names)
		self.assertIn("sonar", tool_names)
		self.assertEqual(
			tool_names,
			{
				"checkmarx_scan",
				"jenkins_artifact",
				"sonar",
			},
		)

	def test_execute_sonar_tool_local_report_does_not_require_base_url(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_sonar_credentials", return_value=object()) as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.SonarCoverageService") as service_cls:
			service_cls.return_value.local_coverage_report.return_value = {"ok": True, "report_type": "local_coverage_prediction"}
			payload = execute_sonar_tool(operation="local_report", coverage_threshold=80.0)

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["report_type"], "local_coverage_prediction")
		resolve_credentials_mock.assert_called_once_with(base_url="", token="", timeout=None, require_base_url=False)
		service_cls.return_value.local_coverage_report.assert_called_once()

	def test_execute_sonar_tool_local_quality_gate_alias_uses_local_coverage_report(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_env_file"), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_sonar_credentials", return_value=object()) as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.SonarCoverageService") as service_cls:
			service_cls.return_value.predict_quality_gate.return_value = {
				"ok": True,
				"operation": "local_quality_gate",
				"report_type": "local_quality_gate_prediction",
				"quality_gate": {"status": "needs_local_metrics", "would_pass": None},
			}
			payload = execute_sonar_tool(
				operation="local_quality_gate",
				project="demo-providerportal-web",
				local_metrics={"coverage": 86.0},
			)

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["operation"], "local_quality_gate")
		self.assertEqual(payload["report_type"], "local_quality_gate_prediction")
		resolve_credentials_mock.assert_called_once_with(base_url="", token="", timeout=None, require_base_url=True)
		service_cls.return_value.predict_quality_gate.assert_called_once()
		_, kwargs = service_cls.return_value.predict_quality_gate.call_args
		self.assertEqual(kwargs["local_metrics"], {"coverage": 86.0})
		self.assertEqual(kwargs["project"], "demo-providerportal-web")
		service_cls.return_value.local_coverage_report.assert_not_called()

	def test_execute_sonar_tool_local_report_uses_mock_payload_in_mock_mode(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.load_mock_sonar_payload") as load_mock_payload, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_sonar_credentials") as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.SonarCoverageService") as service_cls:
			load_mock_payload.return_value = {"ok": True, "report_type": "local_coverage_prediction", "quality_gate": {"status": "pass"}}
			payload = execute_sonar_tool(operation="local_report", coverage_threshold=85.0)

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["report_type"], "local_coverage_prediction")
		self.assertEqual(payload["quality_gate"]["status"], "pass")
		load_mock_payload.assert_called_once()
		resolve_credentials_mock.assert_not_called()
		service_cls.assert_not_called()

	def test_execute_checkmarx_scan_tool_mock_mode_skips_live_dependencies(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials") as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.ProjectScanService") as service_cls:
			payload = execute_checkmarx_scan_tool(project="demo-mock", include_raw=False)

		self.assertEqual(payload["project"]["name"], "demo-mock")
		resolve_credentials_mock.assert_not_called()
		service_cls.assert_not_called()

	def test_execute_checkmarx_scan_tool_mock_mode_points_to_demo_project_files(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True):
			payload = execute_checkmarx_scan_tool(project="demo-providerportal-web", include_raw=False)

		self.assertEqual(payload["demo_project"]["root"], "demo/mock_providerportal_web")
		self.assertEqual(payload["demo_project"]["reset_command"], "python tools/mock_demo_project.py reset")
		self.assertEqual(payload["summary"]["total_findings"], 4)
		locations = {
			item["location"]["filename"]
			for item in payload["agent_report"]["vulnerabilities"]
		}
		self.assertIn("demo/mock_providerportal_web/package.json", locations)
		self.assertIn("demo/mock_providerportal_web/Dockerfile", locations)
		self.assertIn("demo/mock_providerportal_web/src/server.js", locations)
		self.assertIn("demo/mock_providerportal_web/src/server.js", payload["demo_project"]["managed_files"])

	def test_execute_sonar_tool_mock_mode_returns_structured_payload(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_sonar_credentials") as resolve_credentials_mock:
			payload = execute_sonar_tool(operation="file_detail", project="demo-providerportal-web", file="src/example.py")

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["report_type"], "file_coverage_improvement")
		self.assertEqual(payload["file"]["file_path"], "src/example.py")
		resolve_credentials_mock.assert_not_called()

	def test_execute_checkmarx_project_scan_tool_mock_mode_skips_live_dependencies(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials") as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.ProjectScanService") as service_cls:
			payload = execute_checkmarx_project_scan_tool(project="demo-mock", include_raw=False)

		self.assertEqual(payload["project"]["name"], "demo-mock")
		resolve_credentials_mock.assert_not_called()
		service_cls.assert_not_called()

	def test_execute_jenkins_artifact_tool_mock_mode_skips_live_dependencies(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_jenkins_credentials") as resolve_jenkins_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials") as resolve_checkmarx_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.JenkinsArtifactService") as service_cls:
			payload = execute_jenkins_artifact_tool(
				job_url="http://jenkins/job/demo",
				include_raw=False,
			)

		self.assertTrue(payload["summary"]["artifact_found"])
		self.assertEqual(payload["job"]["url"], "http://jenkins/job/demo")
		resolve_jenkins_credentials_mock.assert_not_called()
		resolve_checkmarx_credentials_mock.assert_not_called()
		service_cls.assert_not_called()

	def test_execute_jenkins_artifact_tool_mock_mode_resolves_pr_job(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True):
			payload = execute_jenkins_artifact_tool(
				job_url="http://jenkins/view/change-requests",
				pr_number=112,
				include_raw=False,
			)

		self.assertEqual(payload["request"]["pr_number"], 112)
		self.assertEqual(payload["job"]["url"], "http://jenkins/view/change-requests/job/PR-112")

	def test_crewai_run_sonar_tool_forwards_to_json_runner(self) -> None:
		with mock.patch("checkmarx_dscan.interfaces.agents.crewai.run_sonar_tool_json", return_value='{"ok": true}') as runner:
			payload = run_sonar_tool(operation="projects", project_query="demo")

		self.assertEqual(payload, '{"ok": true}')
		runner.assert_called_once_with(operation="projects", project_query="demo")

	def test_checkmarx_scan_tool_returns_structured_error_for_missing_credentials(self) -> None:
		server = create_mcp_server()
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True):
			_, result = asyncio.run(server.call_tool(
				"checkmarx_scan",
				{
					"project": "demo",
					"scan_mode": "latest_project",
					"include_raw": False,
					"env_file": "__missing__.env",
				},
			))

		self.assertFalse(result["ok"])
		self.assertEqual(result["tool"], "checkmarx_scan")
		self.assertEqual(result["error"]["code"], "missing_checkmarx_api_token")
		self.assertEqual(result["error"]["category"], "configuration")
		self.assertIn("CHECKMARX_API_TOKEN", result["error"]["message"])

	def test_checkmarx_scan_tool_accepts_report_profile_argument(self) -> None:
		server = create_mcp_server()
		with mock.patch("checkmarx_dscan.interfaces.agents.mcp.execute_checkmarx_scan_tool", return_value={"ok": True, "mode": "projects"}) as execute_mock:
			_, result = asyncio.run(server.call_tool(
				"checkmarx_scan",
				{
					"project": "",
					"scan_mode": "projects",
					"include_raw": False,
					"report_profile": "compact",
				},
			))

		self.assertTrue(result["ok"])
		execute_mock.assert_called_once()
		self.assertEqual(execute_mock.call_args.kwargs["report_profile"], "compact")

	def test_mcp_tools_support_mock_mode_without_environment_credentials(self) -> None:
		server = create_mcp_server()
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True):
			_, checkmarx_result = asyncio.run(server.call_tool(
				"checkmarx_scan",
				{
					"project": "demo-mock",
					"include_raw": False,
					"env_file": "__missing__.env",
				},
			))
			_, jenkins_result = asyncio.run(server.call_tool(
				"jenkins_artifact",
				{
					"job_url": "http://jenkins/job/demo",
					"include_raw": False,
					"env_file": "__missing__.env",
				},
			))
			_, sonar_result = asyncio.run(server.call_tool(
				"sonar",
				{
					"operation": "remote_report",
					"project": "demo-providerportal-web",
					"include_raw": False,
					"env_file": "__missing__.env",
				},
			))

		self.assertTrue(checkmarx_result["summary"]["successful"])
		self.assertTrue(jenkins_result["summary"]["artifact_found"])
		self.assertTrue(sonar_result["ok"])
		self.assertEqual(sonar_result["report_type"], "coverage_improvement")

	def test_execute_checkmarx_scan_tool_ignores_passed_data_source_when_env_is_mock(self) -> None:
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "mock"}, clear=True), \
			mock.patch("checkmarx_dscan.interfaces.agents.common.resolve_credentials") as resolve_credentials_mock, \
			mock.patch("checkmarx_dscan.interfaces.agents.common.ProjectScanService") as service_cls:
			payload = execute_checkmarx_scan_tool(project="demo-mock", include_raw=False, data_source="live")

		self.assertEqual(payload["project"]["name"], "demo-mock")
		resolve_credentials_mock.assert_not_called()
		service_cls.assert_not_called()

	def test_sonar_tool_returns_structured_error_for_missing_base_url(self) -> None:
		server = create_mcp_server()
		with mock.patch.dict("os.environ", {"CHECKMARX_DSCAN_DATA_SOURCE": "live"}, clear=True):
			_, result = asyncio.run(server.call_tool(
				"sonar",
				{
					"operation": "remote_report",
					"env_file": "__missing__.env",
					"project": "demo",
				},
			))

		self.assertFalse(result["ok"])
		self.assertEqual(result["tool"], "sonar")
		self.assertEqual(result["error"]["code"], "missing_sonar_base_url")
		self.assertEqual(result["error"]["category"], "configuration")


if __name__ == "__main__":
	unittest.main()