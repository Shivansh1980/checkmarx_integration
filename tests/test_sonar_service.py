from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.services.sonar import SonarCoverageService
from checkmarx_dscan.domain.errors import SonarError, SonarHttpError, SonarPermissionError
from checkmarx_dscan.domain.models import SonarCredentials
from checkmarx_dscan.infrastructure.clients.sonar import SonarClient


def _measures(**values: object) -> list[dict[str, object]]:
	return [{"metric": key, "value": str(value)} for key, value in values.items()]


class SonarCoverageServiceTests(unittest.TestCase):
	def test_client_project_discovery_falls_back_from_projects_search(self) -> None:
		client = SonarClient(base_url="http://sonar.example.test", token="token", timeout=30)
		calls: list[str] = []

		def fake_request_json(path: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
			calls.append(path)
			if path == "api/projects/search":
				raise SonarPermissionError("forbidden", status_code=403, url="", auth_mode="authenticated")
			if path == "api/components/search_projects":
				return (
					{"components": [{"key": "demo", "name": "demo", "qualifier": "TRK"}]},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)
			raise AssertionError(path)

		client._request_json = fake_request_json  # type: ignore[method-assign]

		payload, _ = client.list_projects(page_size=5)

		self.assertEqual(calls, ["api/projects/search", "api/components/search_projects"])
		self.assertEqual(payload["components"][0]["key"], "demo")

	def test_client_file_resolution_falls_back_to_full_tree_scan(self) -> None:
		client = SonarClient(base_url="http://sonar.example.test", token="token", timeout=30)
		calls: list[tuple[str, int]] = []

		def fake_get_component_tree(component: str, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
			page = int(kwargs.get("page", 1))
			query = str(kwargs.get("query", ""))
			calls.append((query, page))
			if query:
				return ({"components": [], "paging": {"pageIndex": 1, "pageSize": 100, "total": 0}}, {"used_auth_mode": "authenticated"})
			if page == 1:
				return (
					{
						"components": [{"key": "demo:src/other.py", "path": "src/other.py", "name": "other.py"}],
						"paging": {"pageIndex": 1, "pageSize": 1, "total": 2},
					},
					{"used_auth_mode": "authenticated"},
				)
			return (
				{
					"components": [{"key": "demo:src/target.py", "path": "src/target.py", "name": "target.py"}],
					"paging": {"pageIndex": 2, "pageSize": 1, "total": 2},
				},
				{"used_auth_mode": "authenticated"},
			)

		client.get_component_tree = fake_get_component_tree  # type: ignore[method-assign]

		component, _ = client.resolve_file_component("demo", file_path="src/target.py")

		self.assertEqual(component["path"], "src/target.py")
		self.assertEqual(calls, [("src/target.py", 1), ("", 1), ("", 2)])

	def test_client_component_app_uses_component_parameter(self) -> None:
		client = SonarClient(base_url="http://sonar.example.test", token="token", timeout=30)

		def fake_request_json(path: str, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
			self.assertEqual(path, "api/components/app")
			params = kwargs.get("params") if isinstance(kwargs.get("params"), dict) else {}
			self.assertEqual(params.get("component"), "demo:file.py")
			self.assertNotIn("key", params)
			return ({"sources": []}, {"used_auth_mode": "authenticated"})

		client._request_json = fake_request_json  # type: ignore[method-assign]

		payload, _ = client.get_component_app("demo:file.py")

		self.assertEqual(payload["sources"], [])

	def test_coverage_report_prioritizes_files_with_biggest_coverage_impact(self) -> None:
		class FakeClient:
			parse_measures = staticmethod(SonarClient.parse_measures)

			def validate_token(self) -> dict[str, object]:
				return {"token_configured": True, "token_valid": True, "token_expiration": "", "error": ""}

			def build_auth_section(self, validation: dict[str, object], metas: list[dict[str, object]]) -> dict[str, object]:
				return {"token_valid": True, "anonymous_fallback_used": False}

			def list_project_branches(self, project: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"branches": [
							{
								"name": "main",
								"isMain": True,
								"analysisDate": "2026-04-24T09:10:37-0400",
								"status": {"qualityGateStatus": "OK"},
							}
						]
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def get_quality_gate_status(self, *, project_key: str = "", **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"projectStatus": {
							"status": "OK",
							"conditions": [
								{
									"metricKey": "coverage",
									"comparator": "LT",
									"errorThreshold": "50",
									"actualValue": "72.5",
									"status": "OK",
								}
							],
							"ignoredConditions": False,
							"caycStatus": "non-compliant",
						}
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def get_component_measures(self, component: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"component": {
							"key": component,
							"name": "demo-project",
							"measures": _measures(
								coverage=72.5,
								line_coverage=74.0,
								branch_coverage=51.0,
								lines_to_cover=200,
								uncovered_lines=55,
								conditions_to_cover=24,
								uncovered_conditions=10,
							),
						}
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def get_measures_component_tree(self, component: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"components": [
							{
								"key": f"{component}:src/types.ts",
								"path": "src/types.ts",
								"measures": _measures(),
							},
							{
								"key": f"{component}:src/service.py",
								"path": "src/service.py",
								"measures": _measures(
									coverage=18.0,
									line_coverage=19.0,
									branch_coverage=12.0,
									lines_to_cover=90,
									uncovered_lines=60,
									conditions_to_cover=18,
									uncovered_conditions=14,
								),
							},
							{
								"key": f"{component}:src/helpers.py",
								"path": "src/helpers.py",
								"measures": _measures(
									coverage=35.0,
									line_coverage=35.0,
									branch_coverage=40.0,
									lines_to_cover=40,
									uncovered_lines=26,
									conditions_to_cover=4,
									uncovered_conditions=2,
								),
							},
							{
								"key": f"{component}:src/model.py",
								"path": "src/model.py",
								"measures": _measures(
									coverage=82.0,
									line_coverage=85.0,
									branch_coverage=70.0,
									lines_to_cover=70,
									uncovered_lines=9,
									conditions_to_cover=2,
									uncovered_conditions=0,
								),
							},
						],
						"paging": {"pageIndex": 1, "pageSize": 500, "total": 3},
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def normalize_components(self, payload: dict[str, object]) -> list[dict[str, object]]:
				components = payload.get("components")
				return components if isinstance(components, list) else []

			def get_component_app(self, component_key: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return ({"sources": []}, {"used_auth_mode": "authenticated", "anonymous_fallback_used": False})

		service = SonarCoverageService(SonarCredentials(base_url="http://sonar.example.test", token="token"))
		service.client = FakeClient()

		payload = service.coverage_report(project="demo-project", branch="main")

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["report_type"], "coverage_improvement")
		self.assertEqual(payload["access_mode"], "authenticated")
		self.assertEqual(payload["files"][0]["file_path"], "src/service.py")
		self.assertEqual(payload["files"][0]["file_name"], "service.py")
		self.assertEqual(payload["files"][0]["coverage_pct"], 18.0)
		self.assertEqual(payload["files"][0]["total_lines_considered"], 90)
		self.assertEqual(payload["files"][0]["covered_lines_count"], 30)
		self.assertEqual(payload["project_summary"]["project_name"], "demo-project")
		self.assertEqual(payload["project_summary"]["total_uncovered_lines"], 55)
		self.assertEqual(payload["project_summary"]["total_covered_lines"], 145)
		self.assertEqual(payload["priority"]["top_files_to_target"][0]["file_path"], "src/service.py")
		self.assertFalse(any(item["file_path"] == "src/types.ts" and item["priority_score"] > payload["files"][0]["priority_score"] for item in payload["files"]))
		self.assertTrue(payload["files"][0]["should_target_first"])
		self.assertEqual(payload["project_summary"]["branch_name"], "main")
		self.assertEqual(payload["quality_gate"]["status"], "pass")
		self.assertTrue(payload["quality_gate"]["would_pass"])
		self.assertEqual(payload["decision_summary"]["source"], "sonar_quality_gate")
		self.assertEqual(payload["decision_summary"]["status"], "pass")
		self.assertEqual(payload["analysis_context"]["resolved_scope"]["branch"], "main")

	def test_coverage_report_resolves_pull_request_scope_when_metadata_is_available(self) -> None:
		class FakeClient:
			parse_measures = staticmethod(SonarClient.parse_measures)

			def validate_token(self) -> dict[str, object]:
				return {"token_configured": True, "token_valid": True, "token_expiration": "", "error": ""}

			def build_auth_section(self, validation: dict[str, object], metas: list[dict[str, object]]) -> dict[str, object]:
				return {"token_valid": True, "anonymous_fallback_used": False}

			def get_component_measures(self, component: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"component": {
							"key": component,
							"name": "demo-project",
							"measures": _measures(
								coverage=91.0,
								line_coverage=91.0,
								branch_coverage=84.0,
								lines_to_cover=100,
								uncovered_lines=9,
							),
						}
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def get_measures_component_tree(self, component: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"components": [
							{
								"key": f"{component}:src/service.py",
								"path": "src/service.py",
								"measures": _measures(
									coverage=91.0,
									line_coverage=91.0,
									branch_coverage=84.0,
									lines_to_cover=100,
									uncovered_lines=9,
								),
							}
						],
						"paging": {"pageIndex": 1, "pageSize": 500, "total": 1},
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def normalize_components(self, payload: dict[str, object]) -> list[dict[str, object]]:
				components = payload.get("components")
				return components if isinstance(components, list) else []

			def get_component_app(self, component_key: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return ({"sources": []}, {"used_auth_mode": "authenticated", "anonymous_fallback_used": False})

			def list_project_pull_requests(self, project: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"pullRequests": [
							{
								"key": "123",
								"title": "Improve service tests",
								"branch": "feature/tests",
								"base": "main",
								"analysisDate": "2026-04-24T09:10:37-0400",
								"status": {"qualityGateStatus": "OK"},
							}
						]
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def normalize_pull_requests(self, payload: dict[str, object]) -> list[dict[str, object]]:
				pull_requests = payload.get("pullRequests")
				return pull_requests if isinstance(pull_requests, list) else []

			def get_quality_gate_status(self, *, project_key: str = "", **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"projectStatus": {
							"status": "OK",
							"conditions": [
								{
									"metricKey": "coverage",
									"comparator": "LT",
									"errorThreshold": "80",
									"actualValue": "91.0",
									"status": "OK",
								}
							],
							"ignoredConditions": False,
						}
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

		service = SonarCoverageService(SonarCredentials(base_url="http://sonar.example.test", token="token"))
		service.client = FakeClient()

		payload = service.coverage_report(project="demo-project", pull_request="123")

		self.assertEqual(payload["analysis_context"]["scope_type"], "pull_request")
		self.assertTrue(payload["analysis_context"]["pull_request"]["matched"])
		self.assertEqual(payload["analysis_context"]["resolved_scope"]["pull_request"], "123")
		self.assertEqual(payload["analysis_context"]["resolved_scope"]["branch"], "feature/tests")
		self.assertEqual(payload["quality_gate"]["current_status"], "OK")
		self.assertEqual(payload["decision_summary"]["status"], "pass")
		self.assertTrue(payload["decision_summary"]["would_pass_quality_gate"])

	def test_coverage_report_raises_clear_error_for_missing_pull_request_analysis(self) -> None:
		class FakeClient:
			def validate_token(self) -> dict[str, object]:
				return {"token_configured": True, "token_valid": True, "token_expiration": "", "error": ""}

			def get_component_measures(self, component: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				raise SonarHttpError(
					"GET http://sonar.example.test/api/measures/component failed with 404: Component 'demo-project' of pull request '123' not found",
					status_code=404,
					url="http://sonar.example.test/api/measures/component",
					auth_mode="authenticated",
				)

		service = SonarCoverageService(SonarCredentials(base_url="http://sonar.example.test", token="token"))
		service.client = FakeClient()

		with self.assertRaisesRegex(SonarError, "pull request '123'"):
			service.coverage_report(project="demo-project", pull_request="123")

	def test_file_coverage_detail_extracts_uncovered_lines_and_source_excerpt(self) -> None:
		class FakeClient:
			parse_measures = staticmethod(SonarClient.parse_measures)

			def validate_token(self) -> dict[str, object]:
				return {"token_configured": False, "token_valid": False, "token_expiration": "", "error": ""}

			def build_auth_section(self, validation: dict[str, object], metas: list[dict[str, object]]) -> dict[str, object]:
				return {"token_valid": False, "anonymous_fallback_used": False}

			def resolve_file_component(self, project: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{"key": f"{project}:src/app.py", "path": "src/app.py", "name": "app.py"},
					{"used_auth_mode": "anonymous", "anonymous_fallback_used": False},
				)

			def get_component_measures(self, component: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"component": {
							"key": component,
							"measures": _measures(
								coverage=41.0,
								line_coverage=42.0,
								branch_coverage=20.0,
								lines_to_cover=12,
								uncovered_lines=7,
								conditions_to_cover=4,
								uncovered_conditions=3,
							),
						}
					},
					{"used_auth_mode": "anonymous", "anonymous_fallback_used": False},
				)

			def get_component_app(self, component_key: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"sources": [
							{"line": 10, "code": "if not user:", "lineHits": 0},
							{"line": 11, "code": "    raise ValueError()", "lineHits": 0},
							{"line": 12, "code": "return user.name", "lineHits": 2},
						]
					},
					{"used_auth_mode": "anonymous", "anonymous_fallback_used": False},
				)

			def show_source(self, component_key: str, **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"sources": [
							{"line": 9, "code": "def render(user):"},
							{"line": 10, "code": "if not user:"},
							{"line": 11, "code": "    raise ValueError()"},
							{"line": 12, "code": "return user.name"},
						]
					},
					{"used_auth_mode": "anonymous", "anonymous_fallback_used": False},
				)

		service = SonarCoverageService(SonarCredentials(base_url="http://sonar.example.test"))
		service.client = FakeClient()

		payload = service.file_coverage_detail(
			project="demo-project",
			file="src/app.py",
			include_source=True,
			include_line_details=True,
			use_internal_fallbacks=True,
		)

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["report_type"], "file_coverage_improvement")
		self.assertEqual(payload["access_mode"], "anonymous")
		self.assertEqual(payload["file"]["file_name"], "app.py")
		self.assertEqual(payload["file"]["uncovered_line_numbers"], [10, 11])
		self.assertEqual(payload["file"]["covered_line_numbers"], [12])
		self.assertEqual(payload["file"]["line_number_quality"], "estimated")
		self.assertEqual(payload["file"]["covered_lines_count"], 5)
		self.assertEqual(payload["priority"]["top_files_to_target"][0]["uncovered_line_numbers"], [10, 11])

	def test_local_coverage_report_evaluates_threshold_and_confirms_line_numbers(self) -> None:
		service = SonarCoverageService(SonarCredentials(base_url="", token=""))
		commands: list[list[str]] = []

		def fake_run(command: list[str], *, cwd: Path, timeout: int) -> SimpleNamespace:
			commands.append(command)
			if "json" in command:
				output_path = Path(command[command.index("-o") + 1])
				output_path.write_text(
					"""
{
	"meta": {"version": "7.0"},
	"totals": {
		"covered_lines": 86,
		"num_statements": 100,
		"missing_lines": 14,
		"percent_covered": 86.0,
		"percent_covered_display": "86"
	},
	"files": {
		"src/demo.py": {
			"executed_lines": [1, 2, 3, 4, 8, 9],
			"missing_lines": [5, 6, 7],
			"summary": {
				"covered_lines": 6,
				"num_statements": 9,
				"missing_lines": 3,
				"percent_covered": 66.67,
				"num_branches": 4,
				"covered_branches": 1,
				"missing_branches": 3
			}
		},
		"src/healthy.py": {
			"executed_lines": [1, 2, 3, 4],
			"missing_lines": [],
			"summary": {
				"covered_lines": 4,
				"num_statements": 4,
				"missing_lines": 0,
				"percent_covered": 100.0,
				"num_branches": 0,
				"covered_branches": 0,
				"missing_branches": 0
			}
		}
	}
}
""".strip(),
					encoding="utf-8",
				)
			return SimpleNamespace(returncode=0, stdout="ok", stderr="")

		service._run_local_command = fake_run  # type: ignore[method-assign]

		payload = service.local_coverage_report(
			working_directory=str(ROOT),
			source_paths="src",
			coverage_threshold=80.0,
			file_limit=5,
		)

		self.assertTrue(payload["ok"])
		self.assertEqual(payload["report_type"], "local_coverage_prediction")
		self.assertTrue(payload["would_meet_threshold"])
		self.assertEqual(payload["predicted_sonar_outcome"], "pass")
		self.assertEqual(payload["project_summary"]["overall_coverage_pct"], 86.0)
		self.assertEqual(payload["files"][0]["file_path"], "src/demo.py")
		self.assertEqual(payload["files"][0]["uncovered_line_numbers"], [5, 6, 7])
		self.assertEqual(payload["files"][0]["line_number_quality"], "confirmed")
		self.assertEqual(payload["quality_gate"]["status"], "pass")
		self.assertTrue(payload["quality_gate"]["would_pass"])
		self.assertTrue(any("coverage" in part for part in commands[0]))

	def test_local_coverage_report_marks_quality_gate_fail_when_below_threshold(self) -> None:
		service = SonarCoverageService(SonarCredentials(base_url="", token=""))

		def fake_run(command: list[str], *, cwd: Path, timeout: int) -> SimpleNamespace:
			if "json" in command:
				output_path = Path(command[command.index("-o") + 1])
				output_path.write_text(
					"""
{
	"meta": {"version": "7.0"},
	"totals": {
		"covered_lines": 40,
		"num_statements": 100,
		"missing_lines": 60,
		"percent_covered": 40.0,
		"percent_covered_display": "40"
	},
	"files": {
		"src/demo.py": {
			"executed_lines": [1, 2],
			"missing_lines": [3, 4, 5],
			"summary": {
				"covered_lines": 2,
				"num_statements": 5,
				"missing_lines": 3,
				"percent_covered": 40.0,
				"num_branches": 0,
				"covered_branches": 0,
				"missing_branches": 0
			}
		}
	}
}
""".strip(),
					encoding="utf-8",
				)
			return SimpleNamespace(returncode=0, stdout="ok", stderr="")

		service._run_local_command = fake_run  # type: ignore[method-assign]

		payload = service.local_coverage_report(
			working_directory=str(ROOT),
			source_paths="src",
			coverage_threshold=80.0,
			file_limit=5,
		)

		self.assertFalse(payload["would_meet_threshold"])
		self.assertEqual(payload["predicted_sonar_outcome"], "fail")
		self.assertEqual(payload["quality_gate"]["status"], "fail")
		self.assertFalse(payload["quality_gate"]["would_pass"])
		self.assertEqual(payload["quality_gate"]["failing_conditions"][0]["metric"], "coverage")

	def test_local_coverage_report_resolves_live_sonar_project_and_predicts_gate(self) -> None:
		class FakeClient:
			def validate_token(self) -> dict[str, object]:
				return {"token_configured": True, "token_valid": True, "token_expiration": "", "error": ""}

			def list_projects(self, *, query: str = "", **_: object) -> tuple[dict[str, object], dict[str, object]]:
				self.last_query = query
				return (
					{
						"components": [
							{"key": "cis-providerportal-web", "name": "CheckmarxIntegration", "qualifier": "TRK"},
						]
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

			def normalize_project_list(self, payload: dict[str, object]) -> list[dict[str, object]]:
				components = payload.get("components")
				return components if isinstance(components, list) else []

			def get_quality_gate_status(self, *, project_key: str = "", **_: object) -> tuple[dict[str, object], dict[str, object]]:
				return (
					{
						"projectStatus": {
							"status": "ERROR",
							"conditions": [
								{
									"metricKey": "coverage",
									"comparator": "LT",
									"errorThreshold": "80",
									"actualValue": "71.4",
									"status": "ERROR",
								},
								{
									"metricKey": "new_coverage",
									"comparator": "LT",
									"errorThreshold": "80",
									"actualValue": "50.0",
									"status": "ERROR",
								},
							],
							"ignoredConditions": False,
						}
					},
					{"used_auth_mode": "authenticated", "anonymous_fallback_used": False},
				)

		service = SonarCoverageService(SonarCredentials(base_url="http://sonar.example.test", token="token"))
		service.client = FakeClient()

		def fake_run(command: list[str], *, cwd: Path, timeout: int) -> SimpleNamespace:
			if "json" in command:
				output_path = Path(command[command.index("-o") + 1])
				output_path.write_text(
					"""
{
	"meta": {"version": "7.0"},
	"totals": {
		"covered_lines": 86,
		"num_statements": 100,
		"missing_lines": 14,
		"percent_covered": 86.0,
		"percent_covered_display": "86"
	},
	"files": {
		"src/demo.py": {
			"executed_lines": [1, 2, 3, 4, 8, 9],
			"missing_lines": [5, 6, 7],
			"summary": {
				"covered_lines": 6,
				"num_statements": 9,
				"missing_lines": 3,
				"percent_covered": 66.67,
				"num_branches": 4,
				"covered_branches": 1,
				"missing_branches": 3
			}
		}
	}
}
""".strip(),
					encoding="utf-8",
				)
			return SimpleNamespace(returncode=0, stdout="ok", stderr="")

		service._run_local_command = fake_run  # type: ignore[method-assign]

		payload = service.local_coverage_report(
			working_directory=str(ROOT),
			source_paths="src",
			coverage_threshold=80.0,
			file_limit=5,
		)

		self.assertTrue(payload["sonar_project"]["matched"])
		self.assertEqual(payload["sonar_project"]["project_key"], "cis-providerportal-web")
		self.assertEqual(payload["sonar_quality_gate"]["current_status"], "ERROR")
		self.assertEqual(payload["sonar_quality_gate"]["prediction_status"], "unknown")
		self.assertEqual(payload["quality_gate"]["sonar_prediction_status"], "unknown")
		self.assertIsNone(payload["sonar_quality_gate"]["would_pass"])
		self.assertEqual(payload["sonar_quality_gate"]["evaluated_conditions"][0]["status"], "pass")
		self.assertEqual(payload["sonar_quality_gate"]["unsupported_conditions"][0]["metric"], "new_coverage")


if __name__ == "__main__":
	unittest.main()