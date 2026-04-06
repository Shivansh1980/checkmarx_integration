from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.services.jenkins_artifact import (
    JenkinsArtifactService,
    build_jenkins_artifact_execution_report,
    find_artifact_by_name,
    render_jenkins_artifact_console_report,
    select_build_payload,
    select_build_reference,
)
from checkmarx_dscan.domain.models import JenkinsArtifactRequest, JenkinsCredentials


class JenkinsServiceTests(unittest.TestCase):
    def test_select_build_reference_prefers_running_last_build(self) -> None:
        selected_number, selected_from = select_build_reference(
            {
                "lastBuild": {"number": 140, "url": "http://jenkins/job/demo/140/"},
                "lastCompletedBuild": {"number": 139, "url": "http://jenkins/job/demo/139/", "result": "FAILURE"},
            },
            {"number": 140, "building": True},
        )
        self.assertEqual(selected_number, 140)
        self.assertEqual(selected_from, "lastBuild")

    def test_select_build_reference_falls_back_to_last_completed(self) -> None:
        selected_number, selected_from = select_build_reference(
            {
                "lastBuild": {"number": 140, "url": "http://jenkins/job/demo/140/"},
                "lastCompletedBuild": {"number": 139, "url": "http://jenkins/job/demo/139/", "result": "FAILURE"},
            },
            {"number": 140, "building": False},
        )
        self.assertEqual(selected_number, 139)
        self.assertEqual(selected_from, "lastCompletedBuild")

    def test_select_build_payload_prefers_running_last_build(self) -> None:
        selected_payload, selected_from = select_build_payload(
            {"number": 140, "building": True},
            {"number": 139, "building": False, "result": "FAILURE"},
            prefer_running_build=True,
        )
        self.assertEqual(selected_payload["number"], 140)
        self.assertEqual(selected_from, "lastBuild")

    def test_select_build_payload_falls_back_to_last_completed(self) -> None:
        selected_payload, selected_from = select_build_payload(
            {"number": 140, "building": False},
            {"number": 139, "building": False, "result": "ABORTED"},
            prefer_running_build=True,
        )
        self.assertEqual(selected_payload["number"], 139)
        self.assertEqual(selected_from, "lastCompletedBuild")

    def test_find_artifact_by_name_matches_relative_path(self) -> None:
        artifact = find_artifact_by_name(
            [
                {"fileName": "summary.txt", "relativePath": "logs/summary.txt", "displayPath": "summary.txt"},
                {
                    "fileName": "checkmarx-ast-results.json",
                    "relativePath": "cx.tmp12736116092409960830/checkmarx-ast-results.json",
                    "displayPath": "checkmarx-ast-results.json",
                },
            ],
            "checkmarx-ast-results.json",
        )
        self.assertIsNotNone(artifact)
        self.assertEqual(artifact["relativePath"], "cx.tmp12736116092409960830/checkmarx-ast-results.json")

    def test_build_jenkins_artifact_execution_report_wraps_downloaded_report(self) -> None:
        request = JenkinsArtifactRequest(job_url="http://jenkins/job/demo/job/release_1")
        report = build_jenkins_artifact_execution_report(
            request=request,
            job_payload={"name": "release_1", "fullName": "demo/release_1", "url": request.job_url},
            build_payload={
                "number": 139,
                "url": "http://jenkins/job/demo/job/release_1/139/",
                "result": "FAILURE",
                "building": False,
                "artifacts": [{"fileName": "checkmarx-ast-results.json"}],
            },
            artifact_payload={
                "fileName": "checkmarx-ast-results.json",
                "relativePath": "cx.tmp12736116092409960830/checkmarx-ast-results.json",
                "displayPath": "checkmarx-ast-results.json",
            },
            report_payload={"TotalIssues": 223, "ScanID": "scan-1", "summary": {"total_findings": 3}, "findings": [{}, {}, {}]},
            artifact_download_url="http://jenkins/job/demo/job/release_1/139/artifact/cx.tmp12736116092409960830/checkmarx-ast-results.json",
            selected_from="lastCompletedBuild",
            include_raw=True,
            agent_report={
                "detail_source": "checkmarx_api",
                "detailed_findings_available": True,
                "vulnerabilities": [{}, {}, {}],
            },
        )

        payload = report.to_dict()
        self.assertEqual(payload["build"]["number"], 139)
        self.assertEqual(payload["summary"]["report_total_findings"], 223)
        self.assertEqual(payload["artifact"]["file_name"], "checkmarx-ast-results.json")
        self.assertEqual(payload["summary"]["detail_source"], "checkmarx_api")
        self.assertEqual(payload["summary"]["detailed_findings_count"], 3)
        self.assertIn("agent_report", payload)
        self.assertIn("raw", payload)

        compact_payload = report.to_dict(profile="compact")
        self.assertEqual(compact_payload["report_profile"], "compact")
        self.assertEqual(compact_payload["agent_report"]["canonical_vulnerability_path"], "agent_report.vulnerabilities")
        self.assertEqual(compact_payload["agent_report"]["detailed_findings_count"], 3)
        self.assertEqual(len(compact_payload["agent_report"]["vulnerabilities"]), 3)
        self.assertNotIn("actionable_issues", compact_payload["agent_report"])

    def test_render_jenkins_artifact_console_report_includes_build_and_artifact(self) -> None:
        request = JenkinsArtifactRequest(job_url="http://jenkins/job/demo/job/release_1")
        report = build_jenkins_artifact_execution_report(
            request=request,
            job_payload={"name": "release_1", "url": request.job_url},
            build_payload={
                "number": 139,
                "url": "http://jenkins/job/demo/job/release_1/139/",
                "result": "UNSTABLE",
                "building": False,
                "artifacts": [{"fileName": "checkmarx-ast-results.json"}],
            },
            artifact_payload={
                "fileName": "checkmarx-ast-results.json",
                "relativePath": "cx.tmp/checkmarx-ast-results.json",
                "displayPath": "checkmarx-ast-results.json",
            },
            report_payload={"summary": {"total_findings": 0}, "findings": []},
            artifact_download_url="http://jenkins/job/demo/job/release_1/139/artifact/cx.tmp/checkmarx-ast-results.json",
            selected_from="lastCompletedBuild",
            include_raw=False,
            agent_report={"detail_source": "artifact_summary_only", "detailed_findings_available": False, "vulnerabilities": []},
        )

        rendered = render_jenkins_artifact_console_report(report)
        self.assertIn("Build: 139 [UNSTABLE] via lastCompletedBuild", rendered)
        self.assertIn("Artifact: checkmarx-ast-results.json", rendered)
        self.assertIn("Detail source: artifact_summary_only", rendered)

    def test_render_jenkins_artifact_console_report_lists_top_actionable_issues(self) -> None:
        request = JenkinsArtifactRequest(job_url="http://jenkins/job/demo/job/release_1")
        report = build_jenkins_artifact_execution_report(
            request=request,
            job_payload={"name": "release_1", "url": request.job_url},
            build_payload={
                "number": 161,
                "url": "http://jenkins/job/demo/job/release_1/161/",
                "result": "FAILURE",
                "building": False,
                "artifacts": [{"fileName": "checkmarx-ast-results.json"}],
            },
            artifact_payload={
                "fileName": "checkmarx-ast-results.json",
                "relativePath": "cx.tmp/checkmarx-ast-results.json",
                "displayPath": "checkmarx-ast-results.json",
            },
            report_payload={"TotalIssues": 2},
            artifact_download_url="http://jenkins/job/demo/job/release_1/161/artifact/cx.tmp/checkmarx-ast-results.json",
            selected_from="explicit",
            include_raw=False,
            agent_report={
                "detail_source": "checkmarx_api",
                "detailed_findings_available": True,
                "vulnerabilities": [{}, {}],
                "top_actionable_issues": [
                    {
                        "severity": "critical",
                        "type": "sca",
                        "title": "axios 0.16.2",
                        "location": "package-lock.json",
                        "vulnerability_count": 2,
                        "recommended_version": "1.12.2",
                    }
                ],
            },
        )

        rendered = render_jenkins_artifact_console_report(report)
        self.assertIn("Top actionable issues: 1", rendered)
        self.assertIn("[CRITICAL] [sca] axios 0.16.2 @ package-lock.json | vulnerabilities=2 | recommended=1.12.2", rendered)

    def test_execute_with_explicit_build_number_skips_job_lookup(self) -> None:
        class FakeClient:
            def get_job(self, job_url: str) -> dict[str, object]:
                raise AssertionError("get_job should not be called for an explicit build number")

            def get_build_reference(self, job_url: str, reference: str) -> dict[str, object] | None:
                raise AssertionError("get_build_reference should not be called for an explicit build number")

            def get_build(self, job_url: str, build_number: int) -> dict[str, object]:
                return {
                    "number": build_number,
                    "url": f"{job_url}/{build_number}/",
                    "result": "FAILURE",
                    "building": False,
                    "artifacts": [
                        {
                            "fileName": "checkmarx-ast-results.json",
                            "relativePath": "cx.tmp/checkmarx-ast-results.json",
                            "displayPath": "checkmarx-ast-results.json",
                        }
                    ],
                }

            def build_artifact_download_url(self, build_payload: dict[str, object], relative_path: str, job_url: str, build_number: int) -> str:
                return f"{job_url}/{build_number}/artifact/{relative_path}"

            def download_artifact_json(self, download_url: str) -> dict[str, object]:
                return {"summary": {"total_findings": 1}, "findings": [{}]}

        service = JenkinsArtifactService(JenkinsCredentials())
        service.client = FakeClient()

        report = service.execute(
            JenkinsArtifactRequest(
                job_url="http://jenkins/job/demo/job/release_1",
                build_number=139,
                include_raw=False,
            )
        )

        payload = report.to_dict(include_raw=False)
        self.assertEqual(payload["build"]["number"], 139)
        self.assertEqual(payload["summary"]["build_selected_from"], "explicit")
        self.assertEqual(payload["summary"]["report_total_findings"], 1)

    def test_execute_without_explicit_build_uses_build_references(self) -> None:
        class FakeClient:
            def get_build_reference(self, job_url: str, reference: str) -> dict[str, object] | None:
                if reference == "lastBuild":
                    return {"number": 140, "building": False, "result": "FAILURE", "url": f"{job_url}/140/", "artifacts": []}
                if reference == "lastCompletedBuild":
                    return {
                        "number": 139,
                        "building": False,
                        "result": "ABORTED",
                        "url": f"{job_url}/139/",
                        "artifacts": [
                            {
                                "fileName": "checkmarx-ast-results.json",
                                "relativePath": "cx.tmp/checkmarx-ast-results.json",
                                "displayPath": "checkmarx-ast-results.json",
                            }
                        ],
                    }
                return None

            def get_build(self, job_url: str, build_number: int) -> dict[str, object]:
                return {
                    "number": build_number,
                    "url": f"{job_url}/{build_number}/",
                    "result": "ABORTED",
                    "building": False,
                    "artifacts": [
                        {
                            "fileName": "checkmarx-ast-results.json",
                            "relativePath": "cx.tmp/checkmarx-ast-results.json",
                            "displayPath": "checkmarx-ast-results.json",
                        }
                    ],
                }

            def build_artifact_download_url(self, build_payload: dict[str, object], relative_path: str, job_url: str, build_number: int) -> str:
                return f"{job_url}/{build_number}/artifact/{relative_path}"

            def download_artifact_json(self, download_url: str) -> dict[str, object]:
                return {"TotalIssues": 223, "ProjectName": "demo", "BranchName": "release_1", "ScanID": "scan-1"}

        service = JenkinsArtifactService(JenkinsCredentials())
        service.client = FakeClient()

        report = service.execute(
            JenkinsArtifactRequest(
                job_url="http://jenkins/job/demo/job/release_1",
                include_raw=False,
            )
        )

        payload = report.to_dict(include_raw=False)
        self.assertEqual(payload["build"]["number"], 139)
        self.assertEqual(payload["summary"]["build_selected_from"], "lastCompletedBuild")
        self.assertEqual(payload["summary"]["report_total_findings"], 223)
        self.assertEqual(payload["agent_report"]["artifact_vulnerability_summary"]["total_findings"], 223)

    def test_execute_without_explicit_build_falls_back_to_previous_artifact_build(self) -> None:
        class FakeClient:
            def get_build_reference(self, job_url: str, reference: str) -> dict[str, object] | None:
                if reference == "lastBuild":
                    return {"number": 163, "building": False, "result": "FAILURE", "url": f"{job_url}/163/", "artifacts": []}
                if reference == "lastCompletedBuild":
                    return {"number": 163, "building": False, "result": "FAILURE", "url": f"{job_url}/163/", "artifacts": []}
                return None

            def get_build(self, job_url: str, build_number: int, *, not_found_is_none: bool = False) -> dict[str, object] | None:
                if build_number in {163, 162}:
                    return {
                        "number": build_number,
                        "url": f"{job_url}/{build_number}/",
                        "result": "FAILURE",
                        "building": False,
                        "artifacts": [],
                    }
                if build_number == 161:
                    return {
                        "number": 161,
                        "url": f"{job_url}/161/",
                        "result": "FAILURE",
                        "building": False,
                        "artifacts": [
                            {
                                "fileName": "checkmarx-ast-results.json",
                                "relativePath": "cx.tmp/checkmarx-ast-results.json",
                                "displayPath": "checkmarx-ast-results.json",
                            }
                        ],
                    }
                return None

            def build_artifact_download_url(self, build_payload: dict[str, object], relative_path: str, job_url: str, build_number: int) -> str:
                return f"{job_url}/{build_number}/artifact/{relative_path}"

            def download_artifact_json(self, download_url: str) -> dict[str, object]:
                return {"TotalIssues": 240, "ProjectName": "demo", "BranchName": "release_1", "ScanID": "scan-161"}

        service = JenkinsArtifactService(JenkinsCredentials())
        service.client = FakeClient()

        report = service.execute(
            JenkinsArtifactRequest(
                job_url="http://jenkins/job/demo/job/release_1",
                include_raw=False,
                fallback_build_lookback=5,
            )
        )

        payload = report.to_dict(include_raw=False)
        self.assertEqual(payload["build"]["number"], 161)
        self.assertEqual(payload["summary"]["build_selected_from"], "lastCompletedBuild-artifactFallback")
        self.assertEqual(payload["summary"]["report_total_findings"], 240)


if __name__ == "__main__":
    unittest.main()