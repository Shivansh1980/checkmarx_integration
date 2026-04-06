from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkmarx_dscan.application.reporting.report_builder import (
    build_actionable_issue_groups,
    build_agent_report_from_jenkins_artifact,
    build_execution_report,
    render_console_report,
)
from checkmarx_dscan.domain.models import ArchiveInfo, ScanRequest


class ReportingTests(unittest.TestCase):
    def test_build_actionable_issue_groups_merges_package_findings(self) -> None:
        findings = [
            {
                "id": "CVE-1",
                "type": "sca",
                "severity": "high",
                "title": "axios",
                "package_name": "axios",
                "package_version": "0.16.2",
                "recommended_version": "1.12.2",
                "location": {"display": "package-lock.json"},
                "fix_recommendation": "Upgrade axios from 0.16.2 to 1.12.2.",
                "references": ["https://example.test/CVE-1"],
            },
            {
                "id": "CVE-2",
                "type": "sca",
                "severity": "critical",
                "title": "axios",
                "package_name": "axios",
                "package_version": "0.16.2",
                "recommended_version": "1.12.2",
                "location": {"display": "package-lock.json"},
                "fix_recommendation": "Upgrade axios from 0.16.2 to 1.12.2.",
                "references": ["https://example.test/CVE-2"],
            },
        ]

        groups = build_actionable_issue_groups(findings)

        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["severity"], "critical")
        self.assertEqual(groups[0]["vulnerability_count"], 2)
        self.assertEqual(groups[0]["title"], "axios 0.16.2")
        self.assertEqual(groups[0]["recommended_version"], "1.12.2")
        self.assertEqual(groups[0]["location"], "package-lock.json")
        self.assertEqual(groups[0]["vulnerability_ids"], ["CVE-1", "CVE-2"])

    def test_build_agent_report_from_jenkins_artifact_includes_actionable_issues(self) -> None:
        detailed_view = {
            "scan": {"id": "scan-1"},
            "summary": {"total_findings": 2},
            "findings": [
                {
                    "id": "CVE-1",
                    "type": "containers",
                    "severity": "critical",
                    "title": "ffmpeg",
                    "package_name": "ffmpeg",
                    "package_version": "7:6.1.1-3ubuntu5",
                    "location": {"display": "Dockerfile"},
                },
                {
                    "id": "CVE-2",
                    "type": "containers",
                    "severity": "high",
                    "title": "ffmpeg",
                    "package_name": "ffmpeg",
                    "package_version": "7:6.1.1-3ubuntu5",
                    "location": {"display": "Dockerfile"},
                },
            ],
        }

        payload = build_agent_report_from_jenkins_artifact(
            {"ScanID": "scan-1", "ProjectName": "demo", "TotalIssues": 2, "Status": "Completed"},
            detailed_view=detailed_view,
        )

        self.assertEqual(payload["detail_source"], "checkmarx_api")
        self.assertEqual(len(payload["actionable_issues"]), 1)
        self.assertEqual(payload["top_actionable_issues"][0]["vulnerability_count"], 2)
        self.assertEqual(payload["top_actionable_issues"][0]["severity"], "critical")
        self.assertEqual(payload["top_fix_targets"][0]["target"], "ffmpeg 7:6.1.1-3ubuntu5")

    def test_build_execution_report_keeps_details_for_agents(self) -> None:
        request = ScanRequest(
            project_name="demo-project",
            source_path=ROOT,
            branch="main",
            scan_types=["sast", "sca"],
            include_raw=True,
        )
        archive = ArchiveInfo(
            path="C:/temp/checkmarx.zip",
            created=True,
            size_bytes=2048,
            size_human="2.0 KB",
            retained=False,
        )
        project = {"id": "proj-1", "name": "demo-project", "mainBranch": "main"}
        created_scan = {"id": "scan-1", "createdAt": "2026-03-16T10:00:00Z"}
        final_scan = {
            "id": "scan-1",
            "status": "Completed",
            "engines": ["sast", "sca"],
            "completedAt": "2026-03-16T10:05:00Z",
            "statusDetails": [{"name": "SAST", "status": "Completed"}],
        }
        results_payload = {
            "scanID": "scan-1",
            "totalCount": 2,
            "results": [
                {
                    "id": "finding-1",
                    "type": "sast",
                    "severity": "High",
                    "description": "SQL injection in login handler",
                    "data": {
                        "queryName": "SQL Injection",
                        "languageName": "Python",
                        "nodes": [{"fileName": "src/app.py", "line": 42, "column": 9}],
                        "recommendation": "Use parameterized queries.",
                    },
                },
                {
                    "id": "finding-2",
                    "type": "sca-package",
                    "severity": "Medium",
                    "data": {
                        "packageIdentifier": "Npm-react-router-7.9.4",
                        "scaPackageData": {"locations": ["requirements.txt"]},
                        "description": "Outdated dependency.",
                        "recommendedVersion": "7.12.0",
                        "packageData": [{"url": "https://github.com/advisories/example", "type": "Advisory"}],
                    },
                },
            ],
        }

        report = build_execution_report(
            request=request,
            archive=archive,
            project=project,
            project_created=False,
            created_scan=created_scan,
            final_scan=final_scan,
            results_payload=results_payload,
            include_raw=True,
        )

        payload = report.to_dict()
        self.assertEqual(payload["summary"]["total_findings"], 2)
        self.assertEqual(payload["summary"]["highest_severity"], "high")
        self.assertIn("raw", payload)
        self.assertEqual(payload["raw"]["results"]["totalCount"], 2)
        self.assertEqual(payload["findings"][0]["description"], "SQL injection in login handler")
        self.assertEqual(payload["findings"][0]["details"]["queryName"], "SQL Injection")
        self.assertEqual(payload["findings"][1]["location"]["display"], "requirements.txt")
        self.assertEqual(payload["findings"][1]["package_name"], "react-router")
        self.assertEqual(payload["findings"][1]["package_version"], "7.9.4")
        self.assertEqual(payload["findings"][1]["recommended_version"], "7.12.0")
        self.assertEqual(payload["findings"][1]["fix_recommendation"], "Upgrade react-router from 7.9.4 to 7.12.0.")
        self.assertEqual(payload["findings"][1]["references"], ["https://github.com/advisories/example"])
        self.assertEqual(payload["agent_report"]["detail_source"], "checkmarx_api")
        self.assertEqual(payload["agent_report"]["engine_coverage"]["engines_with_findings"], ["sast", "sca"])
        self.assertEqual(payload["agent_report"]["code_issues"][0]["type"], "sast")
        self.assertEqual(payload["agent_report"]["dependency_fix_targets"][0]["recommended_version"], "7.12.0")

        compact_payload = report.to_dict(profile="compact")
        self.assertEqual(compact_payload["report_profile"], "compact")
        self.assertNotIn("findings", compact_payload)
        self.assertEqual(compact_payload["agent_report"]["canonical_vulnerability_path"], "agent_report.vulnerabilities")
        self.assertEqual(len(compact_payload["agent_report"]["vulnerabilities"]), 2)
        self.assertEqual(compact_payload["agent_report"]["vulnerabilities"][0]["details"]["queryName"], "SQL Injection")
        self.assertIn(
            "7.12.0",
            [target.get("recommended_version") for target in compact_payload["agent_report"]["top_fix_targets"]],
        )
        self.assertNotIn("actionable_issues", compact_payload["agent_report"])
        self.assertNotIn("code_issues", compact_payload["agent_report"])

    def test_render_console_report_lists_top_findings(self) -> None:
        request = ScanRequest(project_name="demo-project", source_path=ROOT)
        archive = ArchiveInfo(path="archive.zip", created=True, size_bytes=1, size_human="1 B", retained=False)
        report = build_execution_report(
            request=request,
            archive=archive,
            project={"id": "proj-1", "name": "demo-project"},
            project_created=False,
            created_scan={"id": "scan-1"},
            final_scan={"id": "scan-1", "status": "Completed", "engines": ["sast"]},
            results_payload={
                "scanID": "scan-1",
                "totalCount": 1,
                "results": [
                    {
                        "id": "finding-1",
                        "type": "sast",
                        "severity": "Critical",
                        "description": "Critical issue",
                        "data": {"queryName": "Hardcoded Secret", "nodes": [{"fileName": "src/app.py", "line": 7}]},
                    }
                ],
            },
            include_raw=False,
        )

        rendered = render_console_report(report, results_limit=5)
        self.assertIn("Top 1 findings", rendered)
        self.assertIn("[CRITICAL] [sast] Hardcoded Secret @ src/app.py:7", rendered)


if __name__ == "__main__":
    unittest.main()