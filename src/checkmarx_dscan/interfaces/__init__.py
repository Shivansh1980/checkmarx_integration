from __future__ import annotations

from .agents.crewai import (
    CheckmarxProjectScanTool,
    CheckmarxScanTool,
    JenkinsArtifactTool,
    run_checkmarx_project_scan_tool,
    run_checkmarx_scan_tool,
    run_jenkins_artifact_tool,
)
from .agents.mcp import create_mcp_server, main as mcp_main


def jenkins_main(argv=None):
    from .cli.jenkins import main

    return main(argv)


def scan_main(argv=None):
    from .cli.scan import main

    return main(argv)


def project_scan_main(argv=None):
    from .cli.project_scan import main

    return main(argv)

__all__ = [
    "CheckmarxProjectScanTool",
    "CheckmarxScanTool",
    "JenkinsArtifactTool",
    "create_mcp_server",
    "jenkins_main",
    "mcp_main",
    "project_scan_main",
    "run_checkmarx_project_scan_tool",
    "run_checkmarx_scan_tool",
    "run_jenkins_artifact_tool",
    "scan_main",
]