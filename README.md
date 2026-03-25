# Checkmarx DScan

`checkmarx_dscan` is a modular Python package for two related workflows:

1. Run a Checkmarx One upload scan against a local directory, file, or zip archive.
2. Retrieve a Checkmarx JSON report that was already archived by a Jenkins pipeline build.
3. Expose the same capabilities through an MCP server so any MCP-capable agent can call them.

Both flows return JSON shaped for downstream automation and agent processing.

## MCP client guidance

If you attach this project as an MCP server to an agent client such as Cody, the client should treat the tool response itself as the primary output. `output_json` only writes a local copy for audit or later inspection; agents do not need to read files from disk unless they explicitly want persisted artifacts.

Recommended tool selection order:

- `checkmarx_scan`
        Use this for both direct Checkmarx workflows. Provide `source` when you want to create a new upload scan. Omit `source`, or set `scan_mode=latest_project`, when you want the latest existing Checkmarx scan for a project and optional branch.
- `jenkins_artifact`
        Use this when you want the report attached to a Jenkins pipeline build or when Jenkins build selection matters.

Recommended response fields for agents:

- `agent_report.vulnerability_summary`
        High-level scan outcome, severity counts, engine counts, and terminal status.
- `agent_report.engine_coverage`
        Which engines were enabled, which produced findings, and which returned zero findings.
- `agent_report.top_actionable_issues`
        The highest-priority grouped issues to review first.
- `agent_report.top_fix_targets`
        The best concise remediation targets for packages, images, or locations.
- `agent_report.code_issues`, `dependency_issues`, `infrastructure_issues`, `container_issues`
        Category-specific views when the agent needs to focus on one type of issue.
- `findings` or `agent_report.vulnerabilities`
        Long-form normalized vulnerabilities when the summary is not enough.
- `raw.final_scan` and `raw.results`
        Native Checkmarx payloads when the normalized structures are still insufficient. Request these by setting `include_raw=true`.

Recommended agent workflow:

1. Read `agent_report.vulnerability_summary` and `agent_report.engine_coverage`.
2. Inspect `agent_report.top_actionable_issues` or `agent_report.top_fix_targets`.
3. If more context is needed, inspect `findings` or `agent_report.vulnerabilities`.
4. If native Checkmarx response details are required, call the tool again with `include_raw=true`.

## Architecture

The package now follows a layered structure so the codebase is easier to extend without coupling CrewAI integration, CLI entrypoints, transport clients, and reporting logic together.

- `application/`
        Use-case orchestration, request resolution, reporting composition, and service entrypoints.
- `domain/`
        Shared domain-facing models, constants, and error types used across the package.
- `infrastructure/`
        HTTP clients, archive creation, and JSON persistence helpers.
- `interfaces/`
        CLI adapters and CrewAI-facing tool bindings.

The MCP adapter is additive. The CLI entrypoints, CrewAI tools, application services, and domain models still remain the source of truth, and the MCP server only wraps the same underlying execution functions.

The original top-level modules are still kept as compatibility facades so existing imports, scripts, and tests continue to work while new development can target the layered packages.

## What the package returns

For a direct Checkmarx scan, the package returns a bundle with:

- Normalized findings with severity, title, description, location, package metadata, remediation hints, and extracted attributes.
- Scan summary counts by severity and engine.
- Request, archive, project, and scan metadata.
- Raw Checkmarx payloads for the project, scan creation response, final scan response, and all results.

For Jenkins artifact retrieval, the package returns a bundle with:

- Jenkins job metadata.
- Selected build metadata.
- The archived artifact path and download URL.
- The downloaded Checkmarx report JSON.
- An `agent_report.vulnerabilities` array with per-vulnerability type, severity, title, description, location, package coordinates, recommended upgrade version, fix guidance, references, and raw detail fields when Checkmarx API enrichment is available.
- Optional raw Jenkins API payloads.

## Requirements

- Python 3.11 or newer.
- Network access to Checkmarx One for direct scans.
- Network access to Jenkins for archived report retrieval.
- Valid credentials for whichever flow you want to use.

## Install

Editable install:

```bash
pip install -e .
```

Editable install with CrewAI support:

```bash
pip install -e .[crewai]
```

Editable install with MCP server support:

```bash
pip install -e .[mcp]
```

Python 3.13 is supported and is the primary validated runtime for this workspace.

## Required credentials

This project can work with two separate systems. You only need the credentials for the flow you are actually using.

### Checkmarx One

Required for `checkmarx-dscan` or `python -m checkmarx_dscan`.

- `CHECKMARX_API_TOKEN` or `CX_APIKEY`
    This is the Checkmarx One API token used to obtain an access token.
- `CHECKMARX_BASE_URL` or `CX_BASE_URI`
    Example: `https://us.ast.checkmarx.net`

Optional:

- `CHECKMARX_AUTH_URL`, `CHECKMARX_BASE_AUTH_URL`, or `CX_BASE_AUTH_URI`
- `CHECKMARX_TENANT` or `CX_TENANT`
- `CHECKMARX_BRANCH` or `CX_BRANCH`
- `CHECKMARX_SCAN_TYPES`
- `CHECKMARX_TIMEOUT`
- `CHECKMARX_POLL_INTERVAL`
- `CHECKMARX_POLL_TIMEOUT`
- `CHECKMARX_RESULTS_PAGE_SIZE`

### Jenkins

Required for `checkmarx-jenkins-artifact` or `python -m checkmarx_dscan.interfaces.cli.jenkins`.

- `JENKINS_USERNAME` or `JENKINS_USER`
    Your Jenkins user id.
- `JENKINS_API_TOKEN`
    Your Jenkins API token.
- `JENKINS_JOB_URL`
    Full Jenkins job URL or pass `--job-url` on the command line.

Optional:

- `JENKINS_BASE_URL` or `JENKINS_URL`
    Only needed if you prefer to pass relative job paths instead of a full job URL.
- `JENKINS_TIMEOUT`
- `JENKINS_POLL_INTERVAL`
- `JENKINS_POLL_TIMEOUT`
- `JENKINS_ARTIFACT_NAME`
    Defaults to `checkmarx-ast-results.json`.

## Create a `.env` file

The package reads `.env` before resolving environment variables. Use only `KEY=VALUE` lines.

Do not put PowerShell commands, shell commands, or comments containing secrets into `.env`.

Generated JSON artifacts should be written under the top-level `output/` directory. Relative `--output-json` paths are resolved under `output/`, and paths that already start with `output/` are preserved as-is, which keeps the repository root clean without creating nested `output/output/` directories.

Example `.env` for both flows:

```dotenv
CHECKMARX_BASE_URL=https://us.ast.checkmarx.net
CHECKMARX_API_TOKEN=your_checkmarx_api_token

JENKINS_USERNAME=your.jenkins.user
JENKINS_API_TOKEN=your_jenkins_api_token
JENKINS_JOB_URL=http://jenkins.example.com/job/folder/job/project/job/release_1/
```

## How to generate a Jenkins API token

This README follows the current Jenkins documentation for scripted clients and pipeline credentials.

According to the Jenkins documentation:

- Scripted clients should use HTTP basic authentication with `username:apiToken`.
- API tokens are preferred over passwords.
- Credentials should be passed from the first request.
- In pipelines, credentials should be injected with Jenkins credentials bindings rather than hardcoded.

Typical steps:

1. Open your Jenkins user security or configure page.
2. Create a new API token for this integration.
3. Copy the raw token value immediately when Jenkins shows it.
4. Store it in a secure secret store, local `.env`, or Jenkins credential.
5. If a token is ever pasted into chat, logs, or source control, rotate it.

If your Jenkins controller offers HTTPS, use HTTPS instead of HTTP.

## How to verify a Jenkins token locally

PowerShell example:

```powershell
$pair = "your.username:YOUR_JENKINS_API_TOKEN"
$basic = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))
Invoke-RestMethod -Uri "http://jenkins.example.com/user/your.username/api/json" -Headers @{ Authorization = "Basic $basic" }
```

If this returns a `401` or `403`, the most common causes are:

- Wrong username.
- Wrong token.
- Token copied incorrectly.
- Token created on a different Jenkins controller than the one you are calling.
- Jenkins policy preventing that API access for your user.

## How to run the project

### 1. Run a Checkmarx One upload scan

Module form:

```bash
python -m checkmarx_dscan my-project --source ./repo --output-json checkmarx-scan
```

Installed script form:

```bash
checkmarx-dscan my-project --source ./repo --output-json checkmarx-scan
```

Example with explicit scan settings:

```bash
checkmarx-dscan my-project \
    --source ./repo \
    --branch main \
    --scan-types sast,sca,iac-security \
    --results-limit 20 \
        --output-json checkmarx-scan
```

Latest existing project scan through the same command:

```bash
checkmarx-dscan my-project \
        --scan-mode latest_project \
        --branch release_1 \
        --output-json checkmarx-scan
```

### 2. Retrieve a Checkmarx report from Jenkins artifacts

Module form:

```bash
python -m checkmarx_dscan.interfaces.cli.jenkins \
    --job-url http://jenkins.example.com/job/folder/job/project/job/release_1/ \
        --output-json jenkins-checkmarx
```

Installed script form:

```bash
checkmarx-jenkins-artifact \
    --job-url http://jenkins.example.com/job/folder/job/project/job/release_1/ \
        --output-json jenkins-checkmarx
```

Specific build example:

```bash
checkmarx-jenkins-artifact \
    --job-url http://jenkins.example.com/job/folder/job/project/job/release_1/ \
    --build-number 139 \
        --output-json jenkins-build-139
```

Latest completed build only:

```bash
checkmarx-jenkins-artifact \
    --job-url http://jenkins.example.com/job/folder/job/project/job/release_1/ \
    --latest-completed-only \
        --output-json jenkins-checkmarx
```

Behavior when no build number is provided:

1. Prefer the current running build.
2. Otherwise fall back to the latest completed build.
3. Search archived artifacts by exact file name.
4. Download the file named `checkmarx-ast-results.json` unless overridden.

## Jenkins pipeline setup

If you want a Jenkins pipeline to archive the Checkmarx JSON report so this project can retrieve it later, store credentials in Jenkins and archive the JSON artifact explicitly.

### Recommended Jenkins credentials

For calling Checkmarx One from a Jenkins pipeline:

- Store the Checkmarx API token as a Jenkins secret text credential.

For this project's Jenkins artifact retrieval flow:

- Store the Jenkins username and Jenkins API token as either:
    - a Username with password credential where the password is the Jenkins API token, or
    - separate credentials if your organization prefers that pattern.

### Declarative pipeline example

This example follows Jenkins guidance to use credentials bindings and to avoid Groovy string interpolation for secrets.

```groovy
pipeline {
        agent any

        environment {
                CHECKMARX_BASE_URL = 'https://us.ast.checkmarx.net'
                CHECKMARX_API_TOKEN = credentials('checkmarx-api-token')
        }

        stages {
                stage('Run Checkmarx Tool') {
                        steps {
                                bat 'checkmarx-dscan cis-providerportal-web --source . --output-json checkmarx-scan'
                        }
                }
        }

        post {
                always {
                        archiveArtifacts artifacts: 'checkmarx-ast-results.json', fingerprint: true, onlyIfSuccessful: false
                }
        }
}
```

### Jenkins retrieval pipeline example

If a later pipeline or job needs to pull the archived report from another job, bind Jenkins credentials and call the retrieval command.

```groovy
pipeline {
        agent any

        stages {
                stage('Pull Checkmarx Artifact') {
                        steps {
                                withCredentials([usernamePassword(credentialsId: 'jenkins-api-user-token', usernameVariable: 'JENKINS_USERNAME', passwordVariable: 'JENKINS_API_TOKEN')]) {
                                        bat 'checkmarx-jenkins-artifact --job-url "http://jenkins.example.com/job/folder/job/project/job/release_1/" --output-json jenkins-checkmarx'
                                }
                        }
                }
        }

        post {
                always {
                        archiveArtifacts artifacts: 'jenkins-checkmarx-report.json', fingerprint: true, onlyIfSuccessful: false
                }
        }
}
```

### Security notes for Jenkins pipelines

- Do not hardcode tokens in `Jenkinsfile`.
- Do not echo tokens to logs.
- Do not use Groovy double-quoted interpolation for secrets in `sh`, `bat`, `powershell`, or `pwsh` steps.
- Prefer credentials bindings such as `credentials(...)` or `withCredentials(...)`.
- Rotate tokens if they appear in chat, source control, or logs.

## CrewAI usage

Install the optional CrewAI dependencies first:

```bash
pip install -e .[crewai]
```

Then register the tools with your agent:

```python
from crewai import Agent

from checkmarx_dscan.interfaces.agents.crewai import CheckmarxScanTool, JenkinsArtifactTool

scan_tool = CheckmarxScanTool()
jenkins_tool = JenkinsArtifactTool()

security_agent = Agent(
        role="Application Security Analyst",
        goal="Run Checkmarx scans and reason over the resulting JSON payloads.",
        backstory="Specializes in translating scan output into remediation guidance.",
        tools=[scan_tool, jenkins_tool],
)
```

The tools return JSON strings so a CrewAI agent can pass them directly to later tasks or parse them into structured analysis.

## MCP server usage

The package also exposes the same scan and Jenkins retrieval capabilities through a stdio MCP server for any MCP-capable client, including GitHub Copilot, custom agents, and other orchestration frameworks.

Install the MCP extra if needed:

```bash
pip install -e .[mcp]
```

Run the MCP server over stdio:

```bash
checkmarx-mcp-server
```

Or via module form:

```bash
python -m checkmarx_dscan.interfaces.agents.mcp
```

The MCP server exposes two tools:

- `checkmarx_scan`
                Runs a live Checkmarx upload scan and returns structured JSON.
- `jenkins_artifact`
                Pulls an archived Checkmarx report from Jenkins and returns structured JSON.

Unlike the CrewAI adapter, the MCP server returns structured tool output directly instead of JSON strings, which is better for generic MCP clients.

### Example MCP client configuration

Example GitHub Copilot MCP configuration using stdio:

```json
{
        "servers": {
                "checkmarx-dscan": {
                        "type": "stdio",
                        "command": "checkmarx-mcp-server",
                        "env": {
                                "CHECKMARX_BASE_URL": "https://us.ast.checkmarx.net",
                                "CHECKMARX_API_TOKEN": "${input:checkmarxApiToken}"
                        }
                }
        }
}
```

If your client prefers a full Python invocation instead of a script entrypoint:

```json
{
        "servers": {
                "checkmarx-dscan": {
                        "type": "stdio",
                        "command": "python",
                        "args": ["-m", "checkmarx_dscan.interfaces.agents.mcp"],
                        "env": {
                                "CHECKMARX_BASE_URL": "https://us.ast.checkmarx.net",
                                "CHECKMARX_API_TOKEN": "${input:checkmarxApiToken}"
                        }
                }
        }
}
```

If your MCP client launches the server from a directory other than the repository root, a relative `env_file` such as `.env` may not be found where you expect. This server now searches parent directories for relative env files, but the most reliable options are still either:

- pass `env_file` as an absolute path in the tool call, or
- inject `CHECKMARX_BASE_URL` and `CHECKMARX_API_TOKEN` directly into the MCP server process environment.

Because the MCP server uses the same application services as the CLI and CrewAI tools, any improvements to scan normalization, Jenkins enrichment, or reporting automatically flow to MCP clients as well.

## Troubleshooting

### Jenkins `401 Unauthorized`

Check these first:

1. `JENKINS_USERNAME` is the actual Jenkins user id.
2. `JENKINS_API_TOKEN` is the raw token value shown when created.
3. The token was generated on the same Jenkins controller you are calling.
4. The token was not copied with extra whitespace.
5. You are testing the same controller path as the target job.

### Jenkins artifact not found

Check these next:

1. The pipeline archives `checkmarx-ast-results.json` with `archiveArtifacts`.
2. The file exists before the `post` block completes.
3. The artifact name matches exactly, or override it with `--artifact-name`.
4. The build reached the stage where artifact archiving happens.

### Checkmarx scan works but Jenkins retrieval does not

That is expected if Checkmarx credentials are valid but Jenkins credentials are not. The two flows are independent.

## Local validation

```bash
pytest
```