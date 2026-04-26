# Checkmarx DScan

`checkmarx_dscan` is a modular Python package for five related workflows:

1. Run a Checkmarx One upload scan against a local directory, file, or zip archive.
2. Retrieve a Checkmarx JSON report that was already archived by a Jenkins pipeline build.
3. Retrieve SonarQube coverage data through an MCP server with project, branch, file, and best-effort line-level detail.
4. Run local pytest-based coverage analysis through the same MCP server to predict whether the current workspace is likely to clear a coverage threshold before push.
5. Expose the same capabilities through an MCP server so any MCP-capable agent can call them.

Both flows return JSON shaped for downstream automation and agent processing.

By default, the tool-facing adapters in this workspace now use bundled mock reports so demos can run without live Checkmarx, Jenkins, or Sonar access. Switch back to live systems by setting `CHECKMARX_DSCAN_DATA_SOURCE=live` in `.env` or the process environment.

You can also mix live and mock per tool with these overrides (any value of `mock` or `live`):

- `CHECKMARX_DSCAN_DATA_SOURCE_CHECKMARX`
- `CHECKMARX_DSCAN_DATA_SOURCE_JENKINS`
- `CHECKMARX_DSCAN_DATA_SOURCE_SONAR`

Each override falls back to `CHECKMARX_DSCAN_DATA_SOURCE`, so you can keep Checkmarx pointed at a real tenant while demoing Jenkins and SonarQube from the bundled fixtures (no `JENKINS_JOB_URL` or `SONAR_BASE_URL` required).

## MCP client guidance

If you attach this project as an MCP server to an agent client such as Cody, the client should treat the tool response itself as the primary output. `output_json` only writes a local copy for audit or later inspection; agents do not need to read files from disk unless they explicitly want persisted artifacts.

Recommended tool selection order:

- `checkmarx_scan`
                        Use this for all direct Checkmarx workflows. By default it resolves the requested project against accessible Checkmarx projects and fetches the latest existing scan for that project and optional branch. Set `scan_mode=projects` when you need to enumerate accessible projects and find the best match for a user-supplied project name. Use `scan_mode=upload` only when you explicitly want to upload local source to Checkmarx and start a new scan. Use `CHECKMARX_DSCAN_DATA_SOURCE=live` when you want real API traffic instead of the bundled mock report.
- `jenkins_artifact`
                Use this when you want the report attached to a Jenkins pipeline build or when Jenkins build selection matters. You can point `job_url` at a direct Jenkins job or at a PR change-requests view; when used with a change-requests view, pass `pr_number` to target one PR or omit it to use the latest available PR job. Use `CHECKMARX_DSCAN_DATA_SOURCE=live` when you want to call Jenkins and optional Checkmarx enrichment live.
- `sonar`
                Use this single tool for all Sonar and local coverage flows. Set `operation=access_probe` to validate Sonar access, `operation=projects` to discover project keys, `operation=remote_report` for the latest Sonar coverage report, `operation=file_detail` for one file, `operation=local_report` to run local pytest coverage and predict whether the current branch is likely to clear the requested threshold before push, or `operation=local_quality_gate` for the same local analysis with an explicit quality-gate pass/fail view. Live `remote_report` responses now include `analysis_context`, `quality_gate`, and `decision_summary` so agents get a direct pass/fail or unknown answer inline, including pull-request scope when SonarQube exposes PR analysis metadata. In live mode, local Sonar operations run `coverage.py` in the workspace, then use SonarQube APIs to resolve the matching project and inspect the current remote quality gate definition and status. All Sonar operations, including `local_report` and `local_quality_gate`, follow `CHECKMARX_DSCAN_DATA_SOURCE`: mock mode returns bundled mock data, and live mode runs the real Sonar or local coverage workflow.

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

Report profiles:

- `compact`
        Default for CLI and MCP exports. Keeps the full `agent_report.vulnerabilities` list and the top remediation summaries, but removes duplicated derived arrays such as repeated top-level findings copies, per-category issue lists, and full actionable/fix target mirrors.
- `full`
        Preserves every derived section for auditing or debugging. Use this only when you explicitly need every redundant view in one JSON payload.

Recommended agent workflow:

1. Read `agent_report.vulnerability_summary` and `agent_report.engine_coverage`.
2. Inspect `agent_report.top_actionable_issues` or `agent_report.top_fix_targets`.
3. If more context is needed, inspect `findings` or `agent_report.vulnerabilities`.
4. If the project name is ambiguous, call `checkmarx_scan` with `scan_mode=projects` and inspect `matches` or `project_resolution.best_match`.
5. If native Checkmarx response details are required, call the tool again with `include_raw=true`.

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

## Fresh machine setup

Use this sequence on a new machine when you want the MCP server and the validation suite to work immediately.

Windows PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[mcp,dev]"
Copy-Item .env.example .env
python -m unittest tests.test_agent_adapters tests.test_config tests.test_project_catalog_service tests.test_project_scan_service tests.test_checkmarx_scan_service tests.test_jenkins_service tests.test_sonar_service
checkmarx-mcp-server
```

macOS or Linux:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[mcp,dev]'
cp .env.example .env
python -m unittest tests.test_agent_adapters tests.test_config tests.test_project_catalog_service tests.test_project_scan_service tests.test_checkmarx_scan_service tests.test_jenkins_service tests.test_sonar_service
checkmarx-mcp-server
```

If you do not need the MCP server, install with `pip install -e .[dev]` instead. If you only need the runtime CLI entrypoints, `pip install -e .` is sufficient.

For the most portable demo setup, keep `.env` in mock mode first, verify the tests pass, and only then switch the machine to live credentials.

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

For SonarQube coverage, prefer a dedicated service account with a user token and only the minimum browse permissions needed for the target projects.

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

### SonarQube

Required for Sonar MCP coverage tools that talk to a SonarQube server.

- `SONAR_BASE_URL` or `SONAR_HOST_URL`
        Example: `http://sonar.multiplan.com`

Optional but recommended:

- `SONAR_TOKEN` or `SONAR_API_TOKEN`
        Prefer a user token from a dedicated service account.
- `SONAR_TIMEOUT`

Recommended minimum Sonar permissions for the token's backing account:

- `Browse` on the target projects for project, branch, and measure access.
- `See Source Code` on the target projects if you want source excerpts and best-effort line-level detail.

If no token is configured, the Sonar tool will attempt anonymous access and clearly report that mode in the tool output. For `operation=local_report` and `operation=local_quality_gate`, no Sonar base URL is required.

For `operation=remote_report`, `local_report`, and `local_quality_gate`, the MCP server runs real Sonar or local coverage analysis only when `CHECKMARX_DSCAN_DATA_SOURCE=live`. In that live path it uses SonarQube APIs such as project discovery, branch lookup, measures, file/component lookup, source lookup, and `api/qualitygates/project_status` to connect the current workspace to the remote Sonar project and quality gate. When a `pull_request` is provided, the server also attempts to resolve PR-specific analysis metadata if the SonarQube instance exposes that capability. In mock mode it returns the bundled Sonar payloads, consistent with the rest of the mock-only demo flow.

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

SONAR_BASE_URL=http://sonar.multiplan.com
SONAR_TOKEN=your_sonar_user_token

# Optional: switch the tool adapters between bundled demo data and live APIs.
# This is the single source of truth for mode selection.
# Default is mock in this workspace.
CHECKMARX_DSCAN_DATA_SOURCE=mock
```

Minimal `.env` for mock-only MCP usage:

```dotenv
CHECKMARX_DSCAN_DATA_SOURCE=mock
```

That single variable is the only `.env` entry you need to force bundled mock payloads on any machine.

## Mock demo project

The repository now includes a resettable demo target at `demo/mock_providerportal_web`.

The mock Checkmarx findings intentionally point to these real files:

- `demo/mock_providerportal_web/package.json`
- `demo/mock_providerportal_web/package-lock.json`
- `demo/mock_providerportal_web/Dockerfile`
- `demo/mock_providerportal_web/src/server.js`

Recommended demo flow:

1. Keep `CHECKMARX_DSCAN_DATA_SOURCE=mock` in `.env`.
2. Run the MCP server.
3. Ask Copilot to inspect the mock findings and apply the recommended fixes in `demo/mock_providerportal_web`.
4. After the demo, restore the vulnerable baseline with `python tools/mock_demo_project.py reset`.

You can check the current demo-project state with `python tools/mock_demo_project.py status`.

What is mandatory for mock mode:

- `CHECKMARX_DSCAN_DATA_SOURCE=mock`
        Recommended even though the code defaults to `mock`, because it removes ambiguity on fresh machines and in MCP clients.

What is not mandatory for mock mode:

- `CHECKMARX_BASE_URL`
- `CHECKMARX_API_TOKEN`
- `JENKINS_USERNAME`
- `JENKINS_API_TOKEN`
- `SONAR_BASE_URL`
- `SONAR_TOKEN`

Optional convenience values for mock mode:

- `JENKINS_JOB_URL`
        Only useful if you want to call `jenkins_artifact` without passing `job_url` in the CLI or MCP tool call.
- `CHECKMARX_DSCAN_ENV_FILE`
        Useful when your MCP client launches the server outside the workspace root and you want it to load a specific env file.

To switch the same machine to live services later, change `CHECKMARX_DSCAN_DATA_SOURCE=live` and then add only the credentials required by the workflow you intend to call.

## Validation

The validation command used in this workspace for a mock-safe check is:

```bash
python -m unittest tests.test_agent_adapters tests.test_config tests.test_project_catalog_service tests.test_project_scan_service tests.test_checkmarx_scan_service tests.test_jenkins_service tests.test_sonar_service
```

When you want to force mock mode regardless of what is already in the shell environment, set `CHECKMARX_DSCAN_DATA_SOURCE=mock` before running the command.

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

If you want the MCP server to stay fully offline and use bundled demo data, make sure `.env` contains `CHECKMARX_DSCAN_DATA_SOURCE=mock` before starting it.

The MCP server exposes three tools:

- `checkmarx_scan`
                Runs a live Checkmarx upload scan and returns structured JSON.
- `jenkins_artifact`
                Pulls an archived Checkmarx report from Jenkins and returns structured JSON.
- `sonar`
                Unified Sonar and local coverage tool. Use `operation=access_probe`, `projects`, `remote_report`, `file_detail`, or `local_report` depending on the workflow.

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
                                "CHECKMARX_API_TOKEN": "${input:checkmarxApiToken}",
                                "SONAR_BASE_URL": "http://sonar.multiplan.com",
                                "SONAR_TOKEN": "${input:sonarToken}"
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
                                "CHECKMARX_API_TOKEN": "${input:checkmarxApiToken}",
                                "SONAR_BASE_URL": "http://sonar.multiplan.com",
                                "SONAR_TOKEN": "${input:sonarToken}"
                        }
                }
        }
}
```

If your MCP client launches the server from a directory other than the repository root, a relative `env_file` such as `.env` may not be found where you expect. This server now searches parent directories for relative env files, but the most reliable options are still either:

- pass `env_file` as an absolute path in the tool call, or
- inject `CHECKMARX_BASE_URL`, `CHECKMARX_API_TOKEN`, `SONAR_BASE_URL`, and `SONAR_TOKEN` directly into the MCP server process environment.

For local workspace use, the server also supports `CHECKMARX_DSCAN_ENV_FILE` or `CHECKMARX_ENV_FILE` in the MCP server process environment. Point that variable at your workspace `.env` file when you want the server to load credentials from the repo without duplicating them in the client config.

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

### MCP call fails with `Cannot read properties of undefined (reading 'invoke')`

That error is typically from the MCP client layer, not from this Python server. The usual causes are:

1. The Copilot MCP client has stale tool metadata after a schema change. Restart the MCP server or reload the VS Code window.
2. The MCP server is not connected or failed during startup, so the client has no live `checkmarx_scan` tool instance to invoke.
3. The MCP server was launched without the environment it needs.

Recommended setup for Copilot MCP:

1. Prefer injecting `CHECKMARX_BASE_URL` and `CHECKMARX_API_TOKEN` in the MCP server `env` block.
2. If you want to keep secrets only in the workspace, set `CHECKMARX_DSCAN_ENV_FILE` to the absolute path of the workspace `.env` in the MCP server `env` block.
3. Only rely on implicit `.env` discovery when the server is running from the same repo layout and you are comfortable with that coupling.

## Local validation

```bash
pytest
```