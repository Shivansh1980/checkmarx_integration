# Mock Provider Portal Web

This project is intentionally vulnerable and exists only for the mock Checkmarx demo flow.

Files that the mock scan points to:

- `package.json`
- `package-lock.json`
- `Dockerfile`
- `src/server.js`

Reset the project back to the vulnerable baseline with:

```bash
python tools/mock_demo_project.py reset
```

If Copilot changes the dependencies or Dockerfile during a demo, run that command to restore the original vulnerable files.

## Demoing all three integrations

The project layout is designed so the same source tree can drive each tool in the demo:

- **Checkmarx** — `package.json`, `package-lock.json`, `Dockerfile`, and `src/server.js` host the intentional vulnerabilities surfaced by the `checkmarx_scan` tool.
- **Jenkins** — `Jenkinsfile` shows the pipeline shape (`npm ci`, `npm test`, archive `checkmarx-ast-results.json`) that the `jenkins_artifact` tool inspects. In demo (`mock`) mode the tool ignores the actual `JENKINS_JOB_URL` and returns a bundled fixture, so the file is illustrative only.
- **SonarQube** — `src/utils.js` holds the executable code under test. `tests/utils.test.js` and `tests/server.test.js` are Jest suites that intentionally leave a few branches uncovered (`bronze` / `watchlist` tiers in `classifyProviderTier`, and the entire `maskMemberId` helper) so the `sonar` tool can demonstrate how it surfaces files that need more tests.

### Run the JavaScript test suite locally

```bash
cd demo/mock_providerportal_web
npm install
npm test
```

`npm test` runs Jest with coverage. The generated `coverage/lcov.info` and `coverage/coverage-summary.json` files are what a real SonarQube scanner would consume via `sonar-project.properties` if you wanted to scan this project against a live SonarQube server.

### Demo all three tools in mock mode

The demo workflow is fully usable without Jenkins or SonarQube credentials. Set the global data source — or per-tool overrides — in `.env`:

```dotenv
# Easiest path: run the entire demo offline
CHECKMARX_DSCAN_DATA_SOURCE=mock

# Or keep Checkmarx live while demoing Jenkins and SonarQube from fixtures
CHECKMARX_DSCAN_DATA_SOURCE=live
CHECKMARX_DSCAN_DATA_SOURCE_JENKINS=mock
CHECKMARX_DSCAN_DATA_SOURCE_SONAR=mock
```

With those overrides the `jenkins_artifact` tool no longer requires `JENKINS_JOB_URL` and the `sonar` tool no longer requires `SONAR_BASE_URL`; both return the bundled demo fixtures while `checkmarx_scan` continues to call the real Checkmarx tenant.
