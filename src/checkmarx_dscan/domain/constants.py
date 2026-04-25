from __future__ import annotations

TOKEN_ENDPOINT_SUFFIX = "protocol/openid-connect/token"
DEFAULT_TIMEOUT = 60
DEFAULT_POLL_INTERVAL = 15
DEFAULT_POLL_TIMEOUT = 7200
DEFAULT_RESULTS_PAGE_SIZE = 500
DEFAULT_RESULTS_LIMIT = 20
DEFAULT_JENKINS_FALLBACK_BUILDS = 10
DEFAULT_CLIENT_ID = "ast-app"
MAX_SINGLE_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024
TERMINAL_SCAN_STATUSES = frozenset({"Completed", "Failed", "Canceled", "Partial"})
SUCCESS_SCAN_STATUSES = frozenset({"Completed", "Partial"})
DEFAULT_JENKINS_ARTIFACT_NAME = "checkmarx-ast-results.json"
DEFAULT_EXCLUDED_DIRS = frozenset(
	{
		".git",
		".hg",
		".svn",
		".venv",
		"venv",
		"__pycache__",
		"node_modules",
	}
)
SCAN_TYPE_ALIASES = {
	"sast": "sast",
	"sca": "sca",
	"kics": "kics",
	"iac": "kics",
	"iac-security": "kics",
}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
ENGINE_ORDER = ("sast", "sca", "kics", "containers", "unknown")
DEFAULT_SCAN_TYPES = ("sast", "sca", "kics")
USER_AGENT = "checkmarx_dscan/0.1.0"
SONAR_PROJECTS_PAGE_SIZE = 100
SONAR_FILE_PAGE_SIZE = 500
SONAR_FILE_QUALIFIER = "FIL"
SONAR_COVERAGE_METRIC_KEYS = (
	"coverage",
	"line_coverage",
	"branch_coverage",
	"lines_to_cover",
	"uncovered_lines",
	"conditions_to_cover",
	"uncovered_conditions",
	"new_coverage",
	"new_lines_to_cover",
	"new_uncovered_lines",
)
SONAR_LOCALLY_EVALUABLE_QUALITY_GATE_METRICS = (
	"coverage",
	"line_coverage",
	"branch_coverage",
)
