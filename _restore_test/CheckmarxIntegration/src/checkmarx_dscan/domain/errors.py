from __future__ import annotations


class CheckmarxError(RuntimeError):
	"""Base exception for Checkmarx scan orchestration failures."""


class JenkinsError(CheckmarxError):
	"""Raised when Jenkins artifact retrieval fails."""


class CrewAIToolDependencyError(CheckmarxError):
	"""Raised when CrewAI-specific dependencies are unavailable."""


class MCPServerDependencyError(CheckmarxError):
	"""Raised when MCP server dependencies are unavailable."""


class SonarError(CheckmarxError):
	"""Raised when SonarQube coverage retrieval fails."""


class SonarHttpError(SonarError):
	"""Raised when a SonarQube HTTP request fails."""

	def __init__(self, message: str, *, status_code: int, url: str = "", auth_mode: str = "") -> None:
		super().__init__(message)
		self.status_code = int(status_code)
		self.url = url
		self.auth_mode = auth_mode


class SonarAuthenticationError(SonarHttpError):
	"""Raised when SonarQube authentication fails."""


class SonarPermissionError(SonarHttpError):
	"""Raised when SonarQube access is denied."""
