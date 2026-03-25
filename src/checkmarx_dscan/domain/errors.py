from __future__ import annotations


class CheckmarxError(RuntimeError):
	"""Base exception for Checkmarx scan orchestration failures."""


class JenkinsError(CheckmarxError):
	"""Raised when Jenkins artifact retrieval fails."""


class CrewAIToolDependencyError(CheckmarxError):
	"""Raised when CrewAI-specific dependencies are unavailable."""


class MCPServerDependencyError(CheckmarxError):
	"""Raised when MCP server dependencies are unavailable."""
