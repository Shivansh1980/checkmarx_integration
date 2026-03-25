from __future__ import annotations

def jenkins_main(argv=None):
	from .jenkins import main

	return main(argv)


def parse_jenkins_args(argv):
	from .jenkins import parse_args

	return parse_args(argv)


def scan_main(argv=None):
	from .scan import main

	return main(argv)


def parse_scan_args(argv):
	from .scan import parse_args

	return parse_args(argv)

__all__ = ["jenkins_main", "parse_jenkins_args", "parse_scan_args", "scan_main"]