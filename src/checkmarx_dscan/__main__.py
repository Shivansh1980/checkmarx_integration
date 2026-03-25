from __future__ import annotations

import sys

from .domain.errors import CheckmarxError
from .interfaces.cli.scan import main


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CheckmarxError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("Error: interrupted", file=sys.stderr)
        raise SystemExit(130)