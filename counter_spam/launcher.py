"""Entry point of the stand-alone executables (``.exe`` and binaries).

Started without arguments, typically by a double click, the program opens
the web interface, which is what most users want.  With arguments it is the
usual command line.

When a double click fails, the console window would vanish before the
error could be read: it then waits for the Enter key.
"""

from __future__ import annotations

import sys
from typing import Sequence

from . import cli


def main(argv: Sequence[str] | None = None) -> int:
    """Run Counter-Spam; return the process exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    double_clicked = not args
    try:
        code = cli.main(args or ["gui"])
    except SystemExit as exc:  # Raised by argparse on --help or errors.
        code = exc.code if isinstance(exc.code, int) else 1
    if double_clicked and code not in (cli.EXIT_OK, cli.EXIT_INTERRUPTED):
        _pause()
    return code


def _pause() -> None:
    """Keep the console open until the user has read the error."""
    if not sys.stdin or not sys.stdin.isatty():
        return
    try:
        input("\nPress Enter to close this window.")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    sys.exit(main())
