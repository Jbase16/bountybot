"""Convenience wrapper to run the CLI from the repository root."""

from __future__ import annotations

import sys
from pathlib import Path


def _prepare_src_path() -> None:
    """Ensure the `src` directory is importable when running from the repo root."""
    project_root = Path(__file__).resolve().parent
    src_dir = project_root / "src"
    if not src_dir.exists():
        raise RuntimeError(f"Unable to locate source directory at {src_dir}")

    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))


def main() -> None:
    _prepare_src_path()

    from bountybot.cli import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
