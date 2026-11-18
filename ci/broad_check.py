"""Run the repository's broad local check: fmt, clippy, tests and cargo-deny if installed.

Stdlib only: ``python3 ci/broad_check.py``. It mirrors the fmt, clippy, test and deny CI jobs and
exits with the first failing status. Extra arguments go to ``cargo test``.
Set ``PASEKA_CHECK_JOBS`` to limit parallel compile jobs (default 2).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    fallback = Path.home() / ".cargo" / "bin" / name
    if fallback.is_file() and os.access(fallback, os.X_OK):
        return str(fallback)
    return None


def steps(cargo: str, jobs: str, test_args: list[str]) -> list[list[str]]:
    out = [
        [cargo, "fmt", "--all", "--check"],
        [cargo, "clippy", "--workspace", "--all-targets", "--locked", "-j", jobs,
         "--", "-D", "warnings"],
        [cargo, "test", "--workspace", "--locked", "-j", jobs, *test_args],
    ]
    if _tool("cargo-deny"):
        out.append([cargo, "deny", "check", "advisories", "bans", "licenses", "sources"])
    else:
        print("broad_check: cargo-deny not installed, skipping deny", file=sys.stderr)
    return out


def main(argv: list[str]) -> int:
    cargo = _tool("cargo")
    if cargo is None:
        raise SystemExit("broad_check: cargo not found on PATH or in ~/.cargo/bin")
    jobs = os.environ.get("PASEKA_CHECK_JOBS", "2")
    for step in steps(cargo, jobs, argv):
        print("broad_check: " + " ".join(step[1:]), file=sys.stderr, flush=True)
        status = subprocess.run(step, cwd=ROOT, check=False).returncode
        if status != 0:
            print(f"broad_check: failed with status {status}", file=sys.stderr, flush=True)
            return status
    print("broad_check: ok", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
