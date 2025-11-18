"""Wrapper utilities for executing nuclei scans with curated defaults."""

from __future__ import annotations

import json
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Iterable, List, Sequence

__all__ = [
    "DEFAULT_PROFILE",
    "NucleiExecutionError",
    "NucleiNotInstalled",
    "NucleiScanFailed",
    "NucleiScanResult",
    "NucleiScanTimeout",
    "available_profiles",
    "build_nuclei_command",
    "run_nuclei_scan",
]


class NucleiExecutionError(RuntimeError):
    """Base error for nuclei runner issues."""


class NucleiNotInstalled(NucleiExecutionError):
    """Raised when the nuclei binary cannot be located."""


class NucleiScanTimeout(NucleiExecutionError):
    """Raised when a scan exceeds the configured timeout."""

    def __init__(self, timeout: float | None, command: Sequence[str]):
        msg = (
            f"nuclei scan exceeded timeout ({timeout}s) and was aborted"
            if timeout is not None
            else "nuclei scan exceeded timeout and was aborted"
        )
        super().__init__(msg)
        self.timeout = timeout
        self.command = list(command)


class NucleiScanFailed(NucleiExecutionError):
    """Raised when nuclei exits with a non-zero status."""

    def __init__(self, returncode: int, command: Sequence[str], stderr_tail: List[str]):
        super().__init__(f"nuclei exited with code {returncode}")
        self.returncode = returncode
        self.command = list(command)
        self.stderr_tail = stderr_tail


@dataclass(frozen=True)
class ScanProfile:
    """Collection of nuclei arguments bundled under a friendly name."""

    key: str
    description: str
    args: List[str]


DEFAULT_PROFILE = "fast"

_PROFILES: dict[str, ScanProfile] = {
    "fast": ScanProfile(
        key="fast",
        description="High-signal checks only (critical CVEs and common misconfigurations).",
        args=[
            "-severity",
            "medium,high,critical",
            "-tags",
            "cve,misconfig,exposure",
            "-rate-limit",
            "150",
            "-concurrency",
            "15",
        ],
    ),
    "balanced": ScanProfile(
        key="balanced",
        description="Broader coverage while still filtering to actionable template tags.",
        args=[
            "-severity",
            "low,medium,high,critical",
            "-tags",
            "cve,misconfig,exposure,fuzz",
            "-rate-limit",
            "100",
        ],
    ),
    "thorough": ScanProfile(
        key="thorough",
        description="Full nuclei defaults (no filtering) – can take several minutes.",
        args=[],
    ),
}


def available_profiles() -> dict[str, ScanProfile]:
    """Return the configured scan profiles keyed by name."""

    return dict(_PROFILES)


def build_nuclei_command(
    url: str,
    *,
    profile: str | None = None,
    extra_args: Sequence[str] | None = None,
) -> List[str]:
    """
    Construct the nuclei command for the provided URL/profile combination.

    Exposed separately to keep the behavior testable without invoking nuclei.
    """

    profile_key = (profile or DEFAULT_PROFILE).lower()
    if profile_key not in _PROFILES:
        raise ValueError(f"Unknown scan profile '{profile}'")

    scan_profile = _PROFILES[profile_key]
    cmd: List[str] = [
        "nuclei",
        "-u",
        url,
        "-silent",
        "-jsonl",
        "-no-meta",
        "-stats",
    ]
    cmd.extend(scan_profile.args)
    if extra_args:
        cmd.extend(extra_args)
    return cmd


@dataclass
class NucleiScanResult:
    """Structured response returned from `run_nuclei_scan`."""

    findings: List[dict]
    command: List[str]
    profile: str
    duration: float
    stderr_tail: List[str]


def _collect_stdout(stream, bucket: List[str]) -> None:
    for line in iter(stream.readline, ""):
        bucket.append(line)
    stream.close()


def _relay_stderr(stream, sink: deque[str], prefix: str = "[nuclei] ") -> None:
    for line in iter(stream.readline, ""):
        text = line.rstrip()
        if not text:
            continue

        sink.append(text)
        print(f"{prefix}{text}")
    stream.close()


def run_nuclei_scan(
    url: str,
    *,
    profile: str | None = None,
    timeout: float | None = 180,
    extra_args: Sequence[str] | None = None,
) -> NucleiScanResult:
    """
    Execute nuclei with sane defaults, surfacing progress and enforcing a timeout.
    """

    command = build_nuclei_command(url, profile=profile, extra_args=extra_args)

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise NucleiNotInstalled("Unable to find 'nuclei' on PATH") from exc

    stdout_lines: List[str] = []
    stderr_tail: deque[str] = deque(maxlen=40)

    stdout_thread = threading.Thread(
        target=_collect_stdout,
        args=(proc.stdout, stdout_lines),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_relay_stderr,
        args=(proc.stderr, stderr_tail),
        daemon=True,
    )

    start = time.monotonic()
    stdout_thread.start()
    stderr_thread.start()

    try:
        if timeout is None:
            proc.wait()
        else:
            proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        stdout_thread.join(timeout=1)
        stderr_thread.join(timeout=1)
        raise NucleiScanTimeout(timeout, command) from exc
    finally:
        stdout_thread.join()
        stderr_thread.join()

    duration = time.monotonic() - start
    stderr_lines = list(stderr_tail)

    if proc.returncode not in (0, 1):
        raise NucleiScanFailed(proc.returncode, command, stderr_lines)

    findings: List[dict] = []
    skipped_lines: list[str] = []

    for raw_line in stdout_lines:
        line = raw_line.strip()
        if not line:
            continue

        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            skipped_lines.append(line)

    if skipped_lines:
        print(
            f"[nuclei] Skipped {len(skipped_lines)} non-JSON line(s) from stdout (showing last):"
        )
        print(f"[nuclei] {skipped_lines[-1]}")

    return NucleiScanResult(
        findings=findings,
        command=command,
        profile=(profile or DEFAULT_PROFILE).lower(),
        duration=duration,
        stderr_tail=stderr_lines,
    )
