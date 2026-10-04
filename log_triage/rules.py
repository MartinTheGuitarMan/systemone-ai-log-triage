"""Hard rules for log lines, evaluated before any model.

Order matters: critical patterns are checked first so that a known-noise pattern can never
hide a real problem. Labels: act | ignore. None means "undecided, leave for the model".
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CRITICAL = re.compile(
    r"\b(error|exception|traceback|fatal|critical|panic|segfault|oom|out of memory|killed|"
    r"timed? ?out|connection refused|connection reset|unavailable|crash(ed)?|failed|failure|"
    r"denied|corrupt)\b|\b5\d\d\b(?=\s+\d|\s*$)|\"\s+5\d\d\s",
    re.I,
)
CRITICAL_LEVELS = {"error", "err", "warn", "warning", "critical", "fatal", "alert", "emerg"}

NOISE = [
    ("health-check", re.compile(r"\"?(GET|HEAD) /(api/)?(health|healthz|ping|status)\b[^\"]*\"? 200")),
    ("server-lifecycle", re.compile(
        r"(Handling signal|Worker exiting|Booting worker|Using worker|Control socket listening|"
        r"Shutting down|Waiting for application|Application shutdown complete|Application startup complete|"
        r"Finished server process|Started server process|Uvicorn running|Starting gunicorn|Listening at|"
        r"Waiting for application startup)", re.I)),
    ("probe-401", re.compile(r"\"(GET|HEAD) (/|/favicon\.ico) HTTP/[\d.]+\" 401\b")),
]


@dataclass(frozen=True)
class Verdict:
    label: str | None
    reason: str


def classify_line(line: str, level: str | None = None) -> Verdict:
    if (level or "").lower() in CRITICAL_LEVELS:
        return Verdict("act", f"level:{level.lower()}")
    if CRITICAL.search(line):
        return Verdict("act", "critical-pattern")
    for name, pat in NOISE:
        if pat.search(line):
            return Verdict("ignore", name)
    return Verdict(None, "undecided")
