"""Hard per-line rules, evaluated before any model. Labels: act | watch | ignore | None (undecided).

Order matters: strong-critical patterns are checked first so a known-noise pattern can never hide
a real failure. `watch` marks events that are only interesting in aggregate (see aggregate.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ACT_LEVELS = {"error", "err", "critical", "fatal", "alert", "emerg"}
WATCH_LEVELS = {"warn", "warning"}

ACT = re.compile(
    r"\b(error|exception|traceback|fatal|critical|panic|segfault|oom|out of memory|killed|"
    r"timed? ?out|connection refused|connection reset|crash(ed)?|corrupt(ed|ion)?|break-?in)\b|"
    r"failed to (boot|start|connect|load|bind|mount)|\"\s+5\d\d\b|\b5\d\d (Internal|Bad|Service|Gateway)",
    re.I,
)
WATCH = re.compile(r"\b(failed|failure|failures|denied|invalid user|unavailable|did not receive identification)\b", re.I)

NOISE = [
    ("health-check", re.compile(r"\"?(GET|HEAD) /(api/)?(health|healthz|ping|status)\b[^\"]*\"? 200")),
    ("server-lifecycle", re.compile(
        r"(Handling signal|Worker exiting|Booting worker|Using worker|Control socket listening|"
        r"Shutting down|Waiting for application|Application shutdown complete|Application startup complete|"
        r"Finished server process|Started server process|Uvicorn running|Starting gunicorn|Listening at)", re.I)),
    ("probe-401", re.compile(r"\"(GET|HEAD) (/|/favicon\.ico) HTTP/[\d.]+\" 401\b")),
    ("ssh-ancillary", re.compile(
        r"(Received disconnect from .*\[preauth\]|Received disconnect from [\d.]+: 11: Bye Bye|"
        r"Connection closed by .*\[preauth\]|check pass; user unknown|input_userauth_request: invalid user)")),
    ("accepted-login", re.compile(r"Accepted (password|publickey|keyboard-interactive)")),
]


@dataclass(frozen=True)
class Verdict:
    label: str | None
    reason: str


def classify_line(line: str, level: str | None = None) -> Verdict:
    lvl = (level or "").lower()
    if lvl in ACT_LEVELS:
        return Verdict("act", f"level:{lvl}")
    if ACT.search(line):
        return Verdict("act", "critical-pattern")
    for name, pat in NOISE:
        if pat.search(line):
            return Verdict("ignore", name)
    if lvl in WATCH_LEVELS:
        return Verdict("watch", f"level:{lvl}")
    if WATCH.search(line):
        return Verdict("watch", "watch-pattern")
    return Verdict(None, "undecided")
