"""Aggregation: turn floods of similar `watch` events into single incidents.

Per source (first IPv4 in the line), within a sliding window:
  * N watch events in W seconds           -> one `act` incident (reason burst:n/W s)
  * a successful login after recent watch -> `act` (success-after-failures)
  * further events while an incident is open are suppressed to `watch` (reason in-incident)
  * repeated `act` lines for the same source inside the cooldown collapse to `watch` (duplicate)
Events with no source are never deduplicated: an `act` stays an `act`.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from .rules import classify_line

IP = re.compile(r"\b(?!0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}\b")
SUCCESS = re.compile(r"Accepted (password|publickey|keyboard-interactive) for")
SYSLOG_TS = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")
ISO_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")


@dataclass
class Event:
    index: int
    ts: float | None
    source: str | None
    line: str
    label: str | None
    reason: str


def parse_ts(line: str, year: int = 2000) -> float | None:
    m = ISO_TS.search(line)
    if m:
        return datetime.fromisoformat(m.group(1).replace(" ", "T")).timestamp()
    m = SYSLOG_TS.match(line)
    if m:
        s = " ".join(m.group(1).split())
        return datetime.strptime(f"{year} {s}", "%Y %b %d %H:%M:%S").timestamp()
    return None


def parse_source(line: str) -> str | None:
    m = IP.search(line)
    return m.group(0) if m else None


class Aggregator:
    def __init__(self, window: float = 60, threshold: int = 5, lookback: float = 600, cooldown: float = 600):
        self.window, self.threshold, self.lookback, self.cooldown = window, threshold, lookback, cooldown
        self._watch: dict[str, deque] = defaultdict(deque)   # source -> recent watch timestamps
        self._incident_until: dict[str, float] = {}           # source -> time the open incident expires
        self._last_act: dict[str, float] = {}
        self._last_seen: dict[str, float] = {}

    def _prune(self, src: str, now: float, horizon: float) -> deque:
        q = self._watch[src]
        while q and now - q[0] > horizon:
            q.popleft()
        return q

    def feed(self, index: int, line: str, level: str | None = None) -> Event:
        v = classify_line(line, level)
        ts, src = parse_ts(line), parse_source(line)
        label, reason = v.label, v.reason
        if ts is None or src is None:
            return Event(index, ts, src, line, label, reason)

        # successful login after recent failures from the same source
        if SUCCESS.search(line):
            q = self._prune(src, ts, self.lookback)
            if q:
                label, reason = "act", f"success-after-failures:{len(q)}"
        elif label == "watch":
            q = self._prune(src, ts, self.window)
            q.append(ts)
            if ts < self._incident_until.get(src, -1):
                reason = "in-incident"
                self._incident_until[src] = ts + self.window
            elif len(q) >= self.threshold:
                label, reason = "act", f"burst:{len(q)}/{int(self.window)}s"
                self._incident_until[src] = ts + self.window
        if label == "act" and not reason.startswith(("burst", "success")):
            # source-level dedupe of repeated act lines (e.g. repeated break-in warnings)
            if ts - self._last_act.get(src, -1e18) < self.cooldown:
                label, reason = "watch", "duplicate-of-incident"
        if label == "act":
            self._last_act[src] = ts
            if reason.startswith("success"):
                self._watch[src].clear()
        return Event(index, ts, src, line, label, reason)


def triage(lines, **kw) -> list[Event]:
    agg = Aggregator(**kw)
    return [agg.feed(i, l.rstrip("\n")) for i, l in enumerate(lines)]
