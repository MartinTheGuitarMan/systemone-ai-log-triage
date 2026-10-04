import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from log_triage.rules import classify_line  # noqa: E402


@pytest.mark.parametrize("line", [
    'INFO:     10.0.0.1:48948 - "GET /api/health HTTP/1.1" 200 OK',
    "INFO:     Shutting down",
    "INFO:     Waiting for application shutdown.",
    "INFO:     Application shutdown complete.",
    "INFO:     Finished server process [42]",
    "[2026-10-02 07:33:21 +0000] [40] [INFO] Using worker: sync",
    "[2026-10-02 07:33:21 +0000] [41] [INFO] Booting worker with pid: 41",
    "[2026-10-01 18:24:35 +0000] [40] [INFO] Handling signal: term",
    "[2026-10-02 07:33:22 +0000] [40] [INFO] Control socket listening at /opt/render/.gunicorn/gunicorn.ctl",
    '127.0.0.1 - - [02/Oct/2026:07:33:29 +0000] "GET /favicon.ico HTTP/1.1" 401 23 "https://x.onrender.com/" "Mozilla/5.0"',
    '127.0.0.1 - - [02/Oct/2026:07:33:30 +0000] "HEAD / HTTP/1.1" 401 0 "-" "Mozilla/5.0"',
])
def test_known_noise_is_ignored(line):
    assert classify_line(line, "info").label == "ignore"


@pytest.mark.parametrize("line,level", [
    ("Traceback (most recent call last):", "info"),
    ("sqlalchemy.exc.OperationalError: connection refused", "info"),
    ("Worker (pid:41) was sent SIGKILL! Perhaps out of memory?", "info"),
    ('INFO:     10.0.0.1:1 - "GET /api/musicians HTTP/1.1" 500 Internal Server Error', "info"),
    ("something odd", "error"),
    ("something odd", "WARNING"),
    ("[CRITICAL] WORKER TIMEOUT (pid:41)", "info"),
])
def test_critical_always_acts(line, level):
    assert classify_line(line, level).label == "act"


def test_noise_cannot_hide_a_failure():
    # health-check path but not a 200, and a lifecycle phrase carrying an error
    assert classify_line('"GET /api/health HTTP/1.1" 503 Service Unavailable', "info").label == "act"
    assert classify_line("Shutting down: worker failed to boot", "info").label == "act"


def test_unknown_is_undecided():
    assert classify_line('INFO:     1.2.3.4:5 - "GET /api/musicians?q=x HTTP/1.1" 200 OK', "info").label is None
