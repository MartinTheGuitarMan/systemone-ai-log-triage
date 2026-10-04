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


def test_failed_login_alone_is_watch_not_act():
    v = classify_line("Dec 10 06:55:48 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2")
    assert v.label == "watch"
    assert classify_line("Invalid user admin from 1.2.3.4").label == "watch"


def test_break_in_warning_is_act():
    assert classify_line("reverse mapping checking getaddrinfo for x [1.2.3.4] failed - POSSIBLE BREAK-IN ATTEMPT!").label == "act"


def test_ssh_ancillary_noise_ignored():
    assert classify_line("Received disconnect from 1.2.3.4: 11: Bye Bye [preauth]").label == "ignore"
    assert classify_line("pam_unix(sshd:auth): check pass; user unknown").label == "ignore"


def test_warning_level_is_watch():
    assert classify_line("something odd", "WARNING").label == "watch"
