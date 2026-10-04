import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from log_triage.aggregate import Aggregator  # noqa: E402


def fail(sec, ip="1.2.3.4"):
    return f"Dec 10 06:{sec // 60:02d}:{sec % 60:02d} h sshd[1]: Failed password for root from {ip} port 22 ssh2"


def run(lines, **kw):
    a = Aggregator(**kw)
    return [a.feed(i, l) for i, l in enumerate(lines)]


def test_burst_escalates_once_and_suppresses_rest():
    ev = run([fail(i) for i in range(10)], window=60, threshold=5)
    labels = [e.label for e in ev]
    assert labels[:4] == ["watch"] * 4
    assert labels[4] == "act" and ev[4].reason.startswith("burst")
    assert all(l == "watch" for l in labels[5:])
    assert ev[5].reason == "in-incident"


def test_slow_failures_do_not_burst():
    ev = run([fail(i * 30) for i in range(10)], window=60, threshold=5)
    assert all(e.label == "watch" for e in ev)


def test_sources_are_independent():
    ev = run([fail(i, ip=f"9.9.9.{i}") for i in range(10)], window=60, threshold=5)
    assert all(e.label == "watch" for e in ev)


def test_success_after_failures_is_act():
    lines = [fail(1), fail(2), "Dec 10 06:00:30 h sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"]
    ev = run(lines)
    assert ev[2].label == "act" and ev[2].reason.startswith("success-after-failures")


def test_plain_success_is_ignored():
    ev = run(["Dec 10 06:00:30 h sshd[1]: Accepted publickey for martin from 5.6.7.8 port 22 ssh2"])
    assert ev[0].label == "ignore"


def test_success_long_after_failures_is_not_escalated():
    lines = [fail(1), "Dec 10 09:00:00 h sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"]
    assert run(lines, lookback=600)[1].label == "ignore"


def test_repeated_break_in_warnings_dedupe_per_source():
    w = "Dec 10 06:00:{s:02d} h sshd[1]: reverse mapping for x [1.2.3.4] failed - POSSIBLE BREAK-IN ATTEMPT!"
    ev = run([w.format(s=i) for i in range(5)])
    assert [e.label for e in ev] == ["act", "watch", "watch", "watch", "watch"]


def test_sourceless_act_is_never_deduplicated():
    ev = run(["Traceback (most recent call last):"] * 3)
    assert [e.label for e in ev] == ["act"] * 3
