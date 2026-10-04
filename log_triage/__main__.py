import argparse
import collections
import sys

from .aggregate import triage


def main(argv=None):
    p = argparse.ArgumentParser(prog="log_triage", description="Rules + aggregation triage of a log file.")
    p.add_argument("logfile")
    p.add_argument("--window", type=float, default=60)
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--show", type=int, default=5, help="incidents to print")
    a = p.parse_args(argv)
    with open(a.logfile, errors="replace") as f:
        ev = triage(f, window=a.window, threshold=a.threshold)
    c = collections.Counter(e.label or "undecided" for e in ev)
    print(f"{len(ev)} lines:", dict(c))
    print("act reasons:", dict(collections.Counter(e.reason.split(":")[0] for e in ev if e.label == "act")))
    for e in [e for e in ev if e.label == "act"][: a.show]:
        print(f"  line {e.index + 1} [{e.source}] {e.reason}: {e.line[:90]}")
    return 0


raise SystemExit(main(sys.argv[1:]))
