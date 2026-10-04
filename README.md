# log-triage

Rules-first triage of log lines and alarms, with a small local decision model for what the rules leave open.
Labels: `ignore` / `watch` / `act`. Work in progress.

Design notes:
- Hard rules run before any model. Critical patterns are checked first so known-noise rules can never hide a real failure.
- Repeated, similar events should be aggregated per source and escalated on patterns (burst, break-in warning,
  success after failures), not alerted line by line. The same idea applies to alarm floods in any monitored system.
- Calibrate any model threshold on a reviewed sample before acting on its output.

```bash
uv venv --python 3.12 .venv && uv pip install -r requirements.txt -p .venv/bin/python
.venv/bin/python -m pytest -q
```

Test data (not included): public logs from [Loghub](https://github.com/logpai/loghub), e.g. OpenSSH_2k.log, placed in `data/`.
