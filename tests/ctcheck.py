"""Require a working branch/address detector before auditing the C primitive."""

import json
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]
runner = shlex.split(os.environ.get("VALGRIND", "valgrind"))
checks = (("branch-control", "Conditional jump or move depends on uninitialised value"),
          ("address-control", "Use of uninitialised value"),
          ("positive", "ERROR SUMMARY: 0 errors"))
rows = []
summary = ROOT / "build/ctcheck.json"
summary.unlink(missing_ok=True)
for name, message in checks:
    log = ROOT / "build" / f"ctcheck-{name}.log"
    command = [*runner, "--tool=memcheck", "--error-exitcode=99", "--track-origins=yes",
               f"--log-file={log}", str(ROOT / "build/ctcheck")]
    if name != "positive":
        command.append("--"+name)
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
    expected = 0 if name == "positive" else 99
    evidence = log.read_text() if log.exists() else "Memcheck produced no log"
    if result.returncode != expected or message not in evidence:
        raise AssertionError(f"Memcheck {name} failed: {result.returncode}\n{result.stderr}\n{evidence}")
    rows.append({"check": name, "returncode": result.returncode, "log": log.name})
    print(result.stdout.strip())
summary.write_text(json.dumps({"checks": rows, "scope": "sampled dynamic branch/address taint; no constant-time proof"}, indent=2)+"\n")
print("Memcheck audit passed, including both deliberate leak controls")
