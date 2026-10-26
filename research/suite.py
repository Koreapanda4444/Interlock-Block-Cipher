"""Regenerate one coherent bounded evidence bundle; refuse stale/mixed reports."""

import argparse
import copy
import hashlib
import json
import subprocess
import sys

from common import ROOT, Session, fingerprints, require

COMMANDS = (
    ("oracle", ["research/common.py"]),
    ("support", ["research/support.py"]),
    ("components", ["research/components.py"]),
    ("addition", ["research/addition.py"]),
    ("analysis", ["research/analyze.py"]),
    ("differential", ["research/differential.py"]),
    ("symmetry", ["research/symmetry.py"]),
    ("integral", ["research/integral.py"]),
    ("extension", ["research/differential.py", "--extend"]),
)


def validate(document, name, expected, binary):
    require(document.get("status") == "completed" and document.get("experiment") == name,
            f"incomplete/wrong report: {name}")
    require(document["source_sha256"] == expected, f"mixed/stale source fingerprints: {name}")
    require(document["binary_sha256"] == binary, f"mixed binaries: {name}")
    require(document["result"].get("mode", "full") == "full", f"smoke report in full bundle: {name}")
    total = 0
    for label,value in document["query_ledger"].items():
        direction,rounds = label.split("/")
        require(direction in ("forward","inverse") and 0 <= int(rounds) <= 28, "invalid oracle label")
        require(type(value) is int and value >= 0, "invalid query count")
        total += value
    require(total == document["oracle_queries"] <= document["query_budget"], f"query ledger mismatch: {name}")


def check():
    document = json.loads((ROOT / "build/oracle.json").read_bytes())
    expected = fingerprints()
    binary = hashlib.sha256((ROOT / "build/verify.so").read_bytes()).hexdigest()
    validate(document,"oracle",expected,binary)
    stale = copy.deepcopy(document)
    stale["source_sha256"]["docs/spec_ko.md"] = "0"*64
    mismatch = copy.deepcopy(document)
    mismatch["oracle_queries"] += 1
    smoke = copy.deepcopy(document)
    smoke["result"]["mode"] = "smoke"
    for altered in (stale,mismatch,smoke):
        try:
            validate(altered,"oracle",expected,binary)
        except AssertionError:
            pass
        else:
            raise AssertionError("stale, inconsistent or smoke evidence must be rejected")
    print("Evidence gates reject stale sources, inconsistent ledgers and smoke reports")


def main():
    session = Session(0x5355495445,max_queries=1 << 26,seconds=180)
    expected = fingerprints()
    binary = hashlib.sha256((ROOT / "build/verify.so").read_bytes()).hexdigest()
    # Only known generated reports are removed. Other build files are untouched.
    for name in [*(name for name,_ in COMMANDS), "summary"]:
        (ROOT / "build" / f"{name}.json").unlink(missing_ok=True)
    reports,records = {},[]
    for name,arguments in COMMANDS:
        session.reserve(0,0,False)
        subprocess.run([sys.executable,*arguments],cwd=ROOT,check=True,timeout=60)
        path = ROOT / "build" / f"{name}.json"
        raw = path.read_bytes()
        document = json.loads(raw)
        validate(document,name,expected,binary)
        for label,value in document["query_ledger"].items():
            direction,rounds = label.split("/")
            session.reserve(value,int(rounds),direction == "inverse")
        reports[name] = document
        records.append({"experiment": name, "report_sha256": hashlib.sha256(raw).hexdigest(),
                        "oracle_queries": document["oracle_queries"],
                        "wall_seconds": document["wall_seconds"], "peak_rss_kib": document["peak_rss_kib"]})
    require(fingerprints() == expected, "sources changed during evidence generation")
    fm = reports["components"]["result"]
    summary = {"child_reports": records, "child_report_count": len(records),
        "query_unit": "one block evaluated by one specified prefix/inverse oracle; isolated components are separate",
        "ledger_semantics": "aggregate of child experiment ledgers; runner makes no direct oracle calls",
        "max_child_peak_rss_kib": max(r["peak_rss_kib"] for r in records),
        "key_risks": {"max_held_out_local_fm_bit_bias": max(r["max_abs_bit_bias"] for r in fm["fm_validation"]),
                      "full_round_security": "unverified", "release_approved": False},
        "scope_limits": ["finite fixed-key marginal screens are not trail/hull bounds",
                         "no full-round attack or master-key recovery result",
                         "boomerang, MITM, linear hulls and broad related-key classes remain open"]}
    session.save("summary",summary)
    print(f"Evidence bundle complete: {len(records)} experiments, {session.queries} block queries; security unverified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    check() if args.check else main()
