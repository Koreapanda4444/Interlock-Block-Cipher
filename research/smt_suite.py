"""Regenerate coherent SMT evidence, retaining UNKNOWN as unresolved research."""

import argparse
import copy
import hashlib
import json
import subprocess
import sys

from common import ROOT, Session, fingerprints, require
from suite import validate

COMMANDS = (
    ("smt_components", []),
    ("smt_traces", ["--traces"]),
    ("smt_pairs", ["--pairs"]),
    ("smt_counts", ["--count"]),
    ("smt_search", ["--search"]),
    ("smt_recovery", ["--recover"]),
    ("smt_full", ["--full"]),
)


def decisions(value):
    if isinstance(value, dict):
        if "formula_sha256" in value:
            require(value.get("status") in ("sat", "unsat", "unknown"), "invalid solver decision")
            require(value.get("timeout_ms", 0) > 0 and value.get("rlimit", -1) >= 0, "missing solver limits")
            require(value["status"] != "unknown" or bool(value.get("reason_unknown")), "unexplained UNKNOWN")
            return [value["status"]]
        return [s for child in value.values() for s in decisions(child)]
    if isinstance(value, list):
        return [s for child in value for s in decisions(child)]
    return []


def check():
    original = {"formula_sha256": "0"*64, "status": "unknown", "reason_unknown": "resource limit",
                "timeout_ms": 1000, "rlimit": 300000}
    require(decisions(original) == ["unknown"], "UNKNOWN must remain unresolved")
    for field, value in (("status", "secure"), ("reason_unknown", ""), ("timeout_ms", 0), ("rlimit", -1)):
        altered = copy.deepcopy(original)
        altered[field] = value
        try:
            decisions(altered)
        except AssertionError:
            pass
        else:
            raise AssertionError(f"invalid solver evidence accepted: {field}")
    print("SMT evidence rejects missing limits, unexplained UNKNOWN and security labels")


def main():
    session = Session(0x534d545355495445, max_queries=1 << 20, seconds=180)
    expected = fingerprints()
    binary = hashlib.sha256((ROOT / "build/verify.so").read_bytes()).hexdigest()
    for name in [*(name for name, _ in COMMANDS), "smt_summary"]:
        (ROOT / "build" / f"{name}.json").unlink(missing_ok=True)
    reports, versions, counts = [], set(), {"sat": 0, "unsat": 0, "unknown": 0}
    for name, arguments in COMMANDS:
        subprocess.run([sys.executable, "research/smt.py", *arguments], cwd=ROOT, check=True, timeout=60)
        path = ROOT / "build" / f"{name}.json"
        raw = path.read_bytes()
        document = json.loads(raw)
        validate(document, name, expected, binary)
        result = document["result"]
        versions.add(result["solver_version"])
        require(len(versions) == 1, "mixed solver versions")
        for status in decisions(result):
            counts[status] += 1
        for label, value in document["query_ledger"].items():
            direction, rounds = label.split("/")
            session.reserve(value, int(rounds), direction == "inverse")
        formulas = []
        for row in result.get("rows", []):
            if "formula_file" in row:
                formula_path = ROOT / "build" / row["formula_file"]
                require(formula_path.parent == ROOT / "build", "formula path outside build")
                digest = hashlib.sha256(formula_path.read_bytes()).hexdigest()
                require(digest == row["formula_sha256"], "formula/report mismatch")
                formulas.append({"path": row["formula_file"], "sha256": digest})
        reports.append({"experiment": name, "report_sha256": hashlib.sha256(raw).hexdigest(),
                        "oracle_queries": document["oracle_queries"], "formulas": formulas})
    require(fingerprints() == expected, "sources changed during SMT generation")
    require(hashlib.sha256((ROOT / "build/verify.so").read_bytes()).hexdigest() == binary, "binary changed during SMT generation")
    session.save("smt_summary", {"child_reports": reports, "solver_version": versions.pop(),
        "decision_counts": counts, "full_round_security": "unverified",
        "limits": "counts mix controls and research queries; UNKNOWN is unresolved, SAT is feasibility, UNSAT is scoped; no attack probability or master-key recovery"})
    print(f"SMT bundle: {len(reports)} reports; {counts}; security unverified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    check() if args.check else main()
