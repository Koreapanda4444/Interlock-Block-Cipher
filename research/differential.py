"""Chosen-plaintext bit-marginal survey with disjoint training and holdout pairs."""

import argparse
import hashlib
import json
import math
import random

from common import ROOT, Oracle, Session, difference_counts, require

SEED = 0x444946464552454e

CORE_PATHS = ("docs/spec_ko.md", "include/interlock.h", "src/interlock.c",
              "src/interlock_internal.h", "src/shake256.c", "src/shake256.h", "tests/vectors.h")


def compatible(document):
    require(document.get("status") == "completed" and document.get("experiment") == "differential",
            "a completed four-round survey is required")
    for path in CORE_PATHS:
        require(document["source_sha256"].get(path) == hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
                f"stale parent survey: {path}")


def bases(delta, count, seed, forbidden=()):
    if not 0 < delta < 1 << 128 or not 1 <= count <= 65536:
        raise ValueError("nonzero 128-bit difference and 1..65536 pairs required")
    rng = random.Random(seed)
    pivot = delta & -delta
    seen = set(forbidden)
    result = []
    while len(result) < count:
        value = rng.getrandbits(128) & ~pivot
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def measure(oracle, delta, count, rounds, seed, forbidden=()):
    values = bases(delta,count,seed,forbidden)
    inputs = b"".join(x.to_bytes(16,"little") + (x ^ delta).to_bytes(16,"little") for x in values)
    output = oracle.blocks(inputs,rounds)
    counts = difference_counts(output,lib=oracle.lib)
    worst = max(range(128),key=lambda b: abs(counts[b]/count-0.5))
    return {"input_difference": f"{delta:032x}", "rounds": rounds, "samples": count,
            "seed": hex(seed), "input_sha256": hashlib.sha256(inputs).hexdigest(),
            "bit_counts": counts, "worst_bit": worst, "worst_probability": counts[worst]/count,
            "max_abs_bit_bias": abs(counts[worst]/count-0.5)}


def check():
    session = Session(SEED,max_queries=4096)
    with Oracle(session,bytes(32)) as oracle:
        for delta in (1,(1 << 127),(1 << 128)-1,0x80000001000000800000000100000080):
            first = bases(delta,32,SEED)
            second = bases(delta,32,SEED ^ 1,first)
            require(len(set(first+second)) == 64, "disjoint canonical input pairs")
            row = measure(oracle,delta,32,0,SEED)
            require(row["bit_counts"] == [32 if (delta >> b) & 1 else 0 for b in range(128)],
                    "independent identity-pair counter")
    print("Differential sampler, disjoint split and 128-bit counter checks passed")
    document = {"status": "completed", "experiment": "differential", "source_sha256": {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in CORE_PATHS}}
    compatible(document)
    document["source_sha256"]["docs/spec_ko.md"] = "0"*64
    try:
        compatible(document)
    except AssertionError:
        pass
    else:
        raise AssertionError("stale parent must be rejected")


def survey():
    session = Session(SEED,max_queries=1 << 23)
    rng = random.Random(SEED)
    keys = [bytes(32),b"\xff"*32,bytes(range(32)),rng.randbytes(32)]
    deltas = sorted({*(1 << b for b in range(128)),
                     *(3 << (32*w+b) for w in range(4) for b in (0,7,15,23,30)),
                     *(15 << (4*n) for n in range(32)),
                     0x00000001000000010000000100000001,(1 << 128)-1,
                     int.from_bytes(b"\xaa"*16,"little"),int.from_bytes(b"\x55"*16,"little")})
    training,validation = [],[]
    for ki,key in enumerate(keys):
        with Oracle(session,key) as oracle:
            per_key = []
            for delta in deltas:
                seed = SEED ^ (ki << 136) ^ delta
                row = measure(oracle,delta,1024,4,seed)
                row["key_index"] = ki
                per_key.append(row)
                training.append(row)
            selected = sorted(per_key,key=lambda r: (-r["max_abs_bit_bias"],r["input_difference"]))[:8]
            for row in selected:
                delta = int(row["input_difference"],16)
                train_seed = int(row["seed"],16)
                held = measure(oracle,delta,16384,4,train_seed ^ 0x484f4c444f5554,
                               bases(delta,1024,train_seed))
                held.update({"key_index": ki, "training_seed": row["seed"],
                             "training_worst_bit": row["worst_bit"],
                             "training_max_abs_bit_bias": row["max_abs_bit_bias"],
                             "training_input_sha256": row["input_sha256"], "disjoint_plaintext_pairs": True})
                validation.append(held)
    tests = len(validation)*128
    threshold = math.sqrt(math.log(2*tests/0.01)/(2*16384))
    selection = [{"key_index": r["key_index"], "input_difference": r["input_difference"],
                  "training_seed": r["training_seed"], "validation_seed": r["seed"]} for r in validation]
    session.save("differential", {"model": "same-master-key four-round encryption, chosen plaintext pairs",
        "keys_hex": [k.hex() for k in keys], "candidate_differences": len(deltas),
        "training": training, "validation": validation, "frozen_selection": selection,
        "validation_family_tests": tests, "reference_family_alpha": 0.01,
        "bernoulli_reference_bias_threshold": threshold,
        "limits": "bit marginals only, IID reference with ideal-permutation birthday approximation; no trail/hull search"})
    print(f"four-round survey: differences={len(deltas)}, train={len(training)}, holdout={len(validation)}, "
          f"max held-out bias={max(r['max_abs_bit_bias'] for r in validation):.6f}, "
          f"reference exceedances={sum(r['max_abs_bit_bias'] > threshold for r in validation)}/{len(validation)}")


def extend():
    parent = ROOT / "build/differential.json"
    if not parent.is_file():
        raise SystemExit("Run the four-round survey before --extend (or use make research)")
    raw = parent.read_bytes()
    document = json.loads(raw)
    compatible(document)
    previous = document["result"]
    frozen = [{"key_index": r["key_index"], "input_difference": r["input_difference"],
               "training_seed": r["training_seed"], "validation_seed": r["seed"]}
              for r in previous["validation"]]
    require(frozen == previous["frozen_selection"], "candidate selection changed after validation")
    session = Session(SEED ^ 0x455854454e44,max_queries=1 << 22)
    rows = []
    for source in previous["validation"]:
        ki = source["key_index"]
        delta = int(source["input_difference"],16)
        train = bases(delta,1024,int(source["training_seed"],16))
        holdout = bases(delta,source["samples"],int(source["seed"],16),train)
        for values,expected in ((train,source["training_input_sha256"]),(holdout,source["input_sha256"])):
            packed = b"".join(x.to_bytes(16,"little") + (x ^ delta).to_bytes(16,"little") for x in values)
            require(hashlib.sha256(packed).hexdigest() == expected, "parent input replay mismatch")
        used = set(train+holdout)
        with Oracle(session,bytes.fromhex(previous["keys_hex"][ki])) as oracle:
            for rounds in range(5,9):
                seed = session.seed ^ (ki << 136) ^ delta ^ (rounds << 160)
                fresh = bases(delta,8192,seed,used)
                row = measure(oracle,delta,8192,rounds,seed,used)
                used.update(fresh)
                row.update({"key_index": ki, "parent_validation_input_sha256": source["input_sha256"],
                            "disjoint_from_training_holdout_and_other_rounds": True})
                rows.append(row)
    require(session.queries == 2*8192*len(rows), "extension oracle accounting")
    tests = len(rows)*128
    threshold = math.sqrt(math.log(2*tests/0.01)/(2*8192))
    session.save("extension", {"model": "fixed four-round candidate inputs, fresh same-key prefix queries at rounds 5..8",
        "parent_report_sha256": hashlib.sha256(raw).hexdigest(),
        "selection_sha256": hashlib.sha256(json.dumps(frozen,sort_keys=True).encode()).hexdigest(),
        "frozen_selection": frozen, "master_keys_hex": previous["keys_hex"], "rows": rows,
        "validation_family_tests": tests, "reference_family_alpha": 0.01,
        "bernoulli_reference_bias_threshold": threshold,
        "limits": "finite bit-marginal extension only; no optimized trail, hull, linear or master-key recovery search"})
    for rounds in range(5,9):
        selected = [r for r in rows if r["rounds"] == rounds]
        print(f"extension rounds={rounds}: max bit bias={max(r['max_abs_bit_bias'] for r in selected):.6f}, "
              f"reference exceedances={sum(r['max_abs_bit_bias'] > threshold for r in selected)}/{len(selected)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check",action="store_true")
    group.add_argument("--extend",action="store_true")
    args = parser.parse_args()
    check() if args.check else extend() if args.extend else survey()
