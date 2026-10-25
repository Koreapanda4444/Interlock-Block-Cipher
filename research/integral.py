"""Exhaustive fixed-key subcubes; observed zero sums are not universal proofs."""

import argparse
import hashlib
import random

from common import Oracle, Session, require

SEED = 0x494e54454752414c


def cube(base, offset, dimension):
    if not 0 <= offset < 128 or not 1 <= dimension <= 16 or offset+dimension > 128:
        raise ValueError("invalid 128-bit cube")
    free = ((1 << dimension)-1) << offset
    fixed = base & (((1 << 128)-1) ^ free)
    return b"".join((fixed | (value << offset)).to_bytes(16,"little") for value in range(1 << dimension))


def xor_sum(data):
    if len(data) % 16:
        raise ValueError("whole blocks required")
    result = 0
    for i in range(0,len(data),16):
        result ^= int.from_bytes(data[i:i+16],"little")
    return result


def analyze(quick=False):
    session = Session(SEED,max_queries=1 << 22)
    rng = random.Random(SEED)
    dimension = 4 if quick else 16
    keys = [bytes(32)] if quick else [bytes(32),bytes(range(32)),rng.randbytes(32)]
    rows = []
    for ki,key in enumerate(keys):
        with Oracle(session,key) as oracle:
            for offset in (0,96):
                base = rng.getrandbits(128)
                data = cube(base,offset,dimension)
                digest = hashlib.sha256(data).hexdigest()
                for rounds in (range(1,4) if quick else range(1,9)):
                    total = xor_sum(oracle.blocks(data,rounds))
                    if rounds == 1 and offset == 0:
                        require(total == 0, "one-round a-cube degree bound contradicted")
                    rows.append({"key_index": ki, "rounds": rounds, "cube_offset": offset,
                                 "dimension": dimension, "base_hex": f"{base:032x}",
                                 "oracle_queries": 1 << dimension, "input_sha256": digest,
                                 "xor_sum_hex": f"{total:032x}", "zero_sum": total == 0,
                                 "even_parity_output_bits": 128-total.bit_count()})
    session.save("integral", {"mode": "smoke" if quick else "full",
        "model": "chosen-plaintext subcube, enumerate every free-bit assignment, fixed master key",
        "master_keys_hex": [k.hex() for k in keys], "rows": rows,
        "ideal_zero_sum_probability_upper_bound": f"1/(2^128-{1 << dimension}+1)",
        "proven_case": "one-round a-only cube of dimension >=4: output degree <=3, XOR sum zero for every key",
        "limitations": "all other zero sums are observations on these keys/bases only; not a degree/hull proof"})
    for rounds in range(1,4 if quick else 9):
        selected = [r for r in rows if r["rounds"] == rounds]
        print(f"integral rounds={rounds}: zero sums={sum(r['zero_sum'] for r in selected)}/{len(selected)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    analyze(args.check)
