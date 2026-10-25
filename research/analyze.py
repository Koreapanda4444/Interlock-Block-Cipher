"""Reproduce exact component properties and a bounded reduced-round screen.

This is neither a full-round attack search nor a security acceptance test.
The unspecified historical four-round experiment cannot be reproduced here.
"""

import argparse
import ctypes as C
import math
from pathlib import Path
import random
from common import ROOT, Context, Session, U8, array, load_library, ref, require

SEED = 0x494E5445524C4F43


class CountedLibrary:
    def __init__(self, session):
        self.session, self.library = session, load_library()

    def __getattr__(self, name):
        return getattr(self.library,name)

    def il_test_reduced(self, ctx, out, data, rounds):
        self.session.reserve(1,rounds,False)
        return self.library.il_test_reduced(ctx,out,data,rounds)


def sbox_properties(lib):
    s = tuple(lib.il_test_sbox(x) & 15 for x in range(16))
    require(s == ref.SBOX, "C S-box truth table")
    ddt = [[sum((s[x] ^ s[x ^ a]) == b for x in range(16))
            for b in range(16)] for a in range(16)]
    lat = [[sum(1 if ((a & x).bit_count() ^ (b & s[x]).bit_count()) % 2 == 0
                else -1 for x in range(16)) for b in range(16)] for a in range(16)]
    degrees = []
    for bit in range(4):
        coefficients = [(y >> bit) & 1 for y in s]
        for i in range(4):
            for mask in range(16):
                if mask & (1 << i):
                    coefficients[mask] ^= coefficients[mask ^ (1 << i)]
        degrees.append(max(mask.bit_count() for mask in range(16) if coefficients[mask]))
    branch = min(a.bit_count() + b.bit_count()
                 for a in range(1, 16) for b in range(16) if ddt[a][b])
    require(degrees == [2, 3, 3, 3] and branch == 3, "S-box degree and branch")
    # These are component facts, not multi-round active-S-box bounds.
    require(sorted(s) == list(range(16)), "S-box permutation")
    require(max(max(row) for row in ddt[1:]) == 4, "PRESENT differential uniformity")
    require(max(abs(lat[a][b]) for a in range(1, 16) for b in range(1, 16)) == 8,
            "PRESENT Walsh bound")
    return {"ddt": ddt, "lat_walsh": lat, "differential_uniformity": 4,
            "max_nontrivial_abs_walsh": 8, "coordinate_degrees": degrees,
            "differential_bit_branch_number": branch}


def inverse_linear(x):
    for _ in range(31):
        x = ref.linear(x)
    return x


def structural_checks(lib, rng):
    columns = [lib.il_test_linear(1 << bit) for bit in range(32)]
    require(columns == [ref.linear(1 << bit) for bit in range(32)], "C linear basis")
    basis = {}
    for col in columns:
        while col:
            pivot = col.bit_length() - 1
            if pivot in basis:
                col ^= basis[pivot]
            else:
                basis[pivot] = col
                break
    require(len(basis) == 32, "L32 rank")
    for bit in range(32):
        require(inverse_linear(columns[bit]) == 1 << bit, "L inverse basis")
    require(all(c.bit_count() == 3 for c in columns), "L single-bit branch witness")
    inverse_sbox = [ref.SBOX.index(i) for i in range(16)]
    for _ in range(1024):
        x, k = rng.getrandbits(32), rng.getrandbits(32)
        y = lib.il_test_fs(x, k)
        z = inverse_linear(y)
        recovered = x ^ sum(inverse_sbox[(z >> (4*i)) & 15] << (4*i) for i in range(8))
        require(recovered == k, "isolated FS subkey recovery")
    return {"linear_rank": len(basis), "linear_bit_branch_number": 4,
            "inverse_identity": "L^-1 = L^31; L^32 = I",
            "fs_internal_subkey_recoveries": 1024,
            "external_master_key_recovery": "not performed; not implied"}


def one_round_distinguisher(lib):
    seed = SEED ^ 0x53505250
    rng = random.Random(seed)
    for _ in range(16):
        ctx = Context()
        require(lib.interlock_init(C.byref(ctx), array(rng.randbytes(32)), 32) == 0, "attack init")
        for _ in range(64):
            plain = rng.getrandbits(128)
            left, right = (U8 * 16)(), (U8 * 16)()
            require(lib.il_test_reduced(C.byref(ctx), left, array(plain.to_bytes(16, "little")), 1) == 0,
                    "attack left")
            require(lib.il_test_reduced(C.byref(ctx), right, array((plain ^ 1).to_bytes(16, "little")), 1) == 0,
                    "attack right")
            delta = int.from_bytes(bytes(left), "little") ^ int.from_bytes(bytes(right), "little")
            words = [(delta >> (32*i)) & ref.MASK for i in range(4)]
            require(words[0] == 0 and words[1] == (1 << 13) and words[3] == 0,
                    "one-round chosen-plaintext relation")
        lib.interlock_clear(C.byref(ctx))
    return {"seed": hex(seed), "keys": 16, "pair_experiments": 1024,
            "oracle_queries_per_experiment": 2, "matched_experiments": 1024,
            "output_difference_words": ["0", "00002000", "unconstrained", "0"],
            "real_probability": 1, "ideal_permutation_probability": "2^32/(2^128-1)",
            "scope": "one-round external encryption oracle only; no master-key recovery"}


def screen(lib, rng, samples):
    keys = [bytes(32), b"\xff" * 32, bytes(range(32)), rng.randbytes(32)]
    rows = []
    tests = len(keys) * 4 * 128
    alpha = 0.01
    threshold = math.sqrt(math.log(2 * tests / alpha) / (2 * samples))
    for key_id, key in enumerate(keys):
        ctx = Context()
        require(lib.interlock_init(C.byref(ctx), array(key), 32) == 0, "screen init")
        for rounds in range(1, 5):
            counts = [0] * 128
            controls = [0] * 128
            seen = set()
            for _ in range(samples):
                # Clear delta's bit, so each unordered plaintext pair occurs once.
                value = rng.getrandbits(128) & ~1
                while value in seen:
                    value = rng.getrandbits(128) & ~1
                seen.add(value)
                left, right = (U8 * 16)(), (U8 * 16)()
                require(lib.il_test_reduced(C.byref(ctx), left, array(value.to_bytes(16, "little")), rounds) == 0,
                        "screen left")
                require(lib.il_test_reduced(C.byref(ctx), right, array((value ^ 1).to_bytes(16, "little")), rounds) == 0,
                        "screen right")
                difference = int.from_bytes(bytes(left), "little") ^ int.from_bytes(bytes(right), "little")
                require(difference != 0, "reduced-round permutation collision")
                control = rng.getrandbits(128)
                while control == 0:
                    control = rng.getrandbits(128)
                for bit in range(128):
                    counts[bit] += (difference >> bit) & 1
                    controls[bit] += (control >> bit) & 1
            worst = max(range(128), key=lambda bit: abs(counts[bit] / samples - 0.5))
            bias = abs(counts[worst] / samples - 0.5)
            rows.append({"key_index": key_id, "rounds": rounds,
                         "oracle_queries": 2 * samples, "samples": samples,
                         "bit_counts": counts, "control_bit_counts": controls,
                         "worst_bit": worst, "worst_probability": counts[worst] / samples,
                         "max_abs_bit_bias": bias, "reference_threshold_exceeded": bias > threshold,
                         "control_max_abs_bit_bias": max(abs(n / samples - 0.5) for n in controls)})
        lib.interlock_clear(C.byref(ctx))
    return {"model": "chosen plaintext, four fixed keys, delta=1 in LE bit 0, rounds 1..4",
            "key_hex": [k.hex() for k in keys], "tests_in_family": tests,
            "reference_family_alpha": alpha, "bernoulli_hoeffding_bias_threshold": threshold,
            "threshold_limit": "IID Bernoulli reference only; no permutation-security proof. "
            "Uniform nonzero control differences approximate disjoint ideal-permutation pairs; "
            "the approximation error is of birthday order q^2/2^128.",
            "total_oracle_queries": 2 * samples * len(keys) * 4,
            "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=8192)
    parser.add_argument("--output", type=Path, default=ROOT / "build/analysis.json")
    args = parser.parse_args()
    if not 256 <= args.samples <= (1 << 20):
        parser.error("samples must be in [256, 1048576]")
    session = Session(SEED,max_queries=2*args.samples*4*4+2048)
    lib = CountedLibrary(session)
    rng = random.Random(SEED)
    result = {"scope": "component proofs/checks and bounded diagnostic; not full-round security",
              "sbox": sbox_properties(lib), "structure": structural_checks(lib, rng),
              "one_round_distinguisher": one_round_distinguisher(lib),
              "reduced_round_screen": screen(lib, rng, args.samples)}
    result["screen_storage_bound"] = "O(samples) unique-pair set + O(128) counters per dataset"
    require(session.queries == 2*args.samples*4*4+2048, "base oracle ledger conservation")
    session.save("analysis",result,args.output)
    print("S-box:", {k: v for k, v in result["sbox"].items() if k not in ("ddt", "lat_walsh")})
    for rounds in range(1, 5):
        rows = [r for r in result["reduced_round_screen"]["rows"] if r["rounds"] == rounds]
        print(f"rounds={rounds}, max bit bias={max(r['max_abs_bit_bias'] for r in rows):.6f}, "
              f"reference exceedances={sum(r['reference_threshold_exceeded'] for r in rows)}/4")


if __name__ == "__main__":
    main()
