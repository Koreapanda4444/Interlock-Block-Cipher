"""Exact ANF on specified affine restrictions, not a full-word degree certificate."""

import argparse
import hashlib
import random
import struct

from common import Session, load_library, ref, require
from components import evaluate

SEED = 0x414c4745425241


def mobius(values,dimension):
    if len(values) != 1 << dimension:
        raise ValueError("full Boolean cube required")
    result = list(values)
    for bit in range(dimension):
        for mask in range(1 << dimension):
            if mask & (1 << bit):
                result[mask] ^= result[mask ^ (1 << bit)]
    return result


def degrees(coefficients,width):
    answer = [-1]*width
    for mask,value in enumerate(coefficients):
        while value:
            bit = (value & -value).bit_length()-1
            answer[bit] = max(answer[bit],mask.bit_count())
            value &= value-1
    return answer


def analyze(quick=False):
    session,lib = Session(SEED),load_library()
    rng = random.Random(SEED)
    require(max(degrees(mobius(ref.SBOX,4),4)) == 3, "S-box ANF degree")
    dimension = 8 if quick else 16
    keys = [0] if quick else [0,0xffffffff,0x12345678,rng.getrandbits(32)]
    rows = []
    for key in keys:
        for offset in (0,16):
            mask = ((1 << dimension)-1) << offset
            base = rng.getrandbits(32) & ~mask
            inputs = [base | (x << offset) for x in range(1 << dimension)]
            for mixed in (0,1):
                values = evaluate(lib,inputs,key,mixed)
                coefficients = mobius(values,dimension)
                require(mobius(coefficients,dimension) == values, "exact ANF round trip")
                d = degrees(coefficients,32)
                if not mixed:
                    require(max(d) <= 3, "FS degree bound")
                rows.append({"component": "FM" if mixed else "FS", "key": f"{key:08x}",
                    "offset": offset, "dimension": dimension, "fixed_base": f"{base:08x}",
                    "coordinate_degrees": d, "max_restricted_degree": max(d),
                    "restricted_collision_excess": len(values)-len(set(values)),
                    "truth_table_sha256": hashlib.sha256(struct.pack(f"<{len(values)}I",*values)).hexdigest()})
    first,second = 0x11111111,0x66666666
    require(lib.il_test_fm(first,0) == lib.il_test_fm(second,0), "analytic zero-subkey FM collision")
    session.save("algebra", {"mode": "smoke" if quick else "full", "rows": rows,
        "component_evaluations": len(rows)*(1 << dimension)+2,
        "zero_subkey_collision": {"x": f"{first:08x}","y":f"{second:08x}","key":"00000000"},
        "limits": "restricted degrees lower-bound global degree; collisions in a Feistel function do not alone break the permutation"})
    print(f"ANF: dimension={dimension}, restricted FM degree max={max(r['max_restricted_degree'] for r in rows if r['component']=='FM')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    analyze(args.check)
