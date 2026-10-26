"""Signed linear correlations; isolated FS identities precede cipher experiments."""

import argparse
import hashlib
import math
from fractions import Fraction
from functools import lru_cache
import random

from common import Oracle, Session, load_library, ref, require

SEED = 0x4c494e454152


def parity(x):
    return x.bit_count() & 1


def walsh(a,b):
    return sum(1 if parity(a & x) == parity(b & ref.SBOX[x]) else -1 for x in range(16))


def transpose(x):
    return x ^ ref.rol(x,-3) ^ ref.rol(x,-17)


@lru_cache(maxsize=256)
def inverse_transpose(x):
    for _ in range(31):
        x = transpose(x)
    return x


def fs_correlation(alpha,beta,key):
    pulled = transpose(beta)
    value = Fraction(-1 if parity(alpha & key) else 1)
    for i in range(8):
        value *= Fraction(walsh((alpha >> (4*i)) & 15,(pulled >> (4*i)) & 15),16)
    return value


def components():
    session = Session(SEED)
    rng,lib = random.Random(SEED),load_library()
    for i in range(32):
        for j in range(32):
            require(parity((1 << i) & lib.il_test_linear(1 << j)) == parity(transpose(1 << i) & (1 << j)),
                    "linear adjoint basis")
        require(transpose(inverse_transpose(1 << i)) == 1 << i, "adjoint inverse")
    keys = [0,0xffffffff,0x12345678,rng.getrandbits(32)]
    checks = 0
    for key in keys:
        for nibble in range(8):
            inputs = [x << (4*nibble) for x in range(16)]
            outputs = [lib.il_test_fs(x,key) for x in inputs]
            for a in range(1,16):
                for b in range(1,16):
                    alpha,beta = a << (4*nibble),inverse_transpose(b << (4*nibble))
                    observed = Fraction(sum(1 if parity(alpha & x) == parity(beta & y) else -1
                                            for x,y in zip(inputs,outputs)),16)
                    require(observed == fs_correlation(alpha,beta,key), "signed FS correlation")
                    checks += 1
    a,b = next((a,b) for a in range(1,16) for b in range(1,16) if abs(walsh(a,b)) == 8)
    beta = inverse_transpose(b)
    session.save("linear_components", {"model": "uniform 32-bit isolated FS input and fixed known subkey",
        "formula": "(-1)^<alpha,k> times product_i LAT[alpha_i,(L^T beta)_i]/16",
        "exact_correlations_checked": checks, "component_evaluations": 32*32+len(keys)*8*16,
        "sbox_walsh": [[walsh(a,b) for b in range(16)] for a in range(16)],
        "example_alpha": f"{a:08x}", "example_beta": f"{beta:08x}",
        "example_zero_key_correlation": str(fs_correlation(a,beta,0)),
        "limits": "component equality; not a cipher-wide trail/hull bound"})
    print(f"Linear FS: {checks} exact signed correlations; example correlation={fs_correlation(a,beta,0)}")


def cipher(quick=False):
    session = Session(SEED ^ 0x434950484552,max_queries=1 << 20)
    rng = random.Random(session.seed)
    a,b = next((a,b) for a in range(1,16) for b in range(1,16) if abs(walsh(a,b)) == 8)
    beta = inverse_transpose(b)
    input_mask = beta | (a << 32)
    output_mask = ref.rol(beta,13) << 32
    keys = [bytes(32),b"\xff"*32] if quick else [bytes(32),b"\xff"*32,bytes(range(32)),rng.randbytes(32)]
    rows = []
    for ki,key in enumerate(keys):
        train = rng.randbytes(16*1024)
        n = 256 if quick else 8192
        validation = rng.randbytes(16*n)
        require(set(train[i:i+16] for i in range(0,len(train),16)).isdisjoint(
                validation[i:i+16] for i in range(0,len(validation),16)), "linear holdout split")
        with Oracle(session,key) as oracle:
            def observe(data, rounds):
                output = oracle.blocks(data,rounds)
                signed = 0
                for i in range(0,len(data),16):
                    p,c = int.from_bytes(data[i:i+16],"little"),int.from_bytes(output[i:i+16],"little")
                    observed = parity(input_mask & p) ^ parity(output_mask & c)
                    if rounds == 1:
                        x = (p >> 32) & ref.MASK
                        expected = parity(a & x) ^ parity(beta & ref.fs(x,oracle.ctx.round_keys[0][0]))
                        require(observed == expected, "one-round external linear identity")
                    signed += -1 if observed else 1
                return signed/(len(data)//16)
            training = observe(train,1)
            phase = 1 if training >= 0 else -1
            for rounds in (range(1,3) if quick else range(1,9)):
                correlation = observe(validation,rounds)
                rows.append({"key_index": ki, "rounds": rounds, "samples": n,
                    "signed_correlation": correlation, "bias": correlation/2,
                    "training_correlation": training, "training_phase_aligned_correlation": phase*correlation,
                    "predicted_one_round_correlation": str(fs_correlation(a,beta,oracle.ctx.round_keys[0][0])),
                    "validation_sha256": hashlib.sha256(validation).hexdigest()})
    threshold = math.sqrt(2*math.log(2*len(rows)/0.01)/n)
    session.save("linear_cipher", {"mode": "smoke" if quick else "full",
        "model": "fixed input/output masks and same unknown master key; secret schedule used only for ground-truth checks",
        "input_mask": f"{input_mask:032x}", "output_mask": f"{output_mask:032x}",
        "keys_hex": [k.hex() for k in keys], "rows": rows,
        "reference_absolute_correlation_threshold": threshold,
        "limits": "single-mask correlations only; no optimized linear trail/hull bound"})
    print("Linear cipher:",[(r["rounds"],round(r["signed_correlation"],4)) for r in rows if r["key_index"]==0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    parser.add_argument("--cipher",action="store_true")
    args = parser.parse_args()
    cipher(args.check) if args.cipher else components()
