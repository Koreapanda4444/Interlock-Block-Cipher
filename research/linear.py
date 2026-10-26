"""Signed linear correlations; isolated FS identities precede cipher experiments."""

import argparse
from fractions import Fraction
from functools import lru_cache
import random

from common import Session, load_library, ref, require

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    parser.parse_args()
    components()
