"""Exact 32-bit QF_BV research model; optional Z3 dependency, never a C dependency."""

import argparse
import random

try:
    import z3
except ImportError:
    raise SystemExit("Install the optional solver: python3 -m pip install -r research/requirements-smt.txt")

from common import Session, load_library, ref, require

SEED = 0x534d54


def word(x):
    return z3.BitVecVal(x,32)


def substitution(x):
    result = []
    for nibble in range(8):
        v = z3.Extract(4*nibble+3,4*nibble,x)
        out = z3.BitVecVal(ref.SBOX[15],4)
        for i in range(14,-1,-1):
            out = z3.If(v == i,z3.BitVecVal(ref.SBOX[i],4),out)
        result.append(out)
    return z3.Concat(*reversed(result))


def linear(x):
    return x ^ z3.RotateLeft(x,3) ^ z3.RotateLeft(x,17)


def fs(x,k):
    return linear(substitution(x ^ k))


def fm(x,k):
    y = substitution(x ^ k)
    u = y + z3.RotateLeft(k,9)
    v = z3.RotateLeft(y ^ k,7)
    w = z3.RotateLeft(u+v,11) ^ z3.RotateLeft(y & z3.RotateLeft(k,3),19)
    return linear(substitution(w ^ z3.RotateLeft(k,13)))


def solver(timeout_ms=1000,rlimit=0):
    result = z3.SolverFor("QF_BV")
    result.set(timeout=timeout_ms,random_seed=SEED,rlimit=rlimit)
    return result


def components():
    session,lib = Session(SEED),load_library()
    rng = random.Random(SEED)
    pairs = [(x,k) for x in (0,1,0xffffffff,0x80000000,0x55555555) for k in (0,1,0xffffffff)]
    pairs += [(rng.getrandbits(32),rng.getrandbits(32)) for _ in range(32)]
    for x,k in pairs:
        require(z3.simplify(fs(word(x),word(k))).as_long() == lib.il_test_fs(x,k), "SMT FS bitwise model")
        require(z3.simplify(fm(word(x),word(k))).as_long() == lib.il_test_fm(x,k), "SMT FM carry model")
    require(z3.simplify(word(0xffffffff)+word(1)).as_long() == 0, "modular overflow")
    s = solver()
    x = z3.BitVec("addition_identity",32)
    s.add(x+word(0) != x)
    require(s.check() == z3.unsat, "QF_BV solver sanity")
    session.save("smt_components", {"solver_version":z3.get_full_version(),"logic":"QF_BV",
        "component_pairs":len(pairs),"component_evaluations":2*len(pairs),
        "representation":"exact 32-bit addition, rotations, AND, table-defined nibble substitution",
        "limits":"component validation only; not a differential probability or full-round proof"})
    print(f"SMT components: Z3 {z3.get_version_string()}, exact C comparisons={2*len(pairs)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    parser.parse_args()
    components()
