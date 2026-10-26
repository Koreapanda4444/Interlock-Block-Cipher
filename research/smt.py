"""Exact 32-bit QF_BV research model; optional Z3 dependency, never a C dependency."""

import argparse
import hashlib
from fractions import Fraction
import random
import struct
import time

try:
    import z3
except ImportError:
    raise SystemExit("Install the optional solver: python3 -m pip install -r research/requirements-smt.txt")

from common import ROOT, Oracle, Session, load_library, ref, require

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


def round_expression(state,keys,inverse=False):
    k = [word(x) if type(x) is int else x for x in keys]
    a,b,c,d = state
    if inverse:
        a,b,c,d = z3.RotateRight(b,13),z3.RotateRight(d,27),z3.RotateRight(a,5),z3.RotateRight(c,21)
        d = d ^ fs(a,k[3])
        b = b ^ fm(c,k[2])
        c = c ^ fm(d,k[1])
        a = a ^ fs(b,k[0])
        return [a,b,c,d]
    a = a ^ fs(b,k[0])
    c = c ^ fm(d,k[1])
    b = b ^ fm(c,k[2])
    d = d ^ fs(a,k[3])
    return [z3.RotateLeft(c,5),z3.RotateLeft(a,13),z3.RotateLeft(d,21),z3.RotateLeft(b,27)]


def prefix(s,initial,keys,rounds,name,inverse=False):
    if not 0 <= rounds <= 28:
        raise ValueError("rounds must be 0..28")
    states = [initial]
    for step,r in enumerate(reversed(range(rounds)) if inverse else range(rounds)):
        expressions = round_expression(states[-1],keys[r],inverse)
        next_state = [z3.BitVec(f"{name}_{step}_{i}",32) for i in range(4)]
        s.add(*(a == b for a,b in zip(next_state,expressions)))
        states.append(next_state)
    return states


def decide(s,timeout_ms=1000,rlimit=0):
    s.set(timeout=timeout_ms,rlimit=rlimit)
    formula = s.to_smt2()
    started = time.perf_counter()
    status = s.check()
    return {"status":str(status),"reason_unknown":s.reason_unknown() if status == z3.unknown else None,
            "timeout_ms":timeout_ms,"rlimit":rlimit,"check_seconds":time.perf_counter()-started,
            "formula_sha256":hashlib.sha256(formula.encode()).hexdigest(),
            "assertions":len(s.assertions()),"statistics":str(s.statistics())}


def traces():
    session = Session(SEED ^ 0x5452414345,max_queries=512)
    rows = []
    for index,(key,plain) in enumerate(ref.cases()[:3]):
        keys = ref.schedule(key)
        state = [word(x) for x in struct.unpack("<4I",plain)]
        with Oracle(session,key) as oracle:
            for rounds in range(1,29):
                previous = [x.as_long() for x in state]
                state = [z3.simplify(x) for x in round_expression(state,keys[rounds-1])]
                output = oracle.blocks(plain,rounds)
                values = struct.unpack("<4I",output)
                require([x.as_long() for x in state] == list(values), "SMT/C forward prefix")
                reverse = [word(x) for x in values]
                reverse = [z3.simplify(x) for x in round_expression(reverse,keys[rounds-1],True)]
                require([x.as_long() for x in reverse] == previous, "SMT inverse round at each prefix")
        # Fixed-input symbolic consistency includes all 28 round equations.
        s = solver()
        start = [z3.BitVec(f"trace_input_{index}_{i}",32) for i in range(4)]
        s.add(*(x == value for x,value in zip(start,struct.unpack("<4I",plain))))
        states = prefix(s,start,keys,28,f"trace_{index}")
        answer = decide(s,3000)
        require(answer["status"] == "sat", "fixed-input full-round SMT consistency")
        final = [s.model().eval(x).as_long() for x in states[-1]]
        require(final == [x.as_long() for x in state], "symbolic full-round output")
        s.add(states[-1][0] != final[0])
        negative = decide(s,3000)
        require(negative["status"] == "unsat", "wrong fixed-input output rejected")
        rows.append({"case":index,"positive":answer,"wrong_fixed_output":negative})
    session.save("smt_traces", {"solver_version":z3.get_full_version(),"rows":rows,
        "concrete_prefixes":84,"limits":"fixed-input implementation consistency; UNSAT is not cipher security"})
    print("SMT round model: 84 C prefix traces and three full-round fixed-input SAT/UNSAT checks agree")


def packed(state):
    return z3.Concat(*reversed(state))


def paired(s,initial,keys,rounds,delta,name):
    other = [x ^ word((delta >> (32*i)) & ref.MASK) for i,x in enumerate(initial)]
    return prefix(s,initial,keys,rounds,name+"_left"),prefix(s,other,keys,rounds,name+"_right")


def replay_pair(session,key,plain,delta,rounds,mask,value):
    with Oracle(session,key) as oracle:
        data = plain.to_bytes(16,"little")+(plain ^ delta).to_bytes(16,"little")
        output = oracle.blocks(data,rounds)
    actual = int.from_bytes(output[:16],"little") ^ int.from_bytes(output[16:],"little")
    require(actual & mask == value, "SMT witness rejected by independent C permutation")
    return {"plaintext":f"{plain:032x}","input_difference":f"{delta:032x}","output_difference":f"{actual:032x}"}


def pair_checks(quick=False):
    session = Session(SEED ^ 0x50414952,max_queries=64)
    key,delta = bytes(32),1
    keys = ref.schedule(key)
    rows = []
    for rounds in range(3 if quick else 5):
        s = solver()
        initial = [z3.BitVec(f"pair_{rounds}_{i}",32) for i in range(4)]
        s.add(z3.Extract(31,8,initial[0]) == 0,*(x == 0 for x in initial[1:]))
        left,right = paired(s,initial,keys,rounds,delta,f"pair_model_{rounds}")
        difference = packed(left[-1]) ^ packed(right[-1])
        s.add(difference & 1 == 1)
        formula = s.to_smt2()
        (ROOT / "build" / f"smt_pair_{rounds}.smt2").write_text(formula)
        row = decide(s,1500)
        row.update({"rounds":rounds,"input_domain":"P=(u8,0,0,0)","desired_output_mask":"1","desired_output_value":"1"})
        if row["status"] == "sat":
            m = s.model()
            plain = sum(m.eval(x,model_completion=True).as_long() << (32*i) for i,x in enumerate(initial))
            require(plain < 256, "SMT domain restriction")
            row["witness"] = replay_pair(session,key,plain,delta,rounds,1,1)
        if rounds == 0:
            require(row["status"] == "sat", "identity positive pair control")
        if rounds == 1:
            require(row["status"] == "unsat", "one-round impossible bit control")
        rows.append(row)
    session.save("smt_pairs", {"mode":"smoke" if quick else "full","solver_version":z3.get_full_version(),
        "key_hex":key.hex(),"rows":rows,"limits":"exact bounded-input feasibility; SAT is a witness, not a trail probability; UNKNOWN is unresolved"})
    print("SMT pairs:",[(r['rounds'],r['status']) for r in rows])


def projected_counts(quick=False):
    session,lib = Session(SEED ^ 0x434f554e54),load_library()
    dimension = 4 if quick else 8
    rows = []
    for key in ([0] if quick else [0,0xffffffff,0x12345678]):
        for bit in ([31] if quick else [0,31]):
            s = solver()
            u = z3.BitVec(f"count_u_{key}_{bit}",dimension)
            x = z3.ZeroExt(32-dimension,u) << 16
            delta = 1 << (16+min(5,dimension-1))
            difference = fm(x,word(key)) ^ fm(x ^ word(delta),word(key))
            s.add(z3.Extract(bit,bit,difference) == 1)
            expected = {v for v in range(1 << dimension)
                        if ((lib.il_test_fm(v << 16,key) ^ lib.il_test_fm((v << 16) ^ delta,key)) >> bit) & 1}
            seen = set()
            checks = 0
            while True:
                answer = decide(s,1000)
                checks += 1
                if answer["status"] != "sat":
                    break
                value = s.model().eval(u,model_completion=True).as_long()
                require(value in expected and value not in seen, "projected model false positive/duplicate")
                seen.add(value)
                s.add(u != value)
            complete = answer["status"] == "unsat"
            if complete:
                require(seen == expected, "projected model false negatives")
            if quick:
                require(complete, "small-domain model counting must complete")
            rows.append({"key":f"{key:08x}","dimension":dimension,"offset":16,"delta":f"{delta:08x}",
                "output_bit":bit,"models":sorted(seen),"enumeration_complete":complete,
                "model_count_lower":len(seen),"model_count_upper":len(seen) if complete else 1 << dimension,
                "exact_c_count":len(expected),"exact_model_probability":str(Fraction(len(seen),1 << dimension)) if complete else None,
                "solver_checks":checks,"terminal":answer})
    session.save("smt_counts", {"mode":"smoke" if quick else "full","solver_version":z3.get_full_version(),
        "rows":rows,"component_evaluations":2*(1 << dimension)*len(rows),
        "limits":"exact only on the enumerated affine input cube; auxiliary assignments are not counted as plaintexts"})
    print("SMT projected counts:",[(r['key'],r['output_bit'],r['model_count_lower'],r['enumeration_complete']) for r in rows])


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
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--traces",action="store_true")
    modes.add_argument("--pairs",action="store_true")
    modes.add_argument("--count",action="store_true")
    args = parser.parse_args()
    if args.traces:
        traces()
    elif args.pairs:
        pair_checks(args.check)
    elif args.count:
        projected_counts(args.check)
    else:
        components()
