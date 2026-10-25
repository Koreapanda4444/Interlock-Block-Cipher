"""Exact XOR differential counts of one modular addition using paired carries.

Operands are independent uniform words, or the second operand is fixed.
These assumptions do not hold automatically for the correlated operands in FM.
"""

from collections import Counter
from fractions import Fraction

from common import Session, require


def count(alpha, beta, gamma, bits, constant=None):
    if not 1 <= bits <= 64:
        raise ValueError("word size must be 1..64")
    if any(not 0 <= v < 1 << bits for v in (alpha,beta,gamma)):
        raise ValueError("difference exceeds word size")
    if constant is not None and not 0 <= constant < 1 << bits:
        raise ValueError("constant exceeds word size")
    states = {(0,0): 1}
    for i in range(bits):
        next_states = Counter()
        da, db, dc = (alpha >> i) & 1, (beta >> i) & 1, (gamma >> i) & 1
        ys = (0,1) if constant is None else ((constant >> i) & 1,)
        for (carry,paired_carry), paths in states.items():
            for x in (0,1):
                for y in ys:
                    total = x+y+carry
                    paired = (x ^ da)+(y ^ db)+paired_carry
                    if ((total ^ paired) & 1) == dc:
                        next_states[(total >> 1,paired >> 1)] += paths
        states = next_states
    return sum(states.values())


def probability(alpha, beta, gamma, bits=32, constant=None):
    denominator = 1 << (bits if constant is not None else 2*bits)
    return Fraction(count(alpha,beta,gamma,bits,constant),denominator)


def exhaustive():
    checks, base_evaluations = 0, 0
    for bits in range(1,5):
        size = 1 << bits
        mask = size-1
        for a in range(size):
            for b in range(size):
                histogram = Counter(((x+y) & mask) ^ (((x ^ a)+(y ^ b)) & mask)
                                    for x in range(size) for y in range(size))
                base_evaluations += size*size
                for c in range(size):
                    require(count(a,b,c,bits) == histogram[c], "independent operand carry model")
                    checks += 1
        for constant in range(size):
            for a in range(size):
                histogram = Counter(((x+constant) & mask) ^ (((x ^ a)+constant) & mask)
                                    for x in range(size))
                base_evaluations += size
                for c in range(size):
                    require(count(a,0,c,bits,constant) == histogram[c], "fixed operand carry model")
                    checks += 1
    # Nonzero difference on a fixed second operand, with exact 8-bit enumeration.
    for a,b,k in ((1,3,17),(0x80,0x40,0xff),(0x55,0xaa,0x69),(0xff,0xff,0)):
        histogram = Counter(((x+k) & 255) ^ (((x ^ a)+(k ^ b)) & 255) for x in range(256))
        for c in range(256):
            require(count(a,b,c,8,k) == histogram[c], "fixed related-operand carry model")
            checks += 1
        base_evaluations += 256
    return checks,base_evaluations


def analyze():
    session = Session(0x4341525259)
    checks,evaluations = exhaustive()
    examples = [(0,0,0,None),(1,0,0,None),(1,0,1,None),
                (0x80000000,0,0x80000000,None),(1,0,1,0),(1,0,1,1),
                (0x20,0x40,0x60,None),(0x80000001,0x10,0x80000011,None)]
    rows = [{"alpha": f"{a:08x}", "beta": f"{b:08x}", "gamma": f"{c:08x}",
             "constant": None if k is None else f"{k:08x}",
             "exact_probability": str(probability(a,b,c,32,k))} for a,b,c,k in examples]
    require(probability(0,0,0) == 1, "identical operands")
    require(probability(1,0,0) == 0, "LSB impossible difference")
    require(probability(1,0,1) == Fraction(1,2), "one-bit carry probability")
    require(probability(0x80000000,0,0x80000000) == 1, "discard final carry")
    session.save("addition", {"model": "paired carries of one addition modulo 2^n",
        "exact_exhaustive_count_comparisons": checks, "enumerated_operand_cases": evaluations,
        "exhaustive_widths": [1,2,3,4], "fixed_related_operand_width": 8, "examples_32bit": rows,
        "limitations": "not a SAT/SMT search; no multiplication of dependent FM/round probabilities"})
    print(f"addition: exact comparisons={checks}, operand cases={evaluations}, 32-bit examples={len(rows)}")


if __name__ == "__main__":
    analyze()
