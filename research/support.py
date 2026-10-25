"""Sound bitwise differential overapproximation for same-key round prefixes.

Known difference bits are proven constraints; unknown bits admit both values.
FM(nonzero/unknown) deliberately returns top, never an unsupported PRF model.
"""

from dataclasses import dataclass
from functools import lru_cache
import random

from common import Oracle, Session, ref, require


@dataclass(frozen=True)
class Word:
    must: int
    may: int

    def __xor__(self, other):
        return Word((self.must & ~other.may) | (other.must & ~self.may),
                    (self.may & ~other.must) | (other.may & ~self.must))

    def rotate(self, n):
        return Word(ref.rol(self.must, n), ref.rol(self.may, n))


ZERO = Word(0, 0)
TOP = Word(0, ref.MASK)


@lru_cache(maxsize=81)
def nibble(must, may):
    differences = {ref.SBOX[x] ^ ref.SBOX[x ^ delta]
                   for delta in range(16) if delta & must == must and delta & ~may == 0
                   for x in range(16)}
    low, high = 15, 0
    for value in differences:
        low &= value
        high |= value
    return low, high


def fs(word):
    low, high = 0, 0
    for i in range(8):
        a, b = nibble((word.must >> (4*i)) & 15, (word.may >> (4*i)) & 15)
        low |= a << (4*i)
        high |= b << (4*i)
    substituted = Word(low, high)
    return substituted ^ substituted.rotate(3) ^ substituted.rotate(17)


def fm(word):
    return ZERO if word.may == 0 else TOP


def propagate(delta, rounds):
    if not 0 < delta < 1 << 128 or not 0 <= rounds <= 28:
        raise ValueError("nonzero 128-bit difference and rounds 0..28 required")
    state = [Word((delta >> (32*i)) & ref.MASK, (delta >> (32*i)) & ref.MASK) for i in range(4)]
    for _ in range(rounds):
        a, b, c, d = state
        a = a ^ fs(b)
        c = c ^ fm(d)
        b = b ^ fm(c)
        d = d ^ fs(a)
        state = [c.rotate(5), a.rotate(13), d.rotate(21), b.rotate(27)]
    value = sum(w.must << (32*i) for i, w in enumerate(state))
    mask = sum(((~w.may | w.must) & ref.MASK) << (32*i) for i, w in enumerate(state))
    return mask, value


def analyze():
    session = Session(0x535550504f5254, max_queries=1 << 17)
    rng = random.Random(session.seed)
    rows = []
    for bit in range(128):
        for rounds in range(1, 5):
            mask, value = propagate(1 << bit, rounds)
            require(value & ~mask == 0, "must bits contained in fixed mask")
            rows.append({"input_bit": bit, "rounds": rounds, "fixed_bits": mask.bit_count(),
                         "mask_hex": f"{mask:032x}", "value_hex": f"{value:032x}",
                         "ideal_acceptance_upper_bound": f"2^{128-mask.bit_count()}/(2^128-1)"})
    keys = [bytes(32), b"\xff"*32, bytes(range(32)), rng.randbytes(32)]
    for key in keys:
        with Oracle(session, key) as oracle:
            for row in rows:
                delta = 1 << row["input_bit"]
                pivot = delta.bit_length() - 1
                plains = [rng.getrandbits(128) & ~(1 << pivot) for _ in range(16)]
                data = b"".join(x.to_bytes(16, "little") + (x ^ delta).to_bytes(16, "little") for x in plains)
                result = oracle.blocks(data, row["rounds"])
                for i in range(0, len(result), 32):
                    diff = int.from_bytes(result[i:i+16], "little") ^ int.from_bytes(result[i+16:i+32], "little")
                    require(diff & int(row["mask_hex"], 16) == int(row["value_hex"], 16),
                            "sound support contradicted by current C oracle")
    document = session.save("support", {
        "scope": "same-key differential support, all input values and keys; conservative bit projection",
        "fm_model": "zero difference stays zero; every other input difference allows all outputs",
        "rows": rows, "c_pair_checks": len(keys)*len(rows)*16, "key_hex": [k.hex() for k in keys],
        "limits": "not a trail probability model; unknown does not mean attainable; no key recovery"})
    for r in range(1, 5):
        subset = [row for row in rows if row["rounds"] == r]
        zero = subset[0]
        print(f"support rounds={r}: fixed bits min/max={min(x['fixed_bits'] for x in subset)}/"
              f"{max(x['fixed_bits'] for x in subset)}, delta=1 fixed={zero['fixed_bits']}, "
              f"mask={zero['mask_hex']}, value={zero['value_hex']}")
    return document


if __name__ == "__main__":
    analyze()
