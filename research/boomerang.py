"""Exact S-box BCT; cipher quartets use forward and inverse oracles separately."""

import argparse

from common import Session, load_library, ref, require

SEED = 0x424f4f4d4552414e


def bct(s):
    if sorted(s) != list(range(len(s))):
        raise ValueError("BCT requires a permutation")
    inverse = [s.index(x) for x in range(len(s))]
    return [[sum(inverse[s[x] ^ b] ^ inverse[s[x ^ a] ^ b] == a for x in range(len(s)))
             for b in range(len(s))] for a in range(len(s))]


def components():
    session,lib = Session(SEED),load_library()
    s = tuple(lib.il_test_sbox(x) & 15 for x in range(16))
    require(s == ref.SBOX, "current C S-box")
    table = bct(s)
    # Independent ordered-pair definition; no inverse table is used here.
    other = [[sum((s[x] ^ s[y]) == b and (s[x ^ a] ^ s[y ^ a]) == b
                  for x in range(16) for y in range(16)) for b in range(16)] for a in range(16)]
    require(table == other, "two exact BCT definitions")
    require(all(table[0][b] == 16 and table[b][0] == 16 for b in range(16)), "BCT trivial axes")
    for a in range(16):
        for b in range(16):
            ddt = sum(s[x] ^ s[x ^ a] == b for x in range(16))
            require(table[a][b] >= ddt and table[a][b] % 2 == 0, "BCT/DDT inclusion and parity")
    maximum = max(table[a][b] for a in range(1,16) for b in range(1,16))
    session.save("boomerang_components", {"model": "one PRESENT S-box permutation",
        "bct": table, "nontrivial_maximum": maximum,
        "maximizers": [[a,b] for a in range(1,16) for b in range(1,16) if table[a][b] == maximum],
        "exact_entry_comparisons": 256, "component_evaluations": 16,
        "limits": "not a multi-round boomerang probability; switches may be dependent"})
    print(f"PRESENT BCT: two definitions agree, maximum nontrivial entry={maximum}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    parser.parse_args()
    components()
