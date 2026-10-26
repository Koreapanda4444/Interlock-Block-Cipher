"""Exact S-box BCT; cipher quartets use forward and inverse oracles separately."""

import argparse
import hashlib
import random

from common import Oracle, Session, load_library, ref, require
from differential import bases

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


def quartets(oracle,alpha,beta,n,rounds,seed):
    data = b"".join(x.to_bytes(16,"little") + (x ^ alpha).to_bytes(16,"little") for x in bases(alpha,n,seed))
    encrypted = oracle.blocks(data,rounds)
    shifted = b"".join((int.from_bytes(encrypted[i:i+16],"little") ^ beta).to_bytes(16,"little")
                        for i in range(0,len(encrypted),16))
    returned = oracle.blocks(shifted,rounds,True)
    hits,trivial = 0,0
    for i in range(0,len(returned),32):
        hits += (int.from_bytes(returned[i:i+16],"little") ^ int.from_bytes(returned[i+16:i+32],"little")) == alpha
        trivial += (int.from_bytes(encrypted[i:i+16],"little") ^ int.from_bytes(encrypted[i+16:i+32],"little")) == beta
    return {"rounds": rounds, "alpha": f"{alpha:032x}", "beta": f"{beta:032x}", "samples": n,
            "returns_alpha": hits, "trivial_swaps": trivial, "nontrivial_successes": hits-trivial,
            "input_sha256": hashlib.sha256(data).hexdigest()}


def cipher(quick=False):
    session = Session(SEED ^ 0x434950484552,max_queries=1 << 22)
    rng = random.Random(session.seed)
    keys = [bytes(32)] if quick else [bytes(32),bytes(range(32)),rng.randbytes(32)]
    masks = [(1,1 << 64),(1 << 32,1 << 96),(1 << 64,1),(1 << 96,1 << 32)]
    n = 16 if quick else 4096
    rows = []
    for ki,key in enumerate(keys):
        with Oracle(session,key) as oracle:
            for ai,(alpha,beta) in enumerate(masks):
                for rounds in (range(3) if quick else range(1,9)):
                    row = quartets(oracle,alpha,beta,n,rounds,session.seed ^ (ki << 32) ^ (ai << 16) ^ rounds)
                    if rounds == 0 or (rounds == 1 and ai == 0):
                        require(row["returns_alpha"] == n, "identity/proven one-round boomerang")
                    row["key_index"] = ki
                    rows.append(row)
    session.save("boomerang_cipher", {"mode": "smoke" if quick else "full", "model": "same-key forward/inverse quartet, four block queries per trial",
        "keys_hex": [k.hex() for k in keys], "rows": rows,
        "limits": "chosen fixed masks, no p^2*q^2 independence assumption, trivial swaps reported separately"})
    print("Boomerang:",[(r,sum(x['returns_alpha'] for x in rows if x['rounds']==r)) for r in sorted({x['rounds'] for x in rows})])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    parser.add_argument("--cipher",action="store_true")
    args = parser.parse_args()
    cipher(args.check) if args.cipher else components()
