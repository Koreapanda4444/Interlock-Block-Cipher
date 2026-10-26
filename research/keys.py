"""Reachable XOR-related master-key schedule audit; no key-strength claim."""

import argparse
import hashlib
import random
import struct

from common import Oracle, Session, ref, require

SEED = 0x4b455953


def analyze(quick=False):
    session = Session(SEED)
    rng = random.Random(SEED)
    keys = [bytes(32),bytes(range(32))] if quick else [bytes(32),b"\xff"*32,bytes(range(32)),rng.randbytes(32)]
    seen,rows,collisions,zero_fm = {},[],[],[]
    expansions = 0
    def schedule(oracle,key):
        nonlocal expansions
        words = [v for row in oracle.ctx.round_keys for v in row]
        require(words == [v for row in ref.schedule(key) for v in row], "reachable schedule independent check")
        encoded = b"Interlock-128/roundkeys\x00"+key
        require(len(encoded) == 56, "injective fixed-length key input")
        expanded = struct.pack("<112I",*words)
        if expanded in seen and seen[expanded] != key.hex():
            collisions.append([seen[expanded],key.hex()])
        seen[expanded] = key.hex()
        zero_fm.extend({"key_hex":key.hex(),"round":r,"subkey_index":j}
                       for r in range(28) for j in (1,2) if words[4*r+j] == 0)
        expansions += 1
        return expanded
    for ki,key in enumerate(keys):
        with Oracle(session,key) as base:
            original = schedule(base,key)
            for bit in range(8 if quick else 256):
                related = (int.from_bytes(key,"little") ^ (1 << bit)).to_bytes(32,"little")
                with Oracle(session,related) as other:
                    expanded = schedule(other,related)
                delta = bytes(a ^ b for a,b in zip(original,expanded))
                rows.append({"key_index":ki,"master_key_bit":bit,"schedule_hamming_distance":sum(x.bit_count() for x in delta),
                             "unchanged_words":sum(original[i:i+4] == expanded[i:i+4] for i in range(0,448,4)),
                             "related_input_sha256":hashlib.sha256(b"Interlock-128/roundkeys\0"+related).hexdigest()})
    session.save("keys", {"mode":"smoke" if quick else "full","keys_hex":[k.hex() for k in keys],
        "key_expansions":expansions,"rows":rows,"complete_schedule_collisions":collisions,"zero_fm_subkeys":zero_fm,
        "limits":"finite single-bit XOR-related key audit; avalanche is not a related-key security proof"})
    print(f"Key audit: expansions={expansions}, collisions={len(collisions)}, zero FM words={len(zero_fm)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    analyze(args.check)
