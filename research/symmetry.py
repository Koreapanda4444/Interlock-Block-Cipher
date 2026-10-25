"""Separate component rotation identities from reachable master-key relations."""

import argparse
import hashlib
import random

from common import Oracle, Session, ref, require
from components import evaluate

SEED = 0x524f544154494f4e


def rotate_words(data, shift):
    if len(data) % 4:
        raise ValueError("whole LE32 words required")
    return b"".join(ref.rol(int.from_bytes(data[i:i+4],"little"),shift).to_bytes(4,"little")
                    for i in range(0,len(data),4))


def analyze(quick=False):
    session = Session(SEED,max_queries=1 << 19)
    rng = random.Random(SEED)
    n = 64 if quick else 2048
    word_keys = [0,0xffffffff,0x12345678,rng.getrandbits(32)]
    component_rows = []
    with Oracle(session,bytes(32)) as probe:
        lib = probe.lib
        for key in word_keys:
            values = [rng.getrandbits(32) for _ in range(n)]
            fs_base, fm_base = evaluate(lib,values,key,0), evaluate(lib,values,key,1)
            for shift in range(1,32):
                rotated = [ref.rol(x,shift) for x in values]
                fs_other = evaluate(lib,rotated,ref.rol(key,shift),0)
                fm_other = evaluate(lib,rotated,ref.rol(key,shift),1)
                fs_hits = sum(a == ref.rol(b,shift) for a,b in zip(fs_other,fs_base))
                fm_hits = sum(a == ref.rol(b,shift) for a,b in zip(fm_other,fm_base))
                if shift % 4 == 0:
                    require(fs_hits == n, "PRESENT nibble-rotation/FS identity")
                else:
                    require(lib.il_test_fs(0,0) != ref.rol(lib.il_test_fs(0,0),shift),
                            "counterexample to non-nibble FS rotation identity")
                component_rows.append({"subkey": f"{key:08x}", "rotation": shift,
                    "samples": n, "fs_matches": fs_hits, "fm_matches": fm_hits})
    keys = [bytes(32),b"\xff"*32,bytes(range(32)),rng.randbytes(32)]
    audit_keys = keys if quick else keys + [rng.randbytes(32) for _ in range(28)]
    schedules = []
    for ki,key in enumerate(audit_keys):
        for shift in (4,8,12,16):
            with Oracle(session,key) as left, Oracle(session,rotate_words(key,shift)) as right:
                matches = sum(right.ctx.round_keys[r][j] == ref.rol(left.ctx.round_keys[r][j],shift)
                              for r in range(28) for j in range(4))
                schedules.append({"key_index": ki, "rotation": shift,
                                  "matching_subkey_words": matches, "total_subkey_words": 112,
                                  "rotated_master_equals_master": rotate_words(key,shift) == key})
    rows = []
    n = 16 if quick else 1024
    for ki,key in enumerate(keys[:2] if quick else keys):
        for shift in (4,8,16):
            data = rng.randbytes(16*n)
            rotated = rotate_words(data,shift)
            require(all(data[i:i+16] != rotated[i:i+16] for i in range(0,len(data),16)),
                    "exclude rotation-fixed plaintexts")
            with Oracle(session,key) as left, Oracle(session,rotate_words(key,shift)) as right:
                for rounds in (1,2,4,8,28):
                    expected = rotate_words(left.blocks(data,rounds),shift)
                    observed = right.blocks(rotated,rounds)
                    hits = sum(expected[i:i+16] == observed[i:i+16] for i in range(0,len(data),16))
                    rows.append({"key_index": ki, "rotation": shift, "rounds": rounds,
                                 "samples": n, "whole_block_matches": hits,
                                 "input_sha256": hashlib.sha256(data).hexdigest(),
                                 "zero_hit_binomial_upper_95": 1-0.05**(1/n) if hits == 0 else None})
    session.save("symmetry", {"mode": "smoke" if quick else "full",
        "component_model": "simultaneously rotate the input word and isolated subkey",
        "component_evaluations": (1+31)*2*len(word_keys)*(64 if quick else 2048),
        "component_rows": component_rows, "schedule_audit": schedules,
        "master_key_relation": "apply ROL32 independently to each of eight master-key words",
        "master_keys_hex": [k.hex() for k in keys], "cipher_rows": rows,
        "limits": "specific rotation identities only; internal schedule audit is not a key-recovery attack; "
                  "zero-hit bounds concern the sampled fixed-key input distribution, not security bits"})
    print(f"symmetry: schedule relation all-words matches={sum(r['matching_subkey_words']==112 for r in schedules)}"
          f"/{len(schedules)}, whole-block matches={sum(r['whole_block_matches'] for r in rows)}"
          f"/{sum(r['samples'] for r in rows)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    analyze(args.check)
