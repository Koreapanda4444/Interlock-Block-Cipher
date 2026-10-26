"""Recover two first-round FS subkeys from external plaintext/ciphertext only."""

import argparse
import random
import struct

from common import Oracle, Session, ref, require

SEED = 0x5245434f56455259


def inverse_unkeyed_fs(value):
    for _ in range(31):
        value = ref.linear(value)
    inverse = [ref.SBOX.index(x) for x in range(16)]
    return sum(inverse[(value >> (4*i)) & 15] << (4*i) for i in range(8))


def recover(plain,cipher):
    a,b,_,d = struct.unpack("<4I",plain)
    out = struct.unpack("<4I",cipher)
    updated_a,updated_d = ref.rol(out[1],-13),ref.rol(out[2],-21)
    k0 = b ^ inverse_unkeyed_fs(a ^ updated_a)
    k3 = updated_a ^ inverse_unkeyed_fs(d ^ updated_d)
    return k0,k3


def analyze(quick=False):
    session = Session(SEED,max_queries=4096)
    rng = random.Random(SEED)
    examples = []
    count = 4 if quick else 64
    validation = 4 if quick else 16
    for index in range(count):
        key,plain = rng.randbytes(32),rng.randbytes(16)
        with Oracle(session,key) as oracle:
            cipher = oracle.blocks(plain,1)
            k0,k3 = recover(plain,cipher)
            # Only the evaluator sees this ground truth, after external recovery.
            require((k0,k3) == (oracle.ctx.round_keys[0][0],oracle.ctx.round_keys[0][3]), "recovered FS subkeys")
            holdout = rng.randbytes(16*validation)
            observed = oracle.blocks(holdout,1)
            for i in range(0,len(holdout),16):
                a,b,_,d = struct.unpack("<4I",holdout[i:i+16])
                a ^= ref.fs(b,k0)
                d ^= ref.fs(a,k3)
                out = struct.unpack("<4I",observed[i:i+16])
                require(out[1] == ref.rol(a,13) and out[2] == ref.rol(d,21), "unseen output-word prediction")
            if index < 4:
                examples.append({"plaintext":plain.hex(),"ciphertext":cipher.hex(),"k0":f"{k0:08x}","k3":f"{k3:08x}"})
    session.save("recovery", {"mode":"smoke" if quick else "full", "model":"one-round external encryption oracle",
        "keys_tested":count,"successful_keys":count,"discovery_queries_per_key":1,
        "validation_queries_per_key":validation,"recovered_round_subkey_bits":64,"examples":examples,
        "limits":"two round subkeys only; remaining FM subkeys and SHAKE master-key inversion are not recovered"})
    print(f"External one-round recovery: {count}/{count} keys, k0/k3 verified on {validation} new blocks each")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args = parser.parse_args()
    analyze(args.check)
