"""Exact FS nibble distributions and independent-sample local FM screening."""

from collections import Counter
import ctypes as C
import hashlib
import math
import random
import struct

from common import Session, difference_counts, load_library, ref, require
from verify import U32

SEED = 0x434f4d504f4e454e


def evaluate(lib, inputs, key, mixed):
    source = (U32 * len(inputs))(*inputs)
    output = (U32 * len(inputs))()
    require(lib.il_test_components(output,source,len(inputs),key,mixed) == 0, "component batch")
    return list(output)


def sample_words(delta, count, seed, forbidden=()):
    rng = random.Random(seed)
    pivot = delta & -delta
    seen = set(forbidden)
    values = []
    while len(values) < count:
        value = rng.getrandbits(32) & ~pivot
        if value not in seen:
            seen.add(value)
            values.append(value)
    return values


def measure(lib, delta, key, count, seed, forbidden=()):
    values = sample_words(delta,count,seed,forbidden)
    inputs = [y for x in values for y in (x,x ^ delta)]
    output = evaluate(lib,inputs,key,1)
    packed = struct.pack(f"<{len(output)}I", *output)
    counts = difference_counts(packed,4,lib)
    worst = max(range(32), key=lambda b: abs(counts[b]/count-0.5))
    histogram = Counter(output[2*i] ^ output[2*i+1] for i in range(count))
    dominant, hits = min(histogram.items(), key=lambda x: (-x[1],x[0]))
    return {"input_difference": f"{delta:08x}", "samples": count, "seed": hex(seed),
            "input_sha256": hashlib.sha256(struct.pack(f"<{len(inputs)}I", *inputs)).hexdigest(),
            "bit_counts": counts, "worst_bit": worst, "max_abs_bit_bias": abs(counts[worst]/count-0.5),
            "dominant_observed_difference": f"{dominant:08x}", "dominant_count": hits,
            "observed_difference_count": len(histogram)}


def analyze():
    session = Session(SEED)
    lib = load_library()
    rng = random.Random(SEED)
    keys = [0,0xffffffff,0x55555555,0xaaaaaaaa,0x12345678,rng.getrandbits(32)]
    exact = []
    fs_evaluations = 0
    for position in range(8):
        for delta in range(1,16):
            row = Counter(ref.SBOX[x] ^ ref.SBOX[x ^ delta] for x in range(16))
            expected = {ref.linear(d << (4*position)): n for d,n in row.items()}
            for key in keys:
                base = rng.getrandbits(32) & ~(15 << (4*position))
                inputs = [v for x in range(16) for v in (base | (x << (4*position)),
                          (base | (x << (4*position))) ^ (delta << (4*position)))]
                output = evaluate(lib,inputs,key,0)
                observed = Counter(output[i] ^ output[i+1] for i in range(0,len(output),2))
                require(observed == expected, "exact FS nibble DDT under key translation")
                fs_evaluations += len(inputs)
            exact.append({"nibble": position, "delta": delta, "max_probability": max(row.values())/16,
                          "output_counts": {f"{d:08x}": n for d,n in sorted(expected.items())}})
    deltas = sorted({*(1 << i for i in range(32)), *(3 << (4*i) for i in range(8)),
                     *(15 << (4*i) for i in range(8)), 0x10001,0x80000001,0xffffffff})
    training, validation = [], []
    for ki,key in enumerate(keys):
        per_key = []
        for delta in deltas:
            seed = SEED ^ (ki << 40) ^ delta
            result = measure(lib,delta,key,1024,seed)
            result["key_index"] = ki
            training.append(result)
            per_key.append(result)
        selected = sorted(per_key,key=lambda r: (-r["max_abs_bit_bias"],r["input_difference"]))[:4]
        for row in selected:
            delta = int(row["input_difference"],16)
            forbidden = sample_words(delta,1024,int(row["seed"],16))
            result = measure(lib,delta,key,8192,int(row["seed"],16) ^ 0x484f4c444f5554,forbidden)
            result.update({"key_index": ki, "training_max_abs_bit_bias": row["max_abs_bit_bias"],
                           "training_input_sha256": row["input_sha256"], "disjoint_plaintext_pairs": True})
            validation.append(result)
    family = len(validation)*32
    threshold = math.sqrt(math.log(2*family/0.01)/(2*8192))
    result = {"oracle_model": "isolated 32-bit FS/FM with a known fixed subkey, not full-block queries",
              "subkey_hex": [f"{k:08x}" for k in keys], "exact_fs": exact,
              "fm_training": training, "fm_validation": validation,
              "component_evaluations": fs_evaluations + 2*(len(training)*1024+len(validation)*8192),
              "validation_family_tests": family, "validation_reference_alpha": 0.01,
              "validation_bernoulli_bias_threshold": threshold,
              "limits": "IID Bernoulli reference; local-function diagnostics, not a cipher attack probability"}
    session.save("components",result)
    print(f"components: exact FS cases={len(exact)} x {len(keys)} keys; FM train={len(training)}, "
          f"holdout={len(validation)}, maximum holdout bit bias={max(r['max_abs_bit_bias'] for r in validation):.6f}")


if __name__ == "__main__":
    analyze()
