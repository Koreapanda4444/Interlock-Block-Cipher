"""Cross-check the C implementation with independent Python bit operations."""

import ctypes as C
import hashlib
import random
import struct

import reference as ref

U8 = C.c_uint8
U32 = C.c_uint32
P8 = C.POINTER(U8)
P32 = C.POINTER(U32)
SEED = 0x494C4F434B


class Context(C.Structure):
    _fields_ = [("round_keys", (U32 * 4) * 28), ("initialized", U32)]


def array(data):
    return (U8 * len(data)).from_buffer_copy(data)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def load_library():
    lib = C.CDLL(str(ref.ROOT / "build/verify.so"))
    for name in ("interlock_encrypt_block", "interlock_decrypt_block"):
        f = getattr(lib, name)
        f.argtypes = [C.POINTER(Context), P8, C.c_size_t, P8, C.c_size_t]
        f.restype = C.c_int
    lib.interlock_init.argtypes = [C.POINTER(Context), P8, C.c_size_t]
    lib.interlock_init.restype = C.c_int
    lib.interlock_clear.argtypes = [C.POINTER(Context)]
    lib.interlock_clear.restype = None
    lib.il_test_ctx_size.argtypes = []
    lib.il_test_ctx_size.restype = C.c_size_t
    for name in ("il_test_sbox", "il_test_linear"):
        getattr(lib, name).argtypes = [U32]
        getattr(lib, name).restype = U32
    for name in ("il_test_fs", "il_test_fm"):
        getattr(lib, name).argtypes = [U32, U32]
        getattr(lib, name).restype = U32
    lib.il_test_round.argtypes = [P32, P32, C.c_int]
    lib.il_test_round.restype = None
    lib.il_test_reduced.argtypes = [C.POINTER(Context), P8, P8, C.c_uint]
    lib.il_test_reduced.restype = C.c_int
    lib.il_shake256.argtypes = [P8, C.c_size_t, P8, C.c_size_t]
    lib.il_shake256.restype = C.c_int
    require(lib.il_test_ctx_size() == C.sizeof(Context), "ctypes context layout")
    return lib


def check_shake(lib, rng):
    lengths = (0, 1, 7, 8, 23, 55, 56, 135, 136, 137, 271, 272, 273, 1024)
    outputs = (0, 1, 7, 64, 135, 136, 137, 272, 448, 1024)
    for n in lengths:
        message = rng.randbytes(n)
        for m in outputs:
            out = (U8 * m)()
            require(lib.il_shake256(out, m, array(message), n) == 0, "SHAKE call")
            require(bytes(out) == hashlib.shake_256(message).digest(m), f"SHAKE {n}/{m}")
    return len(lengths) * len(outputs)


def check_components(lib, rng):
    values = (0, 1, 0xffffffff, 0x80000000, 0x55555555, 0xaaaaaaaa)
    pairs = [(x, k) for x in values for k in values]
    pairs += [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(1024)]
    for x, k in pairs:
        require(lib.il_test_sbox(x) == ref.substitution(x), "S-box word")
        require(lib.il_test_fs(x, k) == ref.fs(x, k), "FS")
        require(lib.il_test_fm(x, k) == ref.fm(x, k), "FM carry/rotation")
    return len(pairs)


def check_blocks(lib, rng):
    pairs = ref.cases()
    pairs += [((1 << b).to_bytes(32, "little"), bytes(16)) for b in range(256)]
    pairs += [(bytes(32), (1 << b).to_bytes(16, "little")) for b in range(128)]
    pairs += [(rng.randbytes(32), rng.randbytes(16)) for _ in range(256)]
    for index, (key, block) in enumerate(pairs):
        ctx = Context()
        require(lib.interlock_init(C.byref(ctx), array(key), 32) == 0, "init")
        keys, states, ciphertext = ref.trace(key, block)
        require([tuple(row) for row in ctx.round_keys] == keys, f"all subkeys {index}")
        state = (U32 * 4)(*states[0])
        for r in range(28):
            lib.il_test_round(state, ctx.round_keys[r], 0)
            require(tuple(state) == states[r + 1], f"forward {index}/{r}")
        for r in range(27, -1, -1):
            lib.il_test_round(state, ctx.round_keys[r], 1)
            require(tuple(state) == states[r], f"inverse {index}/{r}")
        inverse = struct.unpack("<4I", ciphertext)
        for k in reversed(keys):
            inverse = ref.backward(inverse, k)
        require(struct.pack("<4I", *inverse) == block, "independent inverse")
        out = (U8 * 16)()
        require(lib.interlock_encrypt_block(C.byref(ctx), out, 16, array(block), 16) == 0, "encrypt")
        require(bytes(out) == ciphertext, f"ciphertext {index}")
        require(lib.interlock_decrypt_block(C.byref(ctx), out, 16, array(ciphertext), 16) == 0, "decrypt")
        require(bytes(out) == block, f"plaintext {index}")
        for r in (0, 1, 2, 4, 28):
            require(lib.il_test_reduced(C.byref(ctx), out, array(block), r) == 0, "reduced call")
            require(bytes(out) == struct.pack("<4I", *states[r]), "reduced/core consistency")
        require(lib.il_test_reduced(C.byref(ctx), out, array(block), 29) == -1, "round limit")
        lib.interlock_clear(C.byref(ctx))
    return len(pairs)


def main():
    require((ref.ROOT / "tests/vectors.h").read_text() == ref.vector_header(), "KAT/specification drift")
    record = (ref.ROOT / "docs/security_ko.md").read_text()
    for path in ("docs/spec_ko.md", "tests/vectors.h"):
        digest = hashlib.sha256((ref.ROOT / path).read_bytes()).hexdigest()
        require(digest in record, f"Research record fingerprint drift: {path}")
    lib = load_library()
    rng = random.Random(SEED)
    shake = check_shake(lib, rng)
    components = check_components(lib, rng)
    blocks = check_blocks(lib, rng)
    print(f"Independent cross-check passed: seed={SEED:#x}, SHAKE={shake}, "
          f"FS/FM={components}, full keys/traces/inverses={blocks}")


if __name__ == "__main__":
    main()
