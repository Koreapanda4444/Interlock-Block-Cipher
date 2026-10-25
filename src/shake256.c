#include "shake256.h"
#include "interlock_internal.h"

static uint64_t rol64(uint64_t x, unsigned n)
{
    n &= 63U;
    return (x << n) | (x >> ((64U - n) & 63U));
}

/* Original byte-portable implementation of FIPS 202, Keccak-f[1600]. */
static void keccak(uint64_t a[25])
{
    static const uint64_t rc[24] = {
        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
        UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
        UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
        UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
        UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
        UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
        UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
        UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
    };
    static const unsigned rotations[25] = {
        0,1,62,28,27, 36,44,6,55,20, 3,10,43,25,39,
        41,45,15,21,8, 18,2,61,56,14
    };
    uint64_t b[25], c[5], d[5];
    for (unsigned round = 0; round < 24; ++round) {
        for (unsigned x = 0; x < 5; ++x)
            c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20];
        for (unsigned x = 0; x < 5; ++x)
            d[x] = c[(x+4)%5] ^ rol64(c[(x+1)%5], 1);
        for (unsigned y = 0; y < 5; ++y) {
            for (unsigned x = 0; x < 5; ++x) {
                unsigned i = x + 5*y;
                b[y + 5*((2*x+3*y)%5)] = rol64(a[i] ^ d[x], rotations[i]);
            }
        }
        for (unsigned y = 0; y < 5; ++y) {
            for (unsigned x = 0; x < 5; ++x)
                a[x+5*y] = b[x+5*y] ^ (~b[(x+1)%5+5*y] & b[(x+2)%5+5*y]);
        }
        a[0] ^= rc[round];
    }
    il_wipe(b, sizeof b);
    il_wipe(c, sizeof c);
    il_wipe(d, sizeof d);
}

int il_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
    uint64_t state[25] = {0};
    size_t pos = 0;
    if ((out == NULL && out_len != 0) || (in == NULL && in_len != 0)) return -1;
    for (size_t i = 0; i < in_len; ++i) {
        state[pos/8] ^= (uint64_t)in[i] << (8*(pos%8));
        if (++pos == 136) { keccak(state); pos = 0; }
    }
    state[pos/8] ^= UINT64_C(0x1f) << (8*(pos%8));
    state[16] ^= UINT64_C(0x8000000000000000);
    keccak(state);
    pos = 0;
    for (size_t i = 0; i < out_len; ++i) {
        if (pos == 136) { keccak(state); pos = 0; }
        out[i] = (uint8_t)(state[pos/8] >> (8*(pos%8)));
        ++pos;
    }
    il_wipe(state, sizeof state);
    return 0;
}
