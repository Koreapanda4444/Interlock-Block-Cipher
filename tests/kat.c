#include <stdio.h>
#include <string.h>
#include "interlock_internal.h"
#include "shake256.h"
#include "interlock.h"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; \
} } while (0)

static int primitives(void)
{
    static const uint8_t s[16] = {12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2};
    uint8_t bytes[9] = {0};
    for (unsigned nibble = 0; nibble < 8; ++nibble) {
        for (unsigned value = 0; value < 16; ++value) {
            uint32_t x = (uint32_t)value << (nibble * 4);
            uint32_t expected = UINT32_C(0xcccccccc);
            expected &= ~(UINT32_C(15) << (nibble * 4));
            expected |= (uint32_t)s[value] << (nibble * 4);
            CHECK(il_sbox(x) == expected);
        }
    }
    for (unsigned n = 0; n < 96; ++n) {
        for (unsigned bit = 0; bit < 32; ++bit) {
            uint32_t x = UINT32_C(1) << bit;
            CHECK(il_rol32(x,n) == (UINT32_C(1) << ((bit+n)%32)));
            CHECK(il_ror32(il_rol32(x,n),n) == x);
        }
    }
    for (unsigned bit = 0; bit < 32; ++bit) {
        uint32_t x = UINT32_C(1) << bit;
        il_store32(bytes+1, x);
        CHECK(il_load32(bytes+1) == x);
        CHECK(bytes[0] == 0 && bytes[5] == 0);
    }
    il_store32(bytes+1, UINT32_C(0x89abcdef));
    CHECK(bytes[1] == 0xef && bytes[2] == 0xcd &&
          bytes[3] == 0xab && bytes[4] == 0x89);
    memset(bytes, 0xff, sizeof bytes);
    il_wipe(bytes, sizeof bytes);
    for (unsigned i = 0; i < sizeof bytes; ++i) CHECK(bytes[i] == 0);
    return 0;
}

static int hex_equal(const uint8_t *actual, const char *hex, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned byte;
        if (sscanf(hex+2*i, "%2x", &byte) != 1 || actual[i] != byte) return 0;
    }
    return 1;
}

static int shake(void)
{
    /* First 512 output bits of the NIST SHAKE256 Msg0 and Msg1600 examples. */
    static const char empty[] =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    static const char a3[] =
        "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
        "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b";
    uint8_t input[200], out[64];
    CHECK(il_shake256(out, sizeof out, NULL, 0) == 0);
    CHECK(hex_equal(out, empty, sizeof out));
    memset(input, 0xa3, sizeof input);
    CHECK(il_shake256(out, sizeof out, input, sizeof input) == 0);
    CHECK(hex_equal(out, a3, sizeof out));
    memset(out, 0x5a, sizeof out);
    CHECK(il_shake256(out, sizeof out, NULL, 1) == -1);
    for (unsigned i = 0; i < sizeof out; ++i) CHECK(out[i] == 0x5a);
    CHECK(il_shake256(NULL, 1, input, sizeof input) == -1);
    CHECK(il_shake256(NULL, 0, NULL, 0) == 0);
    return 0;
}

static int schedule(void)
{
    /* Independently calculated with Python hashlib.shake_256, not this C XOF. */
    static const uint32_t first[2][4] = {
        {0x634a205d,0xd56cc590,0xd6cf518c,0x9c8022bf},
        {0x4fa30366,0xa9c54156,0xd03461f0,0x4c6b264a}
    };
    static const uint32_t last[2][4] = {
        {0x2315c82b,0x3b5f4693,0xc3cab5d3,0x80f8f50b},
        {0x8e035ac9,0x590a5906,0x7e315ea2,0x8358460a}
    };
    interlock_ctx ctx = {0}, expected = {0};
    uint8_t key[32] = {0};
    for (unsigned kind = 0; kind < 2; ++kind) {
        for (unsigned i = 0; i < sizeof key; ++i) key[i] = kind ? (uint8_t)i : 0;
        CHECK(interlock_init(&ctx,key,sizeof key) == INTERLOCK_OK);
        for (unsigned j = 0; j < 4; ++j) {
            CHECK(ctx.round_keys[0][j] == first[kind][j]);
            CHECK(ctx.round_keys[27][j] == last[kind][j]);
        }
    }
    expected = ctx;
    memcpy(&ctx,key,sizeof key);
    CHECK(interlock_init(&ctx,(const uint8_t *)&ctx,sizeof key) == INTERLOCK_OK);
    CHECK(memcmp(ctx.round_keys,expected.round_keys,sizeof ctx.round_keys) == 0);
    CHECK(interlock_init(&ctx,key,31) == INTERLOCK_ERR_ARGUMENT);
    for (size_t i = 0; i < sizeof ctx; ++i) CHECK(((const uint8_t *)&ctx)[i] == 0);
    CHECK(interlock_init(&ctx,NULL,32) == INTERLOCK_ERR_ARGUMENT);
    CHECK(interlock_init(&ctx,key,33) == INTERLOCK_ERR_ARGUMENT);
    CHECK(interlock_init(NULL,key,32) == INTERLOCK_ERR_ARGUMENT);
    interlock_clear(&expected);
    interlock_clear(NULL);
    return 0;
}

int main(void)
{
    CHECK(primitives() == 0);
    CHECK(shake() == 0);
    CHECK(schedule() == 0);
    puts("C checks passed: primitives, NIST SHAKE256, schedule KAT, invalid arguments");
    return 0;
}
