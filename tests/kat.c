#include <stdio.h>
#include <string.h>
#include "interlock_internal.h"

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

int main(void)
{
    CHECK(primitives() == 0);
    puts("C checks passed: S-box exhaustive positions, rotations, unaligned LE32, erase");
    return 0;
}
