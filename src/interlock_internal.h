#ifndef INTERLOCK_INTERNAL_H
#define INTERLOCK_INTERNAL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(CHAR_BIT == 8, "Interlock requires 8-bit bytes");
_Static_assert(sizeof(uint32_t) == 4, "Interlock requires uint32_t");
_Static_assert(sizeof(uint64_t) == 8, "SHAKE requires uint64_t");

static inline uint32_t il_load32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void il_store32(uint8_t *p, uint32_t x)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(x >> (8 * i));
}

static inline uint32_t il_rol32(uint32_t x, unsigned n)
{
    n &= 31U;
    return (uint32_t)((x << n) | (x >> ((32U - n) & 31U)));
}

static inline uint32_t il_ror32(uint32_t x, unsigned n)
{
    return il_rol32(x, (32U - (n & 31U)) & 31U);
}

static inline void il_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n-- != 0) *v++ = 0;
}

/* PRESENT truth table, expressed in ANF on eight parallel nibble planes. */
static inline uint32_t il_sbox(uint32_t x)
{
    const uint32_t m = UINT32_C(0x11111111);
    uint32_t x0 = x & m, x1 = (x >> 1) & m;
    uint32_t x2 = (x >> 2) & m, x3 = (x >> 3) & m;
    uint32_t y0 = x0 ^ x2 ^ (x1 & x2) ^ x3;
    uint32_t y1 = x1 ^ (x0 & x1 & x2) ^ x3 ^ (x1 & x3) ^
                  (x0 & x1 & x3) ^ (x2 & x3) ^ (x0 & x2 & x3);
    uint32_t y2 = m ^ (x0 & x1) ^ x2 ^ x3 ^ (x0 & x3) ^
                  (x1 & x3) ^ (x0 & x1 & x3) ^ (x0 & x2 & x3);
    uint32_t y3 = m ^ x0 ^ x1 ^ (x1 & x2) ^ (x0 & x1 & x2) ^ x3 ^
                  (x0 & x1 & x3) ^ (x0 & x2 & x3);
    return y0 | (y1 << 1) | (y2 << 2) | (y3 << 3);
}

static inline uint32_t il_linear(uint32_t x)
{
    return x ^ il_rol32(x, 3) ^ il_rol32(x, 17);
}

static inline uint32_t il_fs(uint32_t x, uint32_t k)
{
    return il_linear(il_sbox(x ^ k));
}

static inline uint32_t il_fm(uint32_t x, uint32_t k)
{
    uint32_t y = il_sbox(x ^ k);
    uint32_t u = (uint32_t)(y + il_rol32(k, 9));
    uint32_t v = il_rol32(y ^ k, 7);
    uint32_t w = il_rol32((uint32_t)(u + v), 11) ^
                 il_rol32(y & il_rol32(k, 3), 19);
    return il_linear(il_sbox(w ^ il_rol32(k, 13)));
}

#endif
