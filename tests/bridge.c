/* Test-only entry points; never linked into the public static library. */
#include "interlock.h"
#include "interlock_internal.h"

size_t il_test_ctx_size(void) { return sizeof(interlock_ctx); }
uint32_t il_test_sbox(uint32_t x) { return il_sbox(x); }
uint32_t il_test_linear(uint32_t x) { return il_linear(x); }
uint32_t il_test_fs(uint32_t x, uint32_t k) { return il_fs(x,k); }
uint32_t il_test_fm(uint32_t x, uint32_t k) { return il_fm(x,k); }

void il_test_round(uint32_t state[4], const uint32_t key[4], int inverse)
{
    if (inverse) il_inverse_round(state,key);
    else il_round(state,key);
}

/* The caller must pass a successfully initialized context. */
int il_test_reduced(const interlock_ctx *ctx, uint8_t *out, const uint8_t *in, unsigned rounds)
{
    uint32_t state[4];
    if (ctx == NULL || out == NULL || in == NULL || rounds > INTERLOCK_ROUNDS) return -1;
    for (unsigned i = 0; i < 4; ++i) state[i] = il_load32(in+4*i);
    for (unsigned r = 0; r < rounds; ++r) il_round(state,ctx->round_keys[r]);
    for (unsigned i = 0; i < 4; ++i) il_store32(out+4*i,state[i]);
    il_wipe(state,sizeof state);
    return 0;
}
