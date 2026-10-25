/* Test-only entry points; never linked into the public static library. */
#include "bridge.h"
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

/* A valid initialized context and nonoverlapping block arrays are preconditions.
 * Exact in-place operation is supported. No production library links this code. */
int il_test_batch(const interlock_ctx *ctx, uint8_t *out, const uint8_t *in,
                  size_t count, unsigned rounds, int inverse)
{
    uint32_t state[4];
    if (rounds > INTERLOCK_ROUNDS || (inverse != 0 && inverse != 1) || count > SIZE_MAX/16)
        return -1;
    if (count == 0) return 0;
    if (ctx == NULL || out == NULL || in == NULL) return -1;
    for (size_t block = 0; block < count; ++block) {
        for (unsigned i = 0; i < 4; ++i) state[i] = il_load32(in+16*block+4*i);
        if (inverse) {
            for (unsigned r = rounds; r-- > 0;) il_inverse_round(state,ctx->round_keys[r]);
        } else {
            for (unsigned r = 0; r < rounds; ++r) il_round(state,ctx->round_keys[r]);
        }
        for (unsigned i = 0; i < 4; ++i) il_store32(out+16*block+4*i,state[i]);
    }
    il_wipe(state,sizeof state);
    return 0;
}

int il_test_reduced(const interlock_ctx *ctx, uint8_t *out, const uint8_t *in, unsigned rounds)
{
    return il_test_batch(ctx,out,in,1,rounds,0);
}
