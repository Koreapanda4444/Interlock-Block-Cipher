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

int il_test_components(uint32_t *out, const uint32_t *in, size_t count, uint32_t key, int mixed)
{
    if (count > SIZE_MAX/sizeof(uint32_t) || (mixed != 0 && mixed != 1)) return -1;
    if (count == 0) return 0;
    if (out == NULL || in == NULL) return -1;
    for (size_t i = 0; i < count; ++i) out[i] = mixed ? il_fm(in[i],key) : il_fs(in[i],key);
    return 0;
}

int il_test_diff_counts(uint64_t *counts, const uint8_t *pairs, size_t count, unsigned block_bytes)
{
    if (block_bytes == 0 || block_bytes > 16 || counts == NULL ||
        count > SIZE_MAX/(2*block_bytes) || (pairs == NULL && count != 0)) return -1;
    for (unsigned bit = 0; bit < block_bytes*8; ++bit) counts[bit] = 0;
    for (size_t i = 0; i < count; ++i) {
        for (unsigned byte = 0; byte < block_bytes; ++byte) {
            uint8_t delta = pairs[2*block_bytes*i+byte] ^ pairs[2*block_bytes*i+block_bytes+byte];
            for (unsigned bit = 0; bit < 8; ++bit)
                counts[8*byte+bit] += (uint64_t)(((unsigned)delta >> bit) & 1U);
        }
    }
    return 0;
}

/* Signed Walsh spectrum of a Boolean truth table, limited to 16 variables. */
int il_test_walsh(int32_t *out, const uint8_t *truth, size_t count)
{
    if (out == NULL || truth == NULL || count == 0 || count > 65536 ||
        (count & (count-1)) != 0) return -1;
    for (size_t i = 0; i < count; ++i) if (truth[i] > 1) return -1;
    for (size_t i = 0; i < count; ++i) out[i] = truth[i] != 0 ? -1 : 1;
    for (size_t step = 1; step < count; step *= 2) {
        for (size_t block = 0; block < count; block += 2*step) {
            for (size_t i = 0; i < step; ++i) {
                int32_t a = out[block+i], b = out[block+i+step];
                out[block+i] = a+b;
                out[block+i+step] = a-b;
            }
        }
    }
    return 0;
}
