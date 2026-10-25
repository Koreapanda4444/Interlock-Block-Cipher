#include <string.h>
#include "interlock.h"
#include "interlock_internal.h"
#include "shake256.h"

#define IL_READY UINT32_C(0x494c4f43)

void interlock_clear(interlock_ctx *ctx)
{
    if (ctx != NULL) il_wipe(ctx, sizeof *ctx);
}

int interlock_init(interlock_ctx *ctx, const uint8_t *key, size_t key_len)
{
    static const uint8_t domain[] = "Interlock-128/roundkeys";
    uint8_t input[sizeof domain + INTERLOCK_KEY_BYTES];
    uint8_t expanded[INTERLOCK_ROUNDS * INTERLOCK_BLOCK_BYTES];
    if (ctx == NULL) return INTERLOCK_ERR_ARGUMENT;
    if (key == NULL || key_len != INTERLOCK_KEY_BYTES) {
        interlock_clear(ctx);
        return INTERLOCK_ERR_ARGUMENT;
    }
    /* sizeof(domain) includes exactly the specified 00 separator. */
    memcpy(input, domain, sizeof domain);
    memcpy(input + sizeof domain, key, INTERLOCK_KEY_BYTES);
    (void)il_shake256(expanded, sizeof expanded, input, sizeof input);
    for (unsigned r = 0; r < INTERLOCK_ROUNDS; ++r)
        for (unsigned j = 0; j < 4; ++j)
            ctx->round_keys[r][j] = il_load32(expanded + 16*r + 4*j);
    ctx->initialized = IL_READY;
    il_wipe(input, sizeof input);
    il_wipe(expanded, sizeof expanded);
    return INTERLOCK_OK;
}

static int overlaps(const void *a, size_t a_len, const void *b, size_t b_len)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    return x >= y ? x-y < b_len : y-x < a_len;
}

static int crypt_block(const interlock_ctx *ctx, uint8_t *out, size_t out_capacity,
                       const uint8_t *in, size_t in_len, int decrypt)
{
    uint32_t state[4];
    if (ctx == NULL || out == NULL || in == NULL ||
        out_capacity < INTERLOCK_BLOCK_BYTES || in_len != INTERLOCK_BLOCK_BYTES)
        return INTERLOCK_ERR_ARGUMENT;
    if (overlaps(out,INTERLOCK_BLOCK_BYTES,ctx,sizeof *ctx))
        return INTERLOCK_ERR_ARGUMENT;
    if (ctx->initialized != IL_READY) return INTERLOCK_ERR_STATE;
    for (unsigned i = 0; i < 4; ++i) state[i] = il_load32(in+4*i);
    if (decrypt) {
        for (unsigned r = INTERLOCK_ROUNDS; r-- > 0;)
            il_inverse_round(state,ctx->round_keys[r]);
    } else {
        for (unsigned r = 0; r < INTERLOCK_ROUNDS; ++r)
            il_round(state,ctx->round_keys[r]);
    }
    for (unsigned i = 0; i < 4; ++i) il_store32(out+4*i,state[i]);
    il_wipe(state,sizeof state);
    return INTERLOCK_OK;
}

int interlock_encrypt_block(const interlock_ctx *ctx, uint8_t *out, size_t out_capacity,
                            const uint8_t *in, size_t in_len)
{
    return crypt_block(ctx,out,out_capacity,in,in_len,0);
}

int interlock_decrypt_block(const interlock_ctx *ctx, uint8_t *out, size_t out_capacity,
                            const uint8_t *in, size_t in_len)
{
    return crypt_block(ctx,out,out_capacity,in,in_len,1);
}
