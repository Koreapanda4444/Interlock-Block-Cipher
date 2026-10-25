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
