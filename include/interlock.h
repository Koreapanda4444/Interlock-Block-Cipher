#ifndef INTERLOCK_H
#define INTERLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INTERLOCK_BLOCK_BYTES 16U
#define INTERLOCK_KEY_BYTES 32U
#define INTERLOCK_ROUNDS 28U

enum { INTERLOCK_OK = 0, INTERLOCK_ERR_ARGUMENT = -1, INTERLOCK_ERR_STATE = -2 };

/* Zero-initialize or call init before use. Do not edit or serialize the fields. */
typedef struct {
    uint32_t round_keys[INTERLOCK_ROUNDS][4];
    uint32_t initialized;
} interlock_ctx;

/* Exact 32-byte key. Invalid key arguments erase a non-NULL context. */
int interlock_init(interlock_ctx *ctx, const uint8_t *key, size_t key_len);
void interlock_clear(interlock_ctx *ctx);

/* Exact 16-byte input; capacity >= 16. Output is unchanged on failure.
 * Input/output may overlap. Output must not overlap ctx. */
int interlock_encrypt_block(const interlock_ctx *ctx, uint8_t *out, size_t out_capacity,
                            const uint8_t *in, size_t in_len);
int interlock_decrypt_block(const interlock_ctx *ctx, uint8_t *out, size_t out_capacity,
                            const uint8_t *in, size_t in_len);

#ifdef __cplusplus
}
#endif
#endif
