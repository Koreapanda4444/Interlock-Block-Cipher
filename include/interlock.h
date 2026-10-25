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

#ifdef __cplusplus
}
#endif
#endif
