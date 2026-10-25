#ifndef INTERLOCK_TEST_BRIDGE_H
#define INTERLOCK_TEST_BRIDGE_H
#include "interlock.h"

size_t il_test_ctx_size(void);
uint32_t il_test_sbox(uint32_t x);
uint32_t il_test_linear(uint32_t x);
uint32_t il_test_fs(uint32_t x, uint32_t k);
uint32_t il_test_fm(uint32_t x, uint32_t k);
void il_test_round(uint32_t state[4], const uint32_t key[4], int inverse);
int il_test_reduced(const interlock_ctx *ctx, uint8_t *out, const uint8_t *in, unsigned rounds);
int il_test_batch(const interlock_ctx *ctx, uint8_t *out, const uint8_t *in,
                  size_t count, unsigned rounds, int inverse);
int il_test_components(uint32_t *out, const uint32_t *in, size_t count, uint32_t key, int mixed);
int il_test_diff_counts(uint64_t *counts, const uint8_t *pairs, size_t count, unsigned block_bytes);
#endif
