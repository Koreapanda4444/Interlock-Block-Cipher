#ifndef INTERLOCK_SHAKE256_H
#define INTERLOCK_SHAKE256_H

#include <stddef.h>
#include <stdint.h>

/* Internal one-shot XOF. NULL is allowed only for a zero-length region. */
int il_shake256(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);

#endif
