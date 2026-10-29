#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "interlock.h"

#define REQUIRE(expr) do { if (!(expr)) abort(); } while (0)

static int all_zero(const void *p, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)p;
    for (size_t i = 0; i < size; ++i) if (bytes[i] != 0) return 0;
    return 1;
}

static void unchanged_outside(const uint8_t *now, const uint8_t *before, size_t offset)
{
    for (size_t i = 0; i < 64; ++i)
        if (i < offset || i >= offset+16) REQUIRE(now[i] == before[i]);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t bytes[64] = {0}, work[64], saved[64], cipher[16], plain[16];
    interlock_ctx ctx = {0}, baseline;
    if (size > sizeof bytes) size = sizeof bytes;
    if (size != 0) memcpy(bytes,data,size);
    REQUIRE(interlock_init(&ctx,bytes,32) == INTERLOCK_OK);
    baseline = ctx;
    REQUIRE(interlock_encrypt_block(&ctx,cipher,16,bytes+32,16) == INTERLOCK_OK);
    REQUIRE(interlock_decrypt_block(&ctx,plain,16,cipher,16) == INTERLOCK_OK);
    REQUIRE(memcmp(plain,bytes+32,16) == 0);
    const size_t destination = 1U+(size_t)(bytes[48]%31U);
    for (unsigned inverse = 0; inverse < 2; ++inverse) {
        memset(work,0xa5,sizeof work);
        memcpy(work+16,inverse != 0 ? cipher : bytes+32,16);
        memcpy(saved,work,sizeof saved);
        const int result = inverse != 0 ?
            interlock_decrypt_block(&ctx,work+destination,16,work+16,16) :
            interlock_encrypt_block(&ctx,work+destination,16,work+16,16);
        REQUIRE(result == INTERLOCK_OK);
        REQUIRE(memcmp(work+destination,inverse != 0 ? bytes+32 : cipher,16) == 0);
        unchanged_outside(work,saved,destination);
    }
    memset(work,0x5a,sizeof work);
    memcpy(saved,work,sizeof saved);
    const size_t length = bytes[49]%32U, capacity = bytes[50]%32U;
    const int result = interlock_encrypt_block(&ctx,work,capacity,bytes+32,length);
    if (length == 16 && capacity >= 16) {
        REQUIRE(result == INTERLOCK_OK);
        REQUIRE(memcmp(work,cipher,16) == 0);
        unchanged_outside(work,saved,0);
    } else {
        REQUIRE(result == INTERLOCK_ERR_ARGUMENT);
        REQUIRE(memcmp(work,saved,sizeof work) == 0);
    }
    const unsigned nulls = 1U+(bytes[51]%7U);
    memcpy(work,saved,sizeof work);
    REQUIRE(interlock_decrypt_block((nulls & 1U) != 0 ? NULL : &ctx,
        (nulls & 2U) != 0 ? NULL : work,16,
        (nulls & 4U) != 0 ? NULL : cipher,16) == INTERLOCK_ERR_ARGUMENT);
    REQUIRE(memcmp(work,saved,sizeof work) == 0);
    const size_t alias = ((size_t)bytes[53] | ((size_t)bytes[55] << 8))%(sizeof ctx-32U+1U);
    memcpy((uint8_t *)&ctx+alias,bytes,32);
    REQUIRE(interlock_init(&ctx,(const uint8_t *)&ctx+alias,32) == INTERLOCK_OK);
    REQUIRE(memcmp(&ctx,&baseline,sizeof ctx) == 0);
    const size_t key_length = bytes[52]%64U;
    const uint8_t *key = (bytes[54] & 1U) != 0 ? NULL : bytes;
    const int init_result = interlock_init(&ctx,key,key_length);
    if (key != NULL && key_length == 32) {
        REQUIRE(init_result == INTERLOCK_OK);
    } else {
        REQUIRE(init_result == INTERLOCK_ERR_ARGUMENT);
        REQUIRE(all_zero(&ctx,sizeof ctx));
        REQUIRE(interlock_encrypt_block(&ctx,work,16,bytes+32,16) == INTERLOCK_ERR_STATE);
        REQUIRE(memcmp(work,saved,sizeof work) == 0);
    }
    interlock_clear(&ctx);
    interlock_clear(&baseline);
    REQUIRE(all_zero(&ctx,sizeof ctx));
    return 0;
}

#ifdef IL_FUZZ_STANDALONE
int main(void)
{
    uint32_t state = UINT32_C(0x494c465a);
    uint8_t data[64];
    for (unsigned trial = 0; trial < 8192; ++trial) {
        for (unsigned i = 0; i < sizeof data; ++i) {
            state ^= state << 13; state ^= state >> 17; state ^= state << 5;
            data[i] = (uint8_t)state;
        }
        (void)LLVMFuzzerTestOneInput(data,trial%65U);
    }
    puts("Deterministic fuzz regression: 8192 inputs passed");
    return 0;
}
#endif
