#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "interlock.h"

static volatile uint32_t sink;

static uint64_t nanoseconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC,&value) != 0) abort();
    return (uint64_t)value.tv_sec*UINT64_C(1000000000)+(uint64_t)value.tv_nsec;
}

static double measure(unsigned operation, unsigned iterations)
{
    interlock_ctx ctx = {0};
    uint8_t key[32] = {0}, state[16] = {0};
    if (interlock_init(&ctx,key,32) != INTERLOCK_OK) abort();
    const uint64_t begin = nanoseconds();
    for (unsigned i = 0; i < iterations; ++i) {
        int status;
        if (operation == 0) {
            key[0] = (uint8_t)i;
            status = interlock_init(&ctx,key,32);
        } else if (operation == 1) {
            status = interlock_encrypt_block(&ctx,state,16,state,16);
        } else if (operation == 2) {
            status = interlock_decrypt_block(&ctx,state,16,state,16);
        } else {
            key[0] = (uint8_t)i;
            status = interlock_init(&ctx,key,32);
            if (status != INTERLOCK_OK) abort();
            status = interlock_encrypt_block(&ctx,state,16,state,16);
            interlock_clear(&ctx);
        }
        if (status != INTERLOCK_OK) abort();
    }
    const uint64_t end = nanoseconds();
    sink ^= (uint32_t)state[0] ^ (uint32_t)key[0];
    interlock_clear(&ctx);
    if (end <= begin) abort();
    return (double)(end-begin)/(double)iterations;
}

int main(void)
{
    static const char *names[] = {"key_init","encrypt_prepared","decrypt_prepared","init_encrypt_clear"};
    static const unsigned iterations[] = {2000,50000,50000,2000};
    struct timespec resolution;
    if (clock_getres(CLOCK_MONOTONIC,&resolution) != 0) return 1;
    printf("{\"context_bytes\":%zu,\"pointer_bits\":%zu,\"clock_resolution_ns\":%" PRIu64 ",\"rows\":[",
        sizeof(interlock_ctx),sizeof(void *)*8,
        (uint64_t)resolution.tv_sec*UINT64_C(1000000000)+(uint64_t)resolution.tv_nsec);
    for (unsigned operation = 0; operation < 4; ++operation) {
        (void)measure(operation,128);
        printf("%s{\"operation\":\"%s\",\"iterations\":%u,\"samples_ns\":[",
            operation != 0 ? "," : "",names[operation],iterations[operation]);
        for (unsigned sample = 0; sample < 7; ++sample)
            printf("%s%.6f",sample != 0 ? "," : "",measure(operation,iterations[operation]));
        printf("]}");
    }
    printf("],\"checksum\":%" PRIu32 "}\n",sink);
    return 0;
}
