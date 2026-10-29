#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>
#include "interlock.h"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr,"ctcheck:%d: %s\n",__LINE__,#expr); return 1; \
} } while (0)

static int negative_control(const char *mode)
{
    volatile unsigned secret = 1;
    volatile uint8_t table[4] = {0,1,2,3};
    volatile uint8_t sink;
    (void)VALGRIND_MAKE_MEM_UNDEFINED((void *)&secret,sizeof secret);
    if (strcmp(mode,"--branch-control") == 0) {
        if (secret != 0) puts("deliberate secret-dependent branch");
    } else {
        sink = table[secret & 3U];
        (void)VALGRIND_MAKE_MEM_DEFINED((void *)&sink,sizeof sink);
    }
    (void)VALGRIND_MAKE_MEM_DEFINED((void *)&secret,sizeof secret);
    return 0;
}

int main(int argc, char **argv)
{
    if (RUNNING_ON_VALGRIND == 0) {
        fputs("Run with Valgrind Memcheck; native execution does not audit secrets.\n",stderr);
        return 2;
    }
    if (argc == 2 && (strcmp(argv[1],"--branch-control") == 0 ||
                      strcmp(argv[1],"--address-control") == 0))
        return negative_control(argv[1]);
    CHECK(argc == 1);
    for (unsigned sample = 0; sample < 16; ++sample) {
        interlock_ctx ctx = {0};
        uint8_t key[32], plain[16], expected[16], cipher[16], overlap[32] = {0};
        for (unsigned i = 0; i < sizeof key; ++i) key[i] = (uint8_t)(sample*37U+i*17U);
        for (unsigned i = 0; i < sizeof plain; ++i) plain[i] = (uint8_t)(sample*13U+i*31U);
        memcpy(expected,plain,sizeof expected);
        (void)VALGRIND_MAKE_MEM_UNDEFINED(key,sizeof key);
        (void)VALGRIND_MAKE_MEM_UNDEFINED(plain,sizeof plain);
        CHECK(interlock_init(&ctx,key,sizeof key) == INTERLOCK_OK);
        CHECK(interlock_encrypt_block(&ctx,cipher,sizeof cipher,plain,sizeof plain) == INTERLOCK_OK);
        CHECK(interlock_decrypt_block(&ctx,cipher,sizeof cipher,cipher,sizeof cipher) == INTERLOCK_OK);
        memcpy(overlap,plain,sizeof plain);
        CHECK(interlock_encrypt_block(&ctx,overlap+8,16,overlap,16) == INTERLOCK_OK);
        CHECK(interlock_decrypt_block(&ctx,overlap,16,overlap+8,16) == INTERLOCK_OK);
        /* Declassify only after all operations under audit, before comparisons. */
        (void)VALGRIND_MAKE_MEM_DEFINED(cipher,sizeof cipher);
        (void)VALGRIND_MAKE_MEM_DEFINED(overlap,sizeof overlap);
        CHECK(memcmp(cipher,expected,16) == 0);
        CHECK(memcmp(overlap,expected,16) == 0);
        interlock_clear(&ctx);
        CHECK(VALGRIND_CHECK_MEM_IS_DEFINED(&ctx,sizeof ctx) == 0);
        const uint8_t *bytes = (const uint8_t *)&ctx;
        for (size_t i = 0; i < sizeof ctx; ++i) CHECK(bytes[i] == 0);
        (void)VALGRIND_MAKE_MEM_DEFINED(key,sizeof key);
        (void)VALGRIND_MAKE_MEM_DEFINED(plain,sizeof plain);
    }
    puts("Secret taint checks passed: key expansion, encrypt/decrypt, overlap, erasure");
    return 0;
}
