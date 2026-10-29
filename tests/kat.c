#include <stdio.h>
#include <string.h>
#include "interlock_internal.h"
#include "shake256.h"
#include "interlock.h"
#include "vectors.h"
#include "bridge.h"

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); return 1; \
} } while (0)

static int primitives(void)
{
    static const uint8_t s[16] = {12,5,6,11,9,0,10,13,3,14,15,8,4,7,1,2};
    uint8_t bytes[9] = {0};
    for (unsigned nibble = 0; nibble < 8; ++nibble) {
        for (unsigned value = 0; value < 16; ++value) {
            uint32_t x = (uint32_t)value << (nibble * 4);
            uint32_t expected = UINT32_C(0xcccccccc);
            expected &= ~(UINT32_C(15) << (nibble * 4));
            expected |= (uint32_t)s[value] << (nibble * 4);
            CHECK(il_sbox(x) == expected);
        }
    }
    for (unsigned n = 0; n < 96; ++n) {
        for (unsigned bit = 0; bit < 32; ++bit) {
            uint32_t x = UINT32_C(1) << bit;
            CHECK(il_rol32(x,n) == (UINT32_C(1) << ((bit+n)%32)));
            CHECK(il_ror32(il_rol32(x,n),n) == x);
        }
    }
    for (unsigned bit = 0; bit < 32; ++bit) {
        uint32_t x = UINT32_C(1) << bit;
        il_store32(bytes+1, x);
        CHECK(il_load32(bytes+1) == x);
        CHECK(bytes[0] == 0 && bytes[5] == 0);
    }
    il_store32(bytes+1, UINT32_C(0x89abcdef));
    CHECK(bytes[1] == 0xef && bytes[2] == 0xcd &&
          bytes[3] == 0xab && bytes[4] == 0x89);
    memset(bytes, 0xff, sizeof bytes);
    il_wipe(bytes, sizeof bytes);
    for (unsigned i = 0; i < sizeof bytes; ++i) CHECK(bytes[i] == 0);
    return 0;
}

static int hex_equal(const uint8_t *actual, const char *hex, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned byte;
        if (sscanf(hex+2*i, "%2x", &byte) != 1 || actual[i] != byte) return 0;
    }
    return 1;
}

static int shake(void)
{
    /* First 512 output bits of the NIST SHAKE256 Msg0 and Msg1600 examples. */
    static const char empty[] =
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
        "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    static const char a3[] =
        "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d"
        "2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b";
    uint8_t input[200], out[64];
    CHECK(il_shake256(out, sizeof out, NULL, 0) == 0);
    CHECK(hex_equal(out, empty, sizeof out));
    memset(input, 0xa3, sizeof input);
    CHECK(il_shake256(out, sizeof out, input, sizeof input) == 0);
    CHECK(hex_equal(out, a3, sizeof out));
    memset(out, 0x5a, sizeof out);
    CHECK(il_shake256(out, sizeof out, NULL, 1) == -1);
    for (unsigned i = 0; i < sizeof out; ++i) CHECK(out[i] == 0x5a);
    CHECK(il_shake256(NULL, 1, input, sizeof input) == -1);
    CHECK(il_shake256(NULL, 0, NULL, 0) == 0);
    return 0;
}

static int schedule(void)
{
    interlock_ctx ctx = {0}, expected = {0};
    uint8_t key[32] = {0};
    for (size_t kind = 0; kind < sizeof kat_vectors/sizeof kat_vectors[0]; ++kind) {
        CHECK(interlock_init(&ctx,kat_vectors[kind].key,32) == INTERLOCK_OK);
        CHECK(memcmp(ctx.round_keys,kat_vectors[kind].keys,sizeof ctx.round_keys) == 0);
    }
    memcpy(key,kat_vectors[3].key,sizeof key);
    expected = ctx;
    memcpy(&ctx,key,sizeof key);
    CHECK(interlock_init(&ctx,(const uint8_t *)&ctx,sizeof key) == INTERLOCK_OK);
    CHECK(memcmp(ctx.round_keys,expected.round_keys,sizeof ctx.round_keys) == 0);
    CHECK(interlock_init(&ctx,key,31) == INTERLOCK_ERR_ARGUMENT);
    for (size_t i = 0; i < sizeof ctx; ++i) CHECK(((const uint8_t *)&ctx)[i] == 0);
    CHECK(interlock_init(&ctx,NULL,32) == INTERLOCK_ERR_ARGUMENT);
    CHECK(interlock_init(&ctx,key,33) == INTERLOCK_ERR_ARGUMENT);
    CHECK(interlock_init(NULL,key,32) == INTERLOCK_ERR_ARGUMENT);
    interlock_clear(&expected);
    interlock_clear(NULL);
    return 0;
}

static uint32_t random_word(uint32_t *s)
{
    *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
    return *s;
}

static int blocks(void)
{
    interlock_ctx ctx = {0};
    uint8_t key[32], in[16], out[32], recovered[16];
    for (size_t kind = 0; kind < sizeof kat_vectors/sizeof kat_vectors[0]; ++kind) {
        memcpy(key,kat_vectors[kind].key,32);
        memcpy(in,kat_vectors[kind].plaintext,16);
        CHECK(interlock_init(&ctx,key,sizeof key) == 0);
        uint32_t state[4];
        for (unsigned j = 0; j < 4; ++j) state[j] = il_load32(in+4*j);
        for (unsigned r = 0; r < 28; ++r) {
            il_round(state,ctx.round_keys[r]);
            CHECK(memcmp(state,kat_vectors[kind].states[r+1],sizeof state) == 0);
        }
        for (unsigned r = 28; r-- > 0;) {
            il_inverse_round(state,ctx.round_keys[r]);
            CHECK(memcmp(state,kat_vectors[kind].states[r],sizeof state) == 0);
        }
        for (unsigned j = 0; j < 4; ++j) CHECK(state[j] == il_load32(in+4*j));
        memset(out,0xa5,sizeof out);
        CHECK(interlock_encrypt_block(&ctx,out,sizeof out,in,sizeof in) == 0);
        CHECK(memcmp(out,kat_vectors[kind].ciphertext,16) == 0);
        for (unsigned i = 16; i < sizeof out; ++i) CHECK(out[i] == 0xa5);
        CHECK(interlock_decrypt_block(&ctx,recovered,sizeof recovered,kat_vectors[kind].ciphertext,16) == 0);
        CHECK(memcmp(recovered,in,sizeof in) == 0);
    }
    uint32_t seed = UINT32_C(0x494c434b);
    for (unsigned sample = 0; sample < 4096+384; ++sample) {
        if (sample < 384) {
            memset(key,0,sizeof key); memset(in,0,sizeof in);
            if (sample < 256) key[sample/8] = (uint8_t)(1U << (sample%8));
            else in[(sample-256)/8] = (uint8_t)(1U << ((sample-256)%8));
        } else {
            for (unsigned i = 0; i < sizeof key; ++i) key[i] = (uint8_t)random_word(&seed);
            for (unsigned i = 0; i < sizeof in; ++i) in[i] = (uint8_t)random_word(&seed);
        }
        CHECK(interlock_init(&ctx,key,sizeof key) == 0);
        CHECK(interlock_encrypt_block(&ctx,out,sizeof out,in,sizeof in) == 0);
        CHECK(interlock_decrypt_block(&ctx,recovered,sizeof recovered,out,16) == 0);
        CHECK(memcmp(recovered,in,sizeof in) == 0);
    }
    interlock_clear(&ctx);
    return 0;
}

static int buffer_contract(void)
{
    typedef int (*operation)(const interlock_ctx *,uint8_t *,size_t,const uint8_t *,size_t);
    operation ops[2] = {interlock_encrypt_block,interlock_decrypt_block};
    interlock_ctx ctx = {0}, snapshot;
    uint8_t key[32] = {0}, input[16] = {0}, expected[16];
    uint8_t buf[64], before[64];
    const size_t bad_lengths[] = {0,15,17,SIZE_MAX};
    CHECK(interlock_init(&ctx,key,sizeof key) == 0);
    snapshot = ctx;
    for (unsigned op = 0; op < 2; ++op) {
        CHECK(ops[op](&ctx,expected,16,input,16) == 0);
        for (int delta = -15; delta <= 15; ++delta) {
            memset(buf,0xa5,sizeof buf); memcpy(buf+24,input,16);
            memcpy(before,buf,sizeof buf);
            uint8_t *dest = buf+24+delta;
            CHECK(ops[op](&ctx,dest,16,buf+24,16) == 0);
            CHECK(memcmp(dest,expected,16) == 0);
            for (size_t i = 0; i < sizeof buf; ++i)
                if (buf+i < dest || buf+i >= dest+16) CHECK(buf[i] == before[i]);
        }
        memset(buf,0xa5,sizeof buf); memcpy(before,buf,sizeof buf);
        for (unsigned i = 0; i < sizeof bad_lengths/sizeof bad_lengths[0]; ++i)
            CHECK(ops[op](&ctx,buf,sizeof buf,input,bad_lengths[i]) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](&ctx,buf,15,input,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](&ctx,buf,0,input,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](NULL,buf,16,input,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](&ctx,NULL,16,input,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](&ctx,buf,16,NULL,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](&ctx,(uint8_t *)&ctx,16,input,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(ops[op](&ctx,((uint8_t *)&ctx)+sizeof ctx-1,16,input,16) == INTERLOCK_ERR_ARGUMENT);
        CHECK(memcmp(&ctx,&snapshot,sizeof ctx) == 0);
        interlock_clear(&ctx);
        CHECK(ops[op](&ctx,buf,16,input,16) == INTERLOCK_ERR_STATE);
        CHECK(memcmp(buf,before,sizeof buf) == 0);
        ctx = snapshot;
    }
    interlock_clear(&ctx); interlock_clear(&snapshot);
    return 0;
}

static int research_bridge(void)
{
    interlock_ctx ctx = {0};
    uint8_t key[32] = {0}, in[64] = {0}, out[64], saved[64];
    CHECK(interlock_init(&ctx,key,32) == 0);
    for (unsigned i = 0; i < sizeof in; ++i) in[i] = (uint8_t)i;
    for (unsigned rounds = 0; rounds <= 28; ++rounds) {
        CHECK(il_test_batch(&ctx,out,in,4,rounds,0) == 0);
        CHECK(il_test_batch(&ctx,out,out,4,rounds,1) == 0);
        CHECK(memcmp(out,in,sizeof in) == 0);
    }
    memset(out,0xa5,sizeof out); memcpy(saved,out,sizeof out);
    CHECK(il_test_batch(&ctx,out,in,SIZE_MAX/16+1,1,0) == -1);
    CHECK(il_test_batch(&ctx,out,in,1,29,0) == -1);
    CHECK(il_test_batch(&ctx,out,in,1,1,2) == -1);
    CHECK(il_test_batch(NULL,out,in,1,1,0) == -1);
    CHECK(il_test_batch(&ctx,NULL,in,1,1,0) == -1);
    CHECK(il_test_batch(&ctx,out,NULL,1,1,0) == -1);
    CHECK(memcmp(out,saved,sizeof out) == 0);
    CHECK(il_test_batch(NULL,NULL,NULL,0,0,0) == 0);
    uint32_t words[4] = {0,1,UINT32_MAX,UINT32_C(0x80000000)}, components[4];
    for (int mixed = 0; mixed < 2; ++mixed) {
        CHECK(il_test_components(components,words,4,17,mixed) == 0);
        for (unsigned i = 0; i < 4; ++i)
            CHECK(components[i] == (mixed ? il_fm(words[i],17) : il_fs(words[i],17)));
    }
    CHECK(il_test_components(components,words,SIZE_MAX/4+1,0,0) == -1);
    CHECK(il_test_components(components,words,4,0,2) == -1);
    CHECK(il_test_components(NULL,words,4,0,0) == -1);
    CHECK(il_test_components(NULL,NULL,0,0,0) == 0);
    uint64_t counts[128];
    CHECK(il_test_diff_counts(counts,in,2,16) == 0);
    for (unsigned bit = 0; bit < 128; ++bit) {
        unsigned expected = 0;
        for (unsigned pair = 0; pair < 2; ++pair)
            expected += (unsigned)(((in[32*pair+bit/8] ^ in[32*pair+16+bit/8]) >> (bit%8)) & 1);
        CHECK(counts[bit] == expected);
    }
    CHECK(il_test_diff_counts(counts,in,SIZE_MAX/32+1,16) == -1);
    CHECK(il_test_diff_counts(counts,NULL,1,16) == -1);
    CHECK(il_test_diff_counts(counts,in,1,0) == -1);
    CHECK(il_test_diff_counts(counts,in,1,17) == -1);
    CHECK(il_test_diff_counts(NULL,in,1,16) == -1);
    CHECK(il_test_diff_counts(counts,NULL,0,16) == 0);
    interlock_clear(&ctx);
    return 0;
}

int main(void)
{
    const uint32_t endian_probe = UINT32_C(0x01020304);
    uint8_t first_byte;
    memcpy(&first_byte,&endian_probe,1);
#ifdef IL_EXPECT_SIZE_T_BITS
    _Static_assert(sizeof(size_t)*CHAR_BIT == IL_EXPECT_SIZE_T_BITS, "wrong cross-target pointer width");
#endif
#ifdef IL_EXPECT_BIG_ENDIAN
    CHECK((first_byte == 1) == IL_EXPECT_BIG_ENDIAN);
#endif
    printf("Execution target: %zu-bit size_t, %s-endian\n",sizeof(size_t)*CHAR_BIT,
           first_byte == 1 ? "big" : "little");
    CHECK(primitives() == 0);
    CHECK(shake() == 0);
    CHECK(schedule() == 0);
    CHECK(blocks() == 0);
    CHECK(buffer_contract() == 0);
    CHECK(research_bridge() == 0);
    puts("C checks passed: primitives, SHAKE/schedule/block KAT, 4480 round trips, buffer contract");
    return 0;
}
