/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0 (the "License").
 * You may obtain a copy at https://www.openssl.org/source/license.html
 *
 * Isolated process: install memory hooks before OpenSSL initialization and
 * compile sign.c here so digest failures do not require production hooks.
 */
/* Fixed test-only allocation tag, including in no-filenames builds. */
#define OPENSSL_FILE "sm4th/fault-sign"
#define OPENSSL_LINE 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

static unsigned digest_call, fail_digest;

static int fault_digest_init(EVP_MD_CTX *ctx, const EVP_MD *md,
                             const OSSL_PARAM params[])
{
    if (++digest_call == fail_digest)
        return 0;
    return EVP_DigestInit_ex2(ctx, md, params);
}

static int fault_digest_update(EVP_MD_CTX *ctx, const void *data, size_t len)
{
    if (++digest_call == fail_digest)
        return 0;
    return EVP_DigestUpdate(ctx, data, len);
}

static int fault_digest_squeeze(EVP_MD_CTX *ctx, unsigned char *out, size_t len)
{
    if (++digest_call == fail_digest)
        return 0;
    return EVP_DigestSqueeze(ctx, out, len);
}

#define EVP_DigestInit_ex2 fault_digest_init
#define EVP_DigestUpdate fault_digest_update
#define EVP_DigestSqueeze fault_digest_squeeze
#include "../crypto/sm4th/sign.c"
#undef EVP_DigestInit_ex2
#undef EVP_DigestUpdate
#undef EVP_DigestSqueeze

typedef struct {
    void *ptr;
    size_t len;
    int secret;
} allocation;

static allocation live[128];
static int tracking, memory_error;
static unsigned alloc_call, fail_alloc, cleared;
static size_t tree_bytes, decomposition_bytes;

static int from_sm4th(const char *file)
{
    return file != NULL && (strstr(file, "sm4th/") != NULL
                            || strstr(file, "sm4th\\") != NULL);
}

static void *fault_malloc(size_t len, const char *file, int line)
{
    void *ptr;
    unsigned i;

    (void)line;
    if (tracking && from_sm4th(file) && ++alloc_call == fail_alloc)
        return NULL;
    ptr = malloc(len);
    if (ptr == NULL || !tracking || !from_sm4th(file))
        return ptr;
    for (i = 0; i < sizeof(live) / sizeof(live[0]); i++) {
        if (live[i].ptr == NULL) {
            live[i].ptr = ptr;
            live[i].len = len;
            live[i].secret = len == HATLB || len == (size_t)LAM * HATLB
                || len == (size_t)(4096 + 12) * HATLB
                || len == tree_bytes || len == 2 * tree_bytes
                || len == (size_t)LAM * UHASH_OUT || len == decomposition_bytes
                || len == CHALL1_LEN + UHASH_OUT + (size_t)LAM * UHASH_OUT
                          + SM4TH_ELL_BYTES;
            /* Also detect missing wipes on partially initialized buffers. */
            memset(ptr, 0xa5, len);
            return ptr;
        }
    }
    memory_error = 1;
    return ptr;
}

static void fault_free(void *ptr, const char *file, int line)
{
    unsigned i;

    (void)file;
    (void)line;
    if (ptr == NULL)
        return;
    for (i = 0; i < sizeof(live) / sizeof(live[0]); i++) {
        if (live[i].ptr == ptr) {
            if (live[i].secret) {
                size_t j;
                for (j = 0; j < live[i].len; j++) {
                    if (((unsigned char *)ptr)[j] != 0) {
                        memory_error = 1;
                        break;
                    }
                }
                cleared++;
            }
            live[i].ptr = NULL;
            break;
        }
    }
    free(ptr);
}

static void *fault_realloc(void *ptr, size_t len, const char *file, int line)
{
    unsigned i;

    (void)file;
    (void)line;
    /* SM4th uses fixed allocations. Catch an unexpected tracked realloc. */
    for (i = 0; i < sizeof(live) / sizeof(live[0]); i++) {
        if (ptr != NULL && live[i].ptr == ptr)
            memory_error = 1;
    }
    return realloc(ptr, len);
}

static int memory_clean(void)
{
    unsigned i;
    for (i = 0; i < sizeof(live) / sizeof(live[0]); i++) {
        if (live[i].ptr != NULL)
            return 0;
    }
    return !memory_error;
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "SM4th fault test failed at line %d (digest=%u, alloc=%u)\n", \
                __LINE__, fail_digest, fail_alloc); \
        goto end; \
    } \
} while (0)

int main(void)
{
    static const unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    static const unsigned char msg[] = "fault injection";
    unsigned char sk[32], pk[32], rho[32] = {0};
    unsigned char sig[6724], rejected[6724];
    const sm4th_params_t *p;
    EVP_MD *md = NULL;
    unsigned i, j;
    int ok = 0;

    CHECK(CRYPTO_set_mem_functions(fault_malloc, fault_realloc, fault_free));
    p = sm4th_params_get(1); /* f: exercise all 16 context slots */
    CHECK(p != NULL);
    md = EVP_MD_fetch(NULL, "SHAKE-128", NULL);
    CHECK(md != NULL);
    memcpy(sk, key, 16);
    memcpy(sk + 16, key, 16);
    memcpy(pk, key, 16);
    sm4_enc(key, key, pk + 16);
    decomposition_bytes = p->ldecom;
    tree_bytes = (size_t)(2 * p->leaves - 1) * SM4TH_NB;
    tracking = 1;
    CHECK(sm4th_core_sign(p, md, msg, sizeof(msg) - 1, sk, rho, sig) == 0);
    CHECK(memory_clean());
    CHECK(sm4th_core_verify(p, md, msg, sizeof(msg) - 1,
                            pk, sizeof(pk), sig, p->sig_len) == 1);
    CHECK(memory_clean());

    /* H4 init, profile domain, pk, message, purpose byte, squeeze: fail shut. */
    for (i = 1; i <= 6; i++) {
        fail_digest = i;
        digest_call = 0;
        memset(rejected, 0xa5, sizeof(rejected));
        CHECK(sm4th_core_sign(p, md, msg, sizeof(msg) - 1,
                              sk, rho, rejected) == -1);
        CHECK(digest_call == i && memory_clean());
        for (j = 0; j < sizeof(rejected); j++)
            CHECK(rejected[j] == 0xa5);
        digest_call = 0;
        CHECK(sm4th_core_verify(p, md, msg, sizeof(msg) - 1,
                                pk, sizeof(pk), sig, p->sig_len) == 0);
        CHECK(digest_call == i && memory_clean());
    }
    fail_digest = 0;

    /* Each SM4th allocation through the first BAVC.Open must fail shut.
     * Includes partial context/tree setup and post-VOLE transcript buffers.
     */
    for (i = 1; i <= p->tau + 13; i++) {
        fail_alloc = i;
        alloc_call = 0;
        CHECK(sm4th_core_sign(p, md, msg, sizeof(msg) - 1,
                              sk, rho, rejected) == -1);
        CHECK(alloc_call >= i && memory_clean());
    }
    fail_alloc = 0;
    sk[16] = 0; /* raw core API must enforce the same key-space restriction */
    CHECK(sm4th_core_sign(p, md, msg, sizeof(msg) - 1,
                          sk, rho, rejected) == -1);
    CHECK(memory_clean() && cleared != 0);
    printf("PASS: 12 digest failures, %u allocation failures, "
           "%u wiped buffers, invalid raw key rejected\n", p->tau + 13, cleared);
    ok = 1;
end:
    tracking = 0;
    EVP_MD_free(md);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
