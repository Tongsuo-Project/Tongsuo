/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Make each allocation of creating a KDF context fail in turn: creating the
 * context must then fail cleanly.  CRYPTO_set_mem_functions() only works
 * before the first allocation, so this test has its own main() instead of
 * the one of the test framework.
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include "internal/nelem.h"

static int fail_at;             /* the allocation to fail, 0 for none */
static int alloc_count;         /* allocations made since fail_at was set */
static int alloc_failed;

static int should_fail(void)
{
    if (fail_at == 0 || ++alloc_count != fail_at)
        return 0;
    alloc_failed = 1;
    return 1;
}

static void *test_malloc(size_t num, const char *file, int line)
{
    return should_fail() ? NULL : malloc(num);
}

static void *test_realloc(void *addr, size_t num, const char *file, int line)
{
    return should_fail() ? NULL : realloc(addr, num);
}

static void test_free(void *addr, const char *file, int line)
{
    free(addr);
}

static const struct {
    const char *name;
    int pkey;                   /* create it with EVP_PKEY_CTX_new_id() */
    int id;
} kdfs[] = {
    { "PBKDF2", 0, EVP_KDF_PBKDF2 },
#ifndef OPENSSL_NO_SCRYPT
    { "SCRYPT", 0, EVP_KDF_SCRYPT },
    { "EVP_PKEY_SCRYPT", 1, EVP_PKEY_SCRYPT },
#endif
    { "TLS1-PRF", 0, EVP_KDF_TLS1_PRF },
    { "EVP_PKEY_TLS1_PRF", 1, EVP_PKEY_TLS1_PRF },
    { "HKDF", 0, EVP_KDF_HKDF },
    { "EVP_PKEY_HKDF", 1, EVP_PKEY_HKDF },
    { "SSHKDF", 0, EVP_KDF_SSHKDF },
    { "KBKDF", 0, EVP_KDF_KB },
    { "KRB5KDF", 0, EVP_KDF_KRB5KDF },
    { "SSKDF", 0, EVP_KDF_SS }
};

/* Create and free a context for kdfs[i] with allocation n failing */
static int create_context(size_t i, int n)
{
    void *ctx;

    alloc_count = 0;
    alloc_failed = 0;
    fail_at = n;
    if (kdfs[i].pkey) {
        ctx = EVP_PKEY_CTX_new_id(kdfs[i].id, NULL);
        fail_at = 0;
        EVP_PKEY_CTX_free(ctx);
    } else {
        ctx = EVP_KDF_CTX_new_id(kdfs[i].id);
        fail_at = 0;
        EVP_KDF_CTX_free(ctx);
    }
    ERR_clear_error();
    return ctx != NULL;
}

static int test_kdf(size_t i)
{
    int n;

    if (!create_context(i, 0))
        return 0;
    for (n = 1; n < 100; n++) {
        int created = create_context(i, n);

        if (!alloc_failed)
            return created;     /* n is past the last allocation */
        if (created)
            return 0;
    }
    return 0;
}

int main(void)
{
    size_t i;
    int ret = EXIT_SUCCESS;

    if (!CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free)) {
        fprintf(stderr, "Cannot replace the memory functions\n");
        return EXIT_FAILURE;
    }
    /* Allocate the error queue and load the error strings beforehand */
    if (ERR_get_state() == NULL)
        return EXIT_FAILURE;

    for (i = 0; i < OSSL_NELEM(kdfs); i++) {
        if (!test_kdf(i)) {
            fprintf(stderr, "FAIL: %s\n", kdfs[i].name);
            ret = EXIT_FAILURE;
        }
    }
    if (ret == EXIT_SUCCESS)
        printf("PASS\n");
    return ret;
}
