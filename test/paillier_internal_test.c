/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"
#include "internal/nelem.h"
#include "testutil.h"
#include <openssl/conf.h>
#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <time.h>
#include <openssl/paillier.h>
#include "../crypto/paillier/paillier_local.h"
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#define PAILLIER_PUB_FILE_PATH    "paillier-pub.pem"
#define PAILLIER_KEY_FILE_PATH    "paillier-key.pem"

typedef struct paillier_operands_st {
    int32_t x;
    int32_t y;
} paillier_operands_t;

#ifndef OPENSSL_NO_ENGINE
static ENGINE *e;
#endif

static paillier_operands_t test_operands[] = {
    {1111, 0},
    {-1111, 0},
    {1111, 9999},
    {-1111, 9999},
    {1111, -9999},
    {-1111, -9999},
    {0, 9999},
    {0, -9999},
    {9999, 1111},
    {-9999, 1111},
    {9999, -1111},
    {-9999, -1111},
};

typedef enum operation_e {
    ADD,
    ADD_PLAIN,
    SUB,
    MUL
} operation_t;

static char *operation_str[] = {
    "add",
    "add_plain",
    "sub",
    "mul"
};

static size_t paillier_encrypt(PAILLIER_CTX *ctx,
                               unsigned char **out, int32_t plaintext)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    PAILLIER_CIPHERTEXT *r = NULL;

    if (!TEST_ptr(r = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(PAILLIER_encrypt(ctx, r, plaintext)))
        goto err;

    size = PAILLIER_CIPHERTEXT_encode(ctx, NULL, 0, r, 0);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_encode(ctx, buf, size, r, 0)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    PAILLIER_CIPHERTEXT_free(r);
    return ret;
}

static uint32_t paillier_decrypt(PAILLIER_CTX *ctx,
                                 unsigned char *in, size_t size)
{
    int32_t r = 0;
    PAILLIER_CIPHERTEXT *c = NULL;

    if (!TEST_ptr(c = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c, in, size)))
        goto err;

    if (!TEST_true(PAILLIER_decrypt(ctx, &r, c)))
        goto err;

err:
    PAILLIER_CIPHERTEXT_free(c);
    return r;
}

static size_t paillier_add(PAILLIER_CTX *ctx, unsigned char **out,
                           unsigned char *in1, size_t in1_size,
                           unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (!TEST_ptr(r = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c1 = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c2 = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c1, in1, in1_size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c2, in2, in2_size)))
        goto err;

    if (!TEST_true(PAILLIER_add(ctx, r, c1, c2)))
        goto err;

    size = PAILLIER_CIPHERTEXT_encode(ctx, NULL, 0, r, 0);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_encode(ctx, buf, size, r, 0)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    PAILLIER_CIPHERTEXT_free(c1);
    PAILLIER_CIPHERTEXT_free(c2);
    PAILLIER_CIPHERTEXT_free(r);
    return ret;
}

static size_t paillier_add_plain(PAILLIER_CTX *ctx, unsigned char **out,
                                 unsigned char *in, size_t in_size, uint32_t m)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c = NULL;

    if (!TEST_ptr(r = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c, in, in_size)))
        goto err;

    if (!TEST_true(PAILLIER_add_plain(ctx, r, c, m)))
        goto err;

    size = PAILLIER_CIPHERTEXT_encode(ctx, NULL, 0, r, 0);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_encode(ctx, buf, size, r, 0)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    PAILLIER_CIPHERTEXT_free(c);
    PAILLIER_CIPHERTEXT_free(r);
    return ret;
}

static size_t paillier_sub(PAILLIER_CTX *ctx, unsigned char **out,
                           unsigned char *in1, size_t in1_size,
                           unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (!TEST_ptr(r = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c1 = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c2 = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c1, in1, in1_size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c2, in2, in2_size)))
        goto err;

    if (!TEST_true(PAILLIER_sub(ctx, r, c1, c2)))
        goto err;

    size = PAILLIER_CIPHERTEXT_encode(ctx, NULL, 0, r, 0);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_encode(ctx, buf, size, r, 0)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    PAILLIER_CIPHERTEXT_free(c1);
    PAILLIER_CIPHERTEXT_free(c2);
    PAILLIER_CIPHERTEXT_free(r);
    return ret;
}

static size_t paillier_mul(PAILLIER_CTX *ctx, unsigned char **out,
                           unsigned char *in, size_t in_size, uint32_t m)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c = NULL;

    if (!TEST_ptr(r = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c = PAILLIER_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_decode(ctx, c, in, in_size)))
        goto err;

    if (!TEST_true(PAILLIER_mul(ctx, r, c, m)))
        goto err;

    size = PAILLIER_CIPHERTEXT_encode(ctx, NULL, 0, r, 0);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(PAILLIER_CIPHERTEXT_encode(ctx, buf, size, r, 0)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    PAILLIER_CIPHERTEXT_free(c);
    PAILLIER_CIPHERTEXT_free(r);
    return ret;
}

static int paillier_test(operation_t op, ENGINE *engine)
{
    int ret = 0, i;
    BIO *bio = NULL;
    PAILLIER_KEY *pail_key = NULL, *pail_pub_key = NULL, *pail_pri_key = NULL;
    int32_t x, y, r;
    unsigned char *er = NULL, *ex = NULL, *ey = NULL;
    size_t sr, sx, sy;
    PAILLIER_CTX *ectx = NULL, *dctx = NULL;

    TEST_info("Testing %s of paillier\n", operation_str[op]);

    if (!TEST_ptr(pail_key = PAILLIER_KEY_new()))
        goto err;

    if (!TEST_true(PAILLIER_KEY_generate_key(pail_key, 255)))
        goto err;

    /*
     * saving paillier public key to pem file for this test
     */
    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_write_filename(bio, PAILLIER_PUB_FILE_PATH))
        || !TEST_true(PEM_write_bio_PAILLIER_PublicKey(bio, pail_key)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_read_filename(bio, PAILLIER_PUB_FILE_PATH))
        || !TEST_ptr(pail_pub_key = PEM_read_bio_PAILLIER_PublicKey(bio, NULL,
                                                                    NULL, NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(ectx = PAILLIER_CTX_new(pail_pub_key, PAILLIER_MAX_THRESHOLD)))
        goto err;

    /*
     * saving paillier private key to pem file for this test
     */
    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_write_filename(bio, PAILLIER_KEY_FILE_PATH))
        || !TEST_true(PEM_write_bio_PAILLIER_PrivateKey(bio, pail_key)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_read_filename(bio, PAILLIER_KEY_FILE_PATH))
        || !TEST_true(pail_pri_key = PEM_read_bio_PAILLIER_PrivateKey(bio, NULL,
                                                                      NULL, NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(dctx = PAILLIER_CTX_new(pail_pri_key, PAILLIER_MAX_THRESHOLD)))
        goto err;

#ifndef OPENSSL_NO_ENGINE
    if (engine != NULL &&
        !TEST_true(PAILLIER_CTX_set_engine(ectx, engine)) &&
        !TEST_true(PAILLIER_CTX_set_engine(dctx, engine)))
        goto err;
#endif

    for (i = 0; i < (int)(sizeof(test_operands)/sizeof(test_operands[0])); i++) {
        x = test_operands[i].x;
        y = test_operands[i].y;

        sx = paillier_encrypt(ectx, &ex, x);
        if (!TEST_ptr(ex))
            goto err;

        r = paillier_decrypt(dctx, ex, sx);
        if (!TEST_int_eq(r, x))
            goto err;

        sy = paillier_encrypt(ectx, &ey, y);
        if (!TEST_ptr(ey))
            goto err;

        if (op == ADD) {
            sr = paillier_add(ectx, &er, ex, sx, ey, sy);
            if (!TEST_ptr(er))
                goto err;
        } else if (op == ADD_PLAIN) {
            sr = paillier_add_plain(ectx, &er, ex, sx, y);
            if (!TEST_ptr(er))
                goto err;
        } else if (op == SUB) {
            sr = paillier_sub(ectx, &er, ex, sx, ey, sy);
            if (!TEST_ptr(er))
                goto err;
        } else if (op == MUL) {
            sr = paillier_mul(ectx, &er, ex, sx, y);
            if (!TEST_ptr(er))
                goto err;
        } else {
            goto err;
        }

        r = paillier_decrypt(dctx, er, sr);

        if (op == ADD) {
            if (!TEST_int_eq(r, x + y))
                goto err;
        } else if (op == ADD_PLAIN) {
            if (!TEST_int_eq(r, x + y))
                goto err;
        } else if (op == SUB) {
            if (!TEST_int_eq(r, x - y))
                goto err;
        } else if (op == MUL) {
            if (!TEST_int_eq(r, x * y))
                goto err;
        }

        OPENSSL_free(ex);
        OPENSSL_free(ey);
        OPENSSL_free(er);
        ex = ey = er = NULL;
    }

    ret = 1;

err:
    OPENSSL_free(ex);
    OPENSSL_free(ey);
    OPENSSL_free(er);
    PAILLIER_KEY_free(pail_key);
    PAILLIER_KEY_free(pail_pub_key);
    PAILLIER_KEY_free(pail_pri_key);

    PAILLIER_CTX_free(ectx);
    PAILLIER_CTX_free(dctx);

    return ret;
}

static int paillier_tests(void)
{
    if (!TEST_true(paillier_test(ADD, NULL))
        || !TEST_true(paillier_test(ADD_PLAIN, NULL))
        || !TEST_true(paillier_test(SUB, NULL))
        || !TEST_true(paillier_test(MUL, NULL)))
        return 0;

#if !defined(OPENSSL_NO_ENGINE) && !defined(OPENSSL_NO_BN_METHOD)
    if ((e = ENGINE_by_id("bnsoft")) == NULL) {
        TEST_info("Can't load bnsoft engine");
        return 0;
    }

    if (!TEST_true(paillier_test(ADD, e))
        || !TEST_true(paillier_test(ADD_PLAIN, e))
        || !TEST_true(paillier_test(SUB, e))
        || !TEST_true(paillier_test(MUL, e)))
        return 0;
#endif

    return 1;
}

int setup_tests(void)
{
    OPENSSL_load_builtin_modules();
    ENGINE_load_builtin_engines();
    ADD_TEST(paillier_tests);
    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_ENGINE
    ENGINE_free(e);
#endif
}
