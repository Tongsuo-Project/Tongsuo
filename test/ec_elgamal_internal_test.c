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
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <time.h>
#include "../crypto/ec/ec_elgamal.h"

#define EC_PUB_FILE_PATH    "ec-pub.pem"
#define EC_KEY_FILE_PATH    "ec-key.pem"

typedef struct ec_elgamal_operands_st {
    int32_t x;
    int32_t y;
} ec_elgamal_operands_t;

static ec_elgamal_operands_t test_operands[] = {
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
    SUB,
    MUL
} operation_t;

static char *operation_str[] = {
    "add",
    "sub",
    "mul"
};

static char *algo_str[] = {
    "default",
    "twisted",
};

static size_t ec_elgamal_encrypt(EC_ELGAMAL_CTX *ctx,
                                 unsigned char **out, int32_t plaintext)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_encrypt(ctx, r, plaintext)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, r, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static uint32_t ec_elgamal_decrypt(EC_ELGAMAL_CTX *ctx,
                                   unsigned char *in, size_t size)
{
    int32_t r = 0;
    EC_ELGAMAL_CIPHERTEXT *c = NULL;

    if (!TEST_ptr(c = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, in, size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_decrypt(ctx, &r, c)))
        goto err;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c);
    return r;
}

static size_t ec_elgamal_add(EC_ELGAMAL_CTX *ctx, unsigned char **out,
                             unsigned char *in1, size_t in1_size,
                             unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, in1, in1_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c2, in2, in2_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_add(ctx, r, c1, c2)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, r, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static size_t ec_elgamal_sub(EC_ELGAMAL_CTX *ctx, unsigned char **out,
                             unsigned char *in1, size_t in1_size,
                             unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, in1, in1_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c2, in2, in2_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_sub(ctx, r, c1, c2)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, r, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static size_t ec_elgamal_mul(EC_ELGAMAL_CTX *ctx, unsigned char **out,
                             unsigned char *in, size_t in_size, uint32_t m)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c = NULL;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, in, in_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_mul(ctx, r, c, m)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, r, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_ELGAMAL_CIPHERTEXT_free(c);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    return ret;
}

static int ec_elgamal_test(int curve_id, operation_t op, int flag)
{
    int ret = 0, i;
    BIO *bio = NULL;
    EC_KEY *eckey = NULL, *ec_pub_key = NULL, *ec_pri_key = NULL;
    int32_t x, y, r;
    unsigned char *er = NULL, *ex = NULL, *ey = NULL;
    size_t sr, sx, sy;
    EC_ELGAMAL_CTX *ectx = NULL, *dctx = NULL;
    EC_ELGAMAL_DECRYPT_TABLE *dtable = NULL;

    TEST_info("Testing encrypt/descrypt of EC-ElGamal for curve_id: %d, "
              "operation: %s, flag: %s\n", curve_id, operation_str[op],
              algo_str[flag]);

    if (!TEST_ptr(eckey = EC_KEY_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_true(EC_KEY_generate_key(eckey)))
        goto err;

    /*
     * saving ec public key to pem file for this test
     */
    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_write_filename(bio, EC_PUB_FILE_PATH))
        || !TEST_true(PEM_write_bio_EC_PUBKEY(bio, eckey)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_read_filename(bio, EC_PUB_FILE_PATH))
        || !TEST_ptr(ec_pub_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL,
                                                         NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(ectx = EC_ELGAMAL_CTX_new(ec_pub_key, flag)))
        goto err;

    /*
     * saving ec secret key to pem file for this test
     */
    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_write_filename(bio, EC_KEY_FILE_PATH))
        || !TEST_true(PEM_write_bio_ECPrivateKey(bio, eckey, NULL, NULL, 0,
                                                 NULL, NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(bio = BIO_new(BIO_s_file()))
        || !TEST_true(BIO_read_filename(bio, EC_KEY_FILE_PATH))
        || !TEST_true(ec_pri_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL,
                                                             NULL)))
        goto err;
    BIO_free(bio);

    if (!TEST_ptr(dctx = EC_ELGAMAL_CTX_new(ec_pri_key, flag)))
        goto err;

    if (!TEST_ptr(dtable = EC_ELGAMAL_DECRYPT_TABLE_new(dctx, 1)))
        goto err;

    EC_ELGAMAL_CTX_set_decrypt_table(dctx, dtable);

    for (i = 0; i < (int)(sizeof(test_operands)/sizeof(test_operands[0])); i++) {
        x = test_operands[i].x;
        y = test_operands[i].y;

        sx = ec_elgamal_encrypt(dctx, &ex, x);
        if (!TEST_ptr(ex))
            goto err;

        r = ec_elgamal_decrypt(dctx, ex, sx);
        if (!TEST_int_eq(r, x))
            goto err;

        sy = ec_elgamal_encrypt(ectx, &ey, y);
        if (!TEST_ptr(ey))
            goto err;

        r = ec_elgamal_decrypt(dctx, ey, sy);
        if (!TEST_int_eq(r, y))
            goto err;

        if (op == ADD) {
            sr = ec_elgamal_add(ectx, &er, ex, sx, ey, sy);
            if (!TEST_ptr(er))
                goto err;
        } else if (op == SUB) {
            sr = ec_elgamal_sub(ectx, &er, ex, sx, ey, sy);
            if (!TEST_ptr(er))
                goto err;
        } else if (op == MUL) {
            sr = ec_elgamal_mul(ectx, &er, ex, sx, y);
            if (!TEST_ptr(er))
                goto err;
        } else {
            goto err;
        }

        r = ec_elgamal_decrypt(dctx, er, sr);

        if (op == ADD) {
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
    EC_ELGAMAL_DECRYPT_TABLE_free(dtable);

    OPENSSL_free(ex);
    OPENSSL_free(ey);
    OPENSSL_free(er);
    EC_KEY_free(eckey);
    EC_KEY_free(ec_pub_key);
    EC_KEY_free(ec_pri_key);

    EC_ELGAMAL_CTX_free(ectx);
    EC_ELGAMAL_CTX_free(dctx);

    return ret;
}

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
static int ec_point_from_string_test(int curve_id, const char *str)
{
    int ret = 0;
    EC_KEY *key = NULL;
    EC_POINT *r = NULL;

    if (!TEST_ptr(key = EC_KEY_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_true(EC_KEY_generate_key(key)))
        goto err;

    if (!TEST_ptr(r = EC_POINT_new(key->group)))
        goto err;

    if (!TEST_true(EC_POINT_from_string(key->group, r, (const unsigned char *)str, strlen(str))))
        goto err;

    ret = 1;
err:
    EC_POINT_free(r);
    EC_KEY_free(key);
    return ret;
}
#endif

static int ec_elgamal_tests(void)
{
    if (!TEST_true(ec_elgamal_test(NID_X9_62_prime256v1, ADD, 0))
        || !TEST_true(ec_elgamal_test(NID_X9_62_prime256v1, SUB, 0))
        || !TEST_true(ec_elgamal_test(NID_X9_62_prime256v1, MUL, 0))
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
        || !TEST_true(ec_elgamal_test(NID_X9_62_prime256v1, ADD, EC_ELGAMAL_FLAG_TWISTED))
        || !TEST_true(ec_elgamal_test(NID_X9_62_prime256v1, SUB, EC_ELGAMAL_FLAG_TWISTED))
        || !TEST_true(ec_elgamal_test(NID_X9_62_prime256v1, MUL, EC_ELGAMAL_FLAG_TWISTED))
#endif
        )
        return 0;

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (!TEST_true(ec_point_from_string_test(NID_X9_62_prime256v1, "tongsuov587!"))
        || !TEST_true(ec_point_from_string_test(NID_X9_62_prime256v1, "tongsuo+++++===="))
# ifndef OPENSSL_NO_SM2
        || !TEST_true(ec_point_from_string_test(NID_sm2, "tongsuov587!"))
        || !TEST_true(ec_point_from_string_test(NID_sm2, "tongsuo+++++===="))
# endif
        )
        return 0;
#endif

#ifndef OPENSSL_NO_SM2
    if (!TEST_true(ec_elgamal_test(NID_sm2, ADD, 0))
        || !TEST_true(ec_elgamal_test(NID_sm2, SUB, 0))
        || !TEST_true(ec_elgamal_test(NID_sm2, MUL, 0))
# ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
        || !TEST_true(ec_elgamal_test(NID_sm2, ADD, EC_ELGAMAL_FLAG_TWISTED))
        || !TEST_true(ec_elgamal_test(NID_sm2, SUB, EC_ELGAMAL_FLAG_TWISTED))
        || !TEST_true(ec_elgamal_test(NID_sm2, MUL, EC_ELGAMAL_FLAG_TWISTED))
# endif
        )
        return 0;
#endif

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(ec_elgamal_tests);
    return 1;
}

void cleanup_tests(void)
{
}
