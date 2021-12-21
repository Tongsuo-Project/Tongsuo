/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include "internal/nelem.h"
#include "testutil.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/objects.h>
#include <time.h>
#include "../crypto/ec/ec_elgamal.h"

#define EC_PUB_FILE_PATH    "ec-pub.pem"
#define EC_KEY_FILE_PATH    "ec-key.pem"

static size_t ec_elgamal_encrypt(const char *cert_file,
                                 unsigned char **out, uint32_t plaintext)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_KEY *eckey = NULL;
    EC_ELGAMAL_CTX *ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL;
    FILE *f = fopen(cert_file, "rb");
    if (!TEST_ptr(eckey = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(ctx = EC_ELGAMAL_CTX_new(eckey, 0)))
        goto err;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_encrypt(ctx, r, plaintext)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    OPENSSL_free(buf);
    EC_KEY_free(eckey);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    EC_ELGAMAL_CTX_free(ctx);
    fclose(f);
    return ret;
}

static uint32_t ec_elgamal_decrypt(const char *key_file,
                                   unsigned char *in, size_t size)
{
    uint32_t r = 0;
    EC_KEY *eckey = NULL;
    EC_ELGAMAL_CTX *ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *c = NULL;
    FILE *f = fopen(key_file, "rb");

    if (!TEST_ptr(eckey = PEM_read_ECPrivateKey(f, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(ctx = EC_ELGAMAL_CTX_new(eckey, EC_ELGAMAL_BSGS_HASH_TABLE_DEFAULT_SIZE)))
        goto err;

    if (!TEST_ptr(c = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, in, size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_decrypt(ctx, &r, c)))
        goto err;

err:
    EC_KEY_free(eckey);
    EC_ELGAMAL_CIPHERTEXT_free(c);
    EC_ELGAMAL_CTX_free(ctx);
    fclose(f);
    return r;
}

static size_t ec_elgamal_add(const char *cert_file, unsigned char **out,
                             unsigned char *in1, size_t in1_size,
                             unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_KEY *eckey = NULL;
    EC_ELGAMAL_CTX *ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;
    FILE *f = fopen(cert_file, "rb");

    if (!TEST_ptr(eckey = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(ctx = EC_ELGAMAL_CTX_new(eckey, 0)))
        goto err;

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

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_KEY_free(eckey);
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    EC_ELGAMAL_CTX_free(ctx);
    fclose(f);
    return ret;
}

static size_t ec_elgamal_sub(const char *cert_file, unsigned char **out,
                             unsigned char *in1, size_t in1_size,
                             unsigned char *in2, size_t in2_size)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_KEY *eckey = NULL;
    EC_ELGAMAL_CTX *ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;
    FILE *f = fopen(cert_file, "rb");

    if (!TEST_ptr(eckey = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(ctx = EC_ELGAMAL_CTX_new(eckey, 0)))
        goto err;

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

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_KEY_free(eckey);
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    EC_ELGAMAL_CTX_free(ctx);
    fclose(f);
    return ret;
}

static size_t ec_elgamal_mul(const char *cert_file, unsigned char **out,
                             unsigned char *in, size_t in_size, uint32_t m)
{
    size_t size, ret = 0;
    unsigned char *buf = NULL;
    EC_KEY *eckey = NULL;
    EC_ELGAMAL_CTX *ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c = NULL;
    FILE *f = fopen(cert_file, "rb");

    if (!TEST_ptr(eckey = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL)))
        goto err;

    if (!TEST_ptr(ctx = EC_ELGAMAL_CTX_new(eckey, 0)))
        goto err;

    if (!TEST_ptr(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_ptr(c = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, in, in_size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_mul(ctx, r, c, m)))
        goto err;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, NULL, 1);
    if (!TEST_ptr(buf = OPENSSL_zalloc(size)))
        goto err;

    if (!TEST_true(EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, r, 1)))
        goto err;

    *out = buf;
    buf = NULL;
    ret = size;

err:
    EC_KEY_free(eckey);
    EC_ELGAMAL_CIPHERTEXT_free(c);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    EC_ELGAMAL_CTX_free(ctx);
    fclose(f);
    return ret;
}

static int ec_elgamal_test(int curve_id)
{
    TEST_info("Testing encrypt/descrypt of EC-ElGamal for curve_id: %d\n", curve_id);

    int ret = 0;
    FILE *f;
    EC_KEY *eckey;
    uint32_t p1 = 2000000021, p2 = 500, m = 800, r;
    unsigned char *buf = NULL, *buf1 = NULL, *buf2 = NULL;
    size_t size, size1, size2;

    if (!TEST_ptr(eckey = EC_KEY_new_by_curve_name(curve_id)))
        goto err;

    if (!TEST_true(EC_KEY_generate_key(eckey)))
        goto err;

    /*
     * saving ec public key to pem file for this test
     */
    f = fopen(EC_PUB_FILE_PATH, "w");
    PEM_write_EC_PUBKEY(f, eckey);
    fclose(f);

    /*
     * saving ec secret key to pem file for this test
     */
    f = fopen(EC_KEY_FILE_PATH, "w");
    PEM_write_ECPrivateKey(f, eckey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    size1 = ec_elgamal_encrypt(EC_PUB_FILE_PATH, &buf1, p1);
    if (!TEST_ptr(buf1))
        goto err;

    r = ec_elgamal_decrypt(EC_KEY_FILE_PATH, buf1, size1);
    if (!TEST_uint_eq(r, p1))
        goto err;

    size2 = ec_elgamal_encrypt(EC_PUB_FILE_PATH, &buf2, p2);
    if (!TEST_ptr(buf2))
        goto err;

    size = ec_elgamal_add(EC_PUB_FILE_PATH, &buf, buf1, size1, buf2, size2);
    if (!TEST_ptr(buf))
        goto err;

    r = ec_elgamal_decrypt(EC_KEY_FILE_PATH, buf, size);
    if (!TEST_uint_eq(r, p1 + p2))
        goto err;

    OPENSSL_free(buf);
    size = ec_elgamal_sub(EC_PUB_FILE_PATH, &buf, buf1, size1, buf2, size2);
    if (!TEST_ptr(buf))
        goto err;

    r = ec_elgamal_decrypt(EC_KEY_FILE_PATH, buf, size);
    if (!TEST_uint_eq(r, p1 - p2))
        goto err;

    OPENSSL_free(buf);
    size = ec_elgamal_mul(EC_PUB_FILE_PATH, &buf, buf2, size2, m);
    if (!TEST_ptr(buf))
        goto err;

    r = ec_elgamal_decrypt(EC_KEY_FILE_PATH, buf, size);
    if (!TEST_uint_eq(r, m * p2))
        goto err;

    ret = 1;

err:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    OPENSSL_free(buf);
    EC_KEY_free(eckey);

    return ret;
}

static int ec_elgamal_tests(void)
{
    if (!TEST_true(ec_elgamal_test(NID_X9_62_prime256v1)))
        return 0;

    if (!TEST_true(ec_elgamal_test(NID_sm2)))
        return 0;

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
