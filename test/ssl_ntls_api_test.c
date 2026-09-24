/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include "testutil.h"
#include "internal/ssl_unwrap.h"
#include "internal/nelem.h"
#include "../ssl/ssl_local.h"
#include "helpers/ssltestlib.h"

static const char *sm2_sign_cert_file;
static const char *sm2_sign_key_file;
static const char *sm2_enc_cert_file;
static const char *sm2_enc_key_file;
static const char *rsa_sign_cert_file;
static const char *rsa_sign_key_file;
static const char *rsa_enc_cert_file;
static const char *rsa_enc_key_file;

static const char *cipher_list[] = {
#ifndef OPENSSL_NO_SM4
# ifndef OPENSSL_NO_SM3
#  ifndef OPENSSL_NO_SM2
    NTLS_TXT_SM2DHE_WITH_SM4_SM3,
    NTLS_TXT_SM2_WITH_SM4_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_GCM_SM3,
    NTLS_TXT_ECC_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECC_SM2_SM4_GCM_SM3,
    NTLS_TXT_SM2DHE_WITH_SM4_SM3":"NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3":"NTLS_TXT_ECDHE_SM2_SM4_GCM_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3":"NTLS_TXT_ECC_SM2_SM4_CBC_SM3,
    NTLS_TXT_ECDHE_SM2_SM4_CBC_SM3":"NTLS_TXT_RSA_SM4_CBC_SM3,
#  endif /* OPENSSL_NO_SM2 */
    NTLS_TXT_RSA_SM4_CBC_SM3,
    NTLS_TXT_RSA_SM4_GCM_SM3,
# endif /* OPENSSL_NO_SM3 */
    NTLS_TXT_RSA_SM4_CBC_SHA256,
    NTLS_TXT_RSA_SM4_GCM_SHA256,
#endif /* OPENSSL_NO_SM4 */
    NULL,   /* suppress compile error: zero or negative size array */
};

static int test_ntls_ctx_set_cipher_list(int i)
{
    int           ret = 1;
    SSL_CTX      *ctx = NULL;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_client_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    SSL_CTX_enable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 1))
        goto err;

    if (!TEST_true(SSL_CTX_set_cipher_list(ctx, cipher_list[i]))) {
        goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
    return ret;
}

static int test_ntls_ssl_set_cipher_list(int i)
{
    int           ret = 1;
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_client_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    SSL_CTX_enable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 1))
        goto err;


    ssl = SSL_new(ctx);
    if (!TEST_true(ssl != NULL))
        goto err;

    if (!TEST_true(SSL_CTX_set_cipher_list(ctx, cipher_list[i]))) {
        goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return ret;
}

static int test_ntls_ctx_set_cert_pkey_file_api(int i)
{
    int ret = 1;
    const char *sign_cert_file = NULL;
    const char *sign_key_file = NULL;
    const char *enc_cert_file = NULL;
    const char *enc_key_file = NULL;
    SSL_CTX *ctx = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    SSL_CTX_enable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 1))
        goto err;
    SSL_CTX_disable_ntls(ctx);
    if (!TEST_true(ctx->enable_ntls == 0))
        goto err;

    SSL_CTX_enable_force_ntls(ctx);
    if (!TEST_true(ctx->enable_force_ntls == 1))
        goto err;
    SSL_CTX_disable_force_ntls(ctx);
    if (!TEST_true(ctx->enable_force_ntls == 0))
        goto err;

    if (!TEST_int_eq(SSL_CTX_use_sign_certificate_file(ctx,
                                                       sign_cert_file,
                                                       SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_sign_PrivateKey_file(ctx,
                                                      sign_key_file,
                                                      SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_certificate_file(ctx,
                                                      enc_cert_file,
                                                      SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_PrivateKey_file(ctx,
                                                     enc_key_file,
                                                     SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
    return ret;
}

static int test_ntls_ssl_set_cert_pkey_file_api(int i)
{
    int           ret = 1;
    const char   *sign_cert_file = NULL;
    const char   *sign_key_file = NULL;
    const char   *enc_cert_file = NULL;
    const char   *enc_key_file = NULL;
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;
    SSL_CONNECTION  *sc = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    ssl = SSL_new(ctx);
    if (!TEST_true(ssl != NULL))
        goto err;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    if (!TEST_true(sc != NULL))
        goto err;

    if (!TEST_true(SSL_is_ntls(ssl) == 1))
        goto err;

    SSL_enable_ntls(ssl);
    if (!TEST_true(sc->enable_ntls == 1))
        goto err;
    SSL_disable_ntls(ssl);
    if (!TEST_true(sc->enable_ntls == 0))
        goto err;

    SSL_enable_force_ntls(ssl);
    if (!TEST_true(sc->enable_force_ntls == 1))
        goto err;
    SSL_disable_force_ntls(ssl);
    if (!TEST_true(sc->enable_force_ntls == 0))
        goto err;

    if (!TEST_int_eq(SSL_use_sign_certificate_file(ssl,
                                                   sign_cert_file,
                                                   SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_sign_PrivateKey_file(ssl,
                                                  sign_key_file,
                                                  SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_certificate_file(ssl,
                                                  enc_cert_file,
                                                  SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_PrivateKey_file(ssl,
                                                 enc_key_file,
                                                 SSL_FILETYPE_PEM), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return ret;
}

static int test_ntls_ctx_set_cert_pkey_api(int i)
{
    int           ret = 1;
    SSL_CTX      *ctx = NULL;
    X509         *sign_cert = NULL;
    EVP_PKEY     *sign_pkey = NULL;
    X509         *enc_cert = NULL;
    EVP_PKEY     *enc_pkey = NULL;
    BIO          *sign_cert_bio = NULL;
    BIO          *sign_pkey_bio = NULL;
    BIO          *enc_cert_bio = NULL;
    BIO          *enc_pkey_bio = NULL;
    const char   *sign_cert_file = NULL;
    const char   *sign_key_file = NULL;
    const char   *enc_cert_file = NULL;
    const char   *enc_key_file = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    sign_cert_bio = BIO_new(BIO_s_file());
    enc_cert_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_cert_bio) || !TEST_ptr(enc_cert_bio))
        goto err;

    if (!TEST_int_eq(BIO_read_filename(sign_cert_bio, sign_cert_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_cert_bio, enc_cert_file), 1))
        goto err;

    sign_cert = PEM_read_bio_X509(sign_cert_bio, NULL, NULL, NULL);
    enc_cert = PEM_read_bio_X509(enc_cert_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_cert) || !TEST_ptr(enc_cert))
        goto err;

    sign_pkey_bio = BIO_new(BIO_s_file());
    enc_pkey_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_pkey_bio) || !TEST_ptr(enc_pkey_bio))
        goto err;

    if (!TEST_int_eq(BIO_read_filename(sign_pkey_bio, sign_key_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_pkey_bio, enc_key_file), 1))
        goto err;

    sign_pkey = PEM_read_bio_PrivateKey(sign_pkey_bio, NULL, NULL, NULL);
    enc_pkey = PEM_read_bio_PrivateKey(enc_pkey_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_pkey) || !TEST_ptr(enc_pkey))
        goto err;


    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;


    if (!TEST_int_eq(SSL_CTX_use_sign_certificate(ctx, sign_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_sign_PrivateKey(ctx, sign_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_certificate(ctx, enc_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_CTX_use_enc_PrivateKey(ctx, enc_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(ctx->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    BIO_free(sign_cert_bio);
    BIO_free(enc_cert_bio);
    BIO_free(sign_pkey_bio);
    BIO_free(enc_pkey_bio);
    X509_free(sign_cert);
    X509_free(enc_cert);
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
    SSL_CTX_free(ctx);
    return ret;
}

static int test_ntls_ssl_set_cert_pkey_api(int i)
{
    int           ret = 1;
    const char   *sign_cert_file = NULL;
    const char   *sign_key_file = NULL;
    const char   *enc_cert_file = NULL;
    const char   *enc_key_file = NULL;
    SSL_CTX      *ctx = NULL;
    SSL          *ssl = NULL;
    X509         *sign_cert = NULL;
    EVP_PKEY     *sign_pkey = NULL;
    X509         *enc_cert = NULL;
    EVP_PKEY     *enc_pkey = NULL;
    BIO          *sign_cert_bio = NULL;
    BIO          *sign_pkey_bio = NULL;
    BIO          *enc_cert_bio = NULL;
    BIO          *enc_pkey_bio = NULL;
    SSL_CONNECTION  *sc = NULL;

    if (i == 0) {
# ifndef OPENSSL_NO_SM2
        sign_cert_file = sm2_sign_cert_file;
        sign_key_file = sm2_sign_key_file;
        enc_cert_file = sm2_enc_cert_file;
        enc_key_file = sm2_enc_key_file;
# endif
    } else {
        sign_cert_file = rsa_sign_cert_file;
        sign_key_file = rsa_sign_key_file;
        enc_cert_file = rsa_enc_cert_file;
        enc_key_file = rsa_enc_key_file;
    }

    if (sign_cert_file == NULL || sign_key_file == NULL
        || enc_cert_file == NULL || enc_key_file == NULL)
        return 1;

    ret = 0;
    sign_cert_bio = BIO_new(BIO_s_file());
    enc_cert_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_cert_bio) || !TEST_ptr(enc_cert_bio))
        goto err;
    if (!TEST_int_eq(BIO_read_filename(sign_cert_bio, sign_cert_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_cert_bio, enc_cert_file), 1))
        goto err;
    sign_cert = PEM_read_bio_X509(sign_cert_bio, NULL, NULL, NULL);
    enc_cert = PEM_read_bio_X509(enc_cert_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_cert) || !TEST_ptr(enc_cert))
        goto err;

    sign_pkey_bio = BIO_new(BIO_s_file());
    enc_pkey_bio = BIO_new(BIO_s_file());
    if (!TEST_ptr(sign_pkey_bio) || !TEST_ptr(enc_pkey_bio))
        goto err;
    if (!TEST_int_eq(BIO_read_filename(sign_pkey_bio, sign_key_file), 1)
        || !TEST_int_eq(BIO_read_filename(enc_pkey_bio, enc_key_file), 1))
        goto err;
    sign_pkey = PEM_read_bio_PrivateKey(sign_pkey_bio, NULL, NULL, NULL);
    enc_pkey = PEM_read_bio_PrivateKey(enc_pkey_bio, NULL, NULL, NULL);
    if (!TEST_ptr(sign_pkey) || !TEST_ptr(enc_pkey))
        goto err;

    ctx = SSL_CTX_new(NTLS_method());
    if (!TEST_true(ctx != NULL))
        goto err;

    ssl = SSL_new(ctx);
    if (!TEST_true(ssl != NULL))
        goto err;

    sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl);
    if (!TEST_true(sc != NULL))
        goto err;

    if (!TEST_int_eq(SSL_use_sign_certificate(ssl, sign_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_SIGN].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_sign_PrivateKey(ssl, sign_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_SIGN].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_SIGN].privatekey != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_certificate(ssl, enc_cert), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_ENC].x509 != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL))
            goto err;
    }

    if (!TEST_int_eq(SSL_use_enc_PrivateKey(ssl, enc_pkey), 1))
        goto err;

    if (i == 0) {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey != NULL))
            goto err;
    } else {
        if (!TEST_true(sc->cert->pkeys[SSL_PKEY_RSA_ENC].privatekey != NULL))
            goto err;
    }

    ret = 1;
err:
    BIO_free(sign_cert_bio);
    BIO_free(enc_cert_bio);
    BIO_free(sign_pkey_bio);
    BIO_free(enc_pkey_bio);
    X509_free(sign_cert);
    X509_free(enc_cert);
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
    SSL_CTX_free(ctx);
    SSL_free(ssl);
    return ret;
}

static int test_ntls_method_api(void)
{
    int ret = 1;
    const SSL_METHOD *meth = NULL;

    ret = 0;
    meth = NTLS_method();
    if (!TEST_true(meth->version == NTLS_VERSION))
        goto err;
    if (!TEST_true(meth->flags == SSL_METHOD_NO_SUITEB))
        goto err;
    if (!TEST_true(meth->mask == SSL_OP_NO_NTLS))
        goto err;

    meth = NTLS_server_method();
    if (!TEST_true(meth->version == NTLS_VERSION))
        goto err;
    if (!TEST_true(meth->flags == SSL_METHOD_NO_SUITEB))
        goto err;
    if (!TEST_true(meth->mask == SSL_OP_NO_NTLS))
        goto err;

    meth = NTLS_client_method();
    if (!TEST_true(meth->version == NTLS_VERSION))
        goto err;
    if (!TEST_true(meth->flags == SSL_METHOD_NO_SUITEB))
        goto err;
    if (!TEST_true(meth->mask == SSL_OP_NO_NTLS))
        goto err;

    ret = 1;
err:
    return ret;
}

#ifndef OPENSSL_NO_SM4

static X509 *load_cert(const char *file)
{
    BIO *in = BIO_new_file(file, "r");
    X509 *x = in == NULL ? NULL : PEM_read_bio_X509(in, NULL, NULL, NULL);
    BIO_free(in);
    return x;
}

static int verify_always_ok(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

static int test_ntls_get0_peer_certs(int i)
{
    int ret = 0;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    X509 *s_sign_cert = NULL, *s_enc_cert = NULL;
    X509 *p_sign_cert = NULL, *p_enc_cert = NULL;
    
    s_sign_cert = load_cert(rsa_sign_cert_file);
    s_enc_cert = load_cert(rsa_enc_cert_file);
    if (!TEST_ptr(s_sign_cert) || !TEST_ptr(s_enc_cert))
        goto err;

    if (!TEST_true(create_ssl_ctx_pair(NULL, NTLS_server_method(),
                   NTLS_client_method(), 0, 0, &sctx, &cctx, NULL, NULL)))
        goto err;

    SSL_CTX_enable_ntls(sctx);
    SSL_CTX_enable_ntls(cctx);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    if (!TEST_int_eq(SSL_CTX_use_sign_certificate_file(sctx, rsa_sign_cert_file, SSL_FILETYPE_PEM), 1)
        || !TEST_int_eq(SSL_CTX_use_sign_PrivateKey_file(sctx, rsa_sign_key_file, SSL_FILETYPE_PEM), 1)
        || !TEST_int_eq(SSL_CTX_use_enc_certificate_file(sctx, rsa_enc_cert_file, SSL_FILETYPE_PEM), 1)
        || !TEST_int_eq(SSL_CTX_use_enc_PrivateKey_file(sctx, rsa_enc_key_file, SSL_FILETYPE_PEM), 1)
        || !TEST_true(SSL_CTX_set_cipher_list(sctx, NTLS_TXT_RSA_SM4_CBC_SHA256))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, NTLS_TXT_RSA_SM4_CBC_SHA256)))
        goto err;

    if (i == 0) {
        /* Case 0: Unilateral authentication. */
        SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    } else {
        /* Case 1: Mutual authentication. */
        SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,verify_always_ok);
        if (!TEST_int_eq(SSL_CTX_use_sign_certificate_file(cctx, rsa_sign_cert_file, SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_CTX_use_sign_PrivateKey_file(cctx, rsa_sign_key_file, SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_CTX_use_enc_certificate_file(cctx, rsa_enc_cert_file, SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_CTX_use_enc_PrivateKey_file(cctx, rsa_enc_key_file, SSL_FILETYPE_PEM), 1))
            goto err;
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto err;

    if (i == 0) {
        /* Case 0: Unilateral authentication. Test c->s certificates. */
        p_sign_cert = SSL_get0_peer_sign_certificate_ntls(cssl);
        p_enc_cert = SSL_get0_peer_enc_certificate_ntls(cssl);
    } else {
        /* Case 1: Mutual authentication. Test s->c certificates.*/
        p_sign_cert = SSL_get0_peer_sign_certificate_ntls(sssl);
        p_enc_cert = SSL_get0_peer_enc_certificate_ntls(sssl);
    }

    if (!TEST_ptr(p_sign_cert) || !TEST_ptr(p_enc_cert)
        || !TEST_int_eq(X509_cmp(p_sign_cert, s_sign_cert), 0)
        || !TEST_int_eq(X509_cmp(p_enc_cert, s_enc_cert), 0))
        goto err;
    
    ret = 1;
err:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    X509_free(s_sign_cert);
    X509_free(s_enc_cert);
    return ret;
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(sm2_sign_cert_file = test_get_argument(0))
            || !TEST_ptr(sm2_sign_key_file = test_get_argument(1))
            || !TEST_ptr(sm2_enc_cert_file = test_get_argument(2))
            || !TEST_ptr(sm2_enc_key_file = test_get_argument(3))
            || !TEST_ptr(rsa_sign_cert_file = test_get_argument(4))
            || !TEST_ptr(rsa_sign_key_file = test_get_argument(5))
            || !TEST_ptr(rsa_enc_cert_file = test_get_argument(6))
            || !TEST_ptr(rsa_enc_key_file = test_get_argument(7))) {
        TEST_note("usage: ssl_ntls_api_test cert.pem|key.pem");
        return 0;
    }
    ADD_ALL_TESTS(test_ntls_ctx_set_cert_pkey_file_api, 2);
    ADD_ALL_TESTS(test_ntls_ctx_set_cert_pkey_api, 2);
    ADD_ALL_TESTS(test_ntls_ssl_set_cert_pkey_file_api, 2);
    ADD_ALL_TESTS(test_ntls_ssl_set_cert_pkey_api, 2);
    ADD_TEST(test_ntls_method_api);

    ADD_ALL_TESTS(test_ntls_ctx_set_cipher_list, OSSL_NELEM(cipher_list) - 1);
    ADD_ALL_TESTS(test_ntls_ssl_set_cipher_list, OSSL_NELEM(cipher_list) - 1);
    /* All NTLS ciphersuites need SM4. */
# ifndef OPENSSL_NO_SM4
    ADD_ALL_TESTS(test_ntls_get0_peer_certs,2);
# endif
    return 1;
}
