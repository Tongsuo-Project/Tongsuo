/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ssl_local.h"

#define DELEGATED_CREDENTIAL_CLIENT_LABEL "TLS, client delegated credentials"
#define DELEGATED_CREDENTIAL_SERVER_LABEL "TLS, server delegated credentials"
#define DELEGATED_CREDENTIAL_SIGN_START_SIZE 64

#define W16(buf, value) {put_value(buf, value, 2); buf += 2;}
#define W24(buf, value) {put_value(buf, value, 3); buf += 3;}
#define W32(buf, value) {put_value(buf, value, 4); buf += 4;}

static void put_value(unsigned char *buf, size_t value, size_t len)
{
    for (buf += len - 1; len > 0; len--) {
        *buf = (unsigned char)(value & 0xff);
        buf--;
        value >>= 8;
    }
}

void SSL_CTX_enable_verify_peer_by_dc(SSL_CTX *ctx)
{
    ctx->enable_verify_peer_by_dc = 1;
}

void SSL_CTX_disable_verify_peer_by_dc(SSL_CTX *ctx)
{
    ctx->enable_verify_peer_by_dc = 0;
}

void SSL_enable_verify_peer_by_dc(SSL *s)
{
    s->enable_verify_peer_by_dc = 1;
}

void SSL_disable_verify_peer_by_dc(SSL *s)
{
    s->enable_verify_peer_by_dc = 0;
}

void SSL_CTX_enable_sign_by_dc(SSL_CTX *ctx)
{
    ctx->enable_sign_by_dc = 1;
}

void SSL_CTX_disable_sign_by_dc(SSL_CTX *ctx)
{
    ctx->enable_sign_by_dc = 0;
}

void SSL_enable_sign_by_dc(SSL *s)
{
    s->enable_sign_by_dc = 1;
}

void SSL_disable_sign_by_dc(SSL *s)
{
    s->enable_sign_by_dc = 0;
}

int SSL_get_delegated_credential_tag(SSL *s)
{
    return s->delegated_credential_tag;
}

static int ssl_dc_tbs_data(unsigned char *parent_cert_raw,
                           long parent_cert_len,
                           DELEGATED_CREDENTIAL *dc, int is_server,
                           unsigned char **tbs, unsigned int *tbs_len)
{
    unsigned int  sign_data_len;
    unsigned int  dc_cred_and_alg_len = 0;
    unsigned char *index;

    if (dc == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    dc_cred_and_alg_len = DC_get_raw_byte_len(dc) - 2 - DC_get_dc_signature_len(dc);

    /* length of dc client label is equal to server label */
    sign_data_len = DELEGATED_CREDENTIAL_SIGN_START_SIZE
               + sizeof(DELEGATED_CREDENTIAL_SERVER_LABEL)
               + parent_cert_len
               + dc_cred_and_alg_len;

    *tbs = OPENSSL_malloc(sign_data_len);
    index = *tbs;
    if (*tbs == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    /*
     * First part is a string that consists of octet 32 (0x20) repeated 64 times.
     */
    memset(index, 32, DELEGATED_CREDENTIAL_SIGN_START_SIZE);
    index += DELEGATED_CREDENTIAL_SIGN_START_SIZE;

    /*
     * Second part is a context string "TLS, server delegated credentials" for
     * servers and "TLS, client delegated credentials" for clients.
     * Third part is a single 0 byte, which serves as the separator.
     * '0' exists in DELEGATED_CREDENTIAL_SERVER_LABEL default terminator
     */
    if (is_server) {
        strcpy((char *)index, DELEGATED_CREDENTIAL_SERVER_LABEL);
        index += sizeof(DELEGATED_CREDENTIAL_SERVER_LABEL);
    } else {
        strcpy((char *)index, DELEGATED_CREDENTIAL_CLIENT_LABEL);
        index += sizeof(DELEGATED_CREDENTIAL_CLIENT_LABEL);
    }

    /*
     * Fourth part is the DER-encoded X.509 end-entity certificate used to sign the
     * DelegatedCredential.
     */
    memcpy(index, parent_cert_raw, parent_cert_len);
    index += parent_cert_len;

    /*
     * Fifth part is Credential in DelegatedCredential
     * Sixth part is DelegatedCredential.algorithm.
     * We can make a one-time copy from dc raw byte
     */
    memcpy(index, DC_get0_raw_byte(dc), dc_cred_and_alg_len);
    index += dc_cred_and_alg_len;

    if ((index - *tbs) != sign_data_len) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    *tbs_len = sign_data_len;
    return 1;
}

int SSL_verify_delegated_credential_signature(X509 *parent_cert,
                                              DELEGATED_CREDENTIAL *dc,
                                              int is_server)
{
    unsigned char *tbs = NULL;
    unsigned int tbs_len;
    int ret = 0;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int dc_sign_algo = 0;
    unsigned char *parent_cert_raw = NULL;
    unsigned char *parent_cert_raw_index = NULL;
    long parent_cert_len;
    const EVP_MD *md = NULL;
    EVP_PKEY *pkey = NULL;
    const SIGALG_LOOKUP *lu = NULL;

    if (parent_cert == NULL || dc == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    pkey = X509_get0_pubkey(parent_cert);
    if (pkey == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    dc_sign_algo = DC_get_signature_sign_algorithm(dc);

    lu = ssl_sigalg_lookup(dc_sign_algo);
    if (lu == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_SIGNATURE_ALGORITHMS_ERROR);
        goto err;
    }

    md = EVP_get_digestbynid(lu->hash);

    parent_cert_len = i2d_X509_AUX(parent_cert, NULL);
    if (parent_cert_len <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((parent_cert_raw = OPENSSL_malloc(parent_cert_len)) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    parent_cert_raw_index = parent_cert_raw;
    parent_cert_len = i2d_X509_AUX(parent_cert, &parent_cert_raw_index);

    if (!ssl_dc_tbs_data(parent_cert_raw, parent_cert_len,
                                           dc, is_server, &tbs, &tbs_len)) {
        goto err;
    }

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_DigestVerifyInit(mctx, &pctx, md, NULL, pkey) <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
        goto err;
    }

    if (lu->sig == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                RSA_PSS_SALTLEN_DIGEST) <= 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
            goto err;
        }
    }

    ret = EVP_DigestVerify(mctx, DC_get0_dc_signature(dc),
                           DC_get_dc_signature_len(dc),
                           (const unsigned char *)tbs, tbs_len);

err:
    EVP_MD_CTX_free(mctx);
    OPENSSL_free(tbs);
    OPENSSL_free(parent_cert_raw);
    return ret;
}

int DC_sign(DELEGATED_CREDENTIAL *dc, EVP_PKEY *dc_pkey,
            unsigned int valid_time, int expect_verify_hash,
            X509 *ee_cert, EVP_PKEY *ee_pkey, const EVP_MD *md, int is_server)
{
    int ret = 0;
    int day, sec;
    unsigned char *dc_pkey_raw_index = NULL;
    uint32_t max_valid_time = 7 * 24 * 3600;
    unsigned char *dc_buf, *index;
    int dc_raw_len = 0;
    unsigned char *tbs = NULL;
    unsigned int tbs_len;
    int res = 0;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    ASN1_TIME *ee_cert_time = NULL, *curr_time = NULL;
    uint32_t dc_pkey_raw_len;
    unsigned char *dc_pkey_raw = NULL;
    size_t dc_sign_len, dc_sign_result_len;
    unsigned char *parent_cert_raw = NULL, *parent_cert_raw_index = NULL;
    int ee_cert_len;
    const SIGALG_LOOKUP *dc_verify_lu = NULL;
    const SIGALG_LOOKUP *sig_lu = NULL;

    if (dc == NULL || dc_pkey == NULL
        || ee_cert == NULL || ee_pkey == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!DC_check_parent_cert_valid(ee_cert))
        goto end;

    dc_pkey_raw_len = i2d_PUBKEY(dc_pkey, NULL);
    if (dc_pkey_raw_len <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if ((dc_pkey_raw = OPENSSL_malloc(dc_pkey_raw_len)) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    dc_pkey_raw_index = dc_pkey_raw;
    dc_pkey_raw_len = i2d_PUBKEY(dc_pkey, &dc_pkey_raw_index);

    dc_verify_lu = ssl_sigalg_lookup_by_pkey_and_hash(dc_pkey,
                                                      expect_verify_hash, 1);
    if (dc_verify_lu == NULL)
        goto end;

    sig_lu = ssl_sigalg_lookup_by_pkey_and_hash(ee_pkey, EVP_MD_type(md), 0);
    if (sig_lu == NULL)
        goto end;

    if (valid_time > max_valid_time) {
        ERR_raise(ERR_LIB_SSL, SSL_R_DC_VALID_TIME_TOO_LARGE);
        goto end;
    }

    ee_cert_time = ASN1_STRING_dup(X509_get0_notBefore(ee_cert));
    if (ee_cert_time == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    curr_time = X509_time_adj(NULL, 0, NULL);
    if (curr_time == NULL)
        goto end;

    if (!ASN1_TIME_diff(&day, &sec, ee_cert_time, curr_time))
        goto end;

    if (day < 0 || sec < 0 )
        goto end;

    valid_time += day * 24 * 3600 + sec;

    dc_sign_len = EVP_PKEY_size(ee_pkey);

    dc_raw_len = sizeof(uint32_t) + sizeof(uint16_t) + 3 + dc_pkey_raw_len
                 + sizeof(uint16_t) + 2 + dc_sign_len;

    dc_buf = OPENSSL_malloc(dc_raw_len);
    if (!dc_buf) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    index = dc_buf;

    /* uint32 valid_time */
    W32(index, valid_time);

    /* SignatureScheme expected_cert_verify_algorithm */
    W16(index, dc_verify_lu->sigalg);

    /* opaque ASN1_subjectPublicKeyInfo<1..2^24-1> */
    W24(index, dc_pkey_raw_len);
    memcpy(index, dc_pkey_raw, dc_pkey_raw_len);
    index += dc_pkey_raw_len;

    /* SignatureScheme algorithm */
    W16(index, sig_lu->sigalg);

    /*
     * Actualy dc_sign_len is not the real sign result len, but function
     * ssl_dc_tbs_data o    nly need credential and sign
     * algorithm. So we can get right result even if using a wrong
     * dc_sign_len
     */
    W16(index, dc_sign_len);

    DC_set_dc_signature_len(dc, dc_sign_len);
    DC_set0_raw_byte(dc, dc_buf, dc_raw_len);

    ee_cert_len = i2d_X509_AUX(ee_cert, NULL);
    if (ee_cert_len <= 0)
        goto end;

    if ((parent_cert_raw = OPENSSL_malloc(ee_cert_len)) == NULL)
        goto end;

    parent_cert_raw_index = parent_cert_raw;
    ee_cert_len = i2d_X509_AUX(ee_cert, &parent_cert_raw_index);

    res = ssl_dc_tbs_data(parent_cert_raw, ee_cert_len,
                          dc, is_server, &tbs, &tbs_len);
    if (res <= 0)
        goto end;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!EVP_DigestSignInit_ex(mctx, &pctx, EVP_MD_name(md), NULL,
                               NULL, ee_pkey, NULL)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (sig_lu->sig == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                RSA_PSS_SALTLEN_DIGEST) <= 0) {
            ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
            goto end;
        }
    }

    dc_sign_result_len = dc_sign_len;
    res = EVP_DigestSign(mctx, index, &dc_sign_result_len,
                         (const unsigned char *)tbs, tbs_len);
    if (res <= 0) {
        ERR_raise(ERR_LIB_SSL, ERR_R_EVP_LIB);
        goto end;
    }

    index -= 2;
    W16(index, dc_sign_result_len);
    DC_set_dc_signature_len(dc, dc_sign_result_len);

    dc_raw_len = dc_raw_len - dc_sign_len + dc_sign_result_len;
    DC_set0_raw_byte(dc, DC_get0_raw_byte(dc), dc_raw_len);

    ret = 1;
end:
    OPENSSL_free(tbs);
    EVP_MD_CTX_free(mctx);
    OPENSSL_free(dc_pkey_raw);
    OPENSSL_free(parent_cert_raw);
    ASN1_STRING_clear_free(ee_cert_time);
    ASN1_STRING_clear_free(curr_time);

    return ret;
}

int DC_print(BIO *bp, DELEGATED_CREDENTIAL *dc)
{
    int ret = 0;
    int indent = 0;
    unsigned int i, siglen;
    unsigned int sigalg;
    const char *name;
    unsigned char *sig;
    const SIGALG_LOOKUP *lu;

    if (BIO_printf(bp, "DelegatedCredential:\n") <= 0)
        goto end;

    indent += 4;
    if (BIO_printf(bp, "%*sCredential:\n", indent, "") <= 0)
        goto end;

    indent += 4;
    if (BIO_printf(bp, "%*svalid_time: %lu\n",
                   indent, "", DC_get_valid_time(dc)) <= 0)
        goto end;

    sigalg = DC_get_expected_cert_verify_algorithm(dc);

    lu = ssl_sigalg_lookup(sigalg);
    if (lu == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM);
        goto end;
    }

    name = lu->name;
    if (BIO_printf(bp, "%*sexpected_cert_verify_algorithm: %s (0x%04x)\n",
                   indent, "", name ? name : "NULL", sigalg) <= 0)
        goto end;

    if (BIO_printf(bp, "%*sSubject Public Key Info:\n", indent, "") <= 0)
        goto end;

    indent += 4;
    if (BIO_printf(bp, "%*sPublic Key Algorithm: ", indent, "") <= 0)
        goto end;

    if (i2a_ASN1_OBJECT(bp, OBJ_nid2obj(
                                EVP_PKEY_id(DC_get0_publickey(dc)))) <= 0)
        goto end;

    if (BIO_puts(bp, "\n") <= 0)
        goto end;

    indent += 4;
    if (EVP_PKEY_print_public(bp, DC_get0_publickey(dc), indent, NULL) <= 0)
        goto end;

    indent = 4;
    sigalg = DC_get_signature_sign_algorithm(dc);

    lu = ssl_sigalg_lookup(sigalg);
    if (lu == NULL) {
        ERR_raise(ERR_LIB_SSL, SSL_R_NO_SUITABLE_SIGNATURE_ALGORITHM);
        goto end;
    }

    name = lu->name;
    if (BIO_printf(bp, "%*sSignature Algorithm: %s (0x%04x)",
                   indent, "", name ? name : "unknown", sigalg) <= 0)
        goto end;

    if (BIO_printf(bp, "\n%*sSignature:", indent, "") <= 0)
        goto end;

    indent += 4;

    sig = DC_get0_dc_signature(dc);
    siglen = DC_get_dc_signature_len(dc);

    for (i = 0; i < siglen; i++) {
        if ((i % 18) == 0) {
            if (BIO_write(bp, "\n", 1) <= 0)
                goto end;
            if (BIO_indent(bp, indent, indent) <= 0)
                goto end;
        }

        if (BIO_printf(bp, "%02x%s", sig[i],
                       ((i + 1) == siglen) ? "" : ":") <= 0)
            goto end;
    }

    if (BIO_write(bp, "\n", 1) <= 0)
        goto end;

    ret = 1;

end:
    return ret;
}
