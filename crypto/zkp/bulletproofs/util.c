/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/zkpbperr.h>
#include <crypto/ec/ec_local.h>
#include "util.h"

EC_POINT **bp_random_ec_points_new(const EC_GROUP *group, size_t n, BN_CTX *bn_ctx)
{
    size_t i;
    BIGNUM *r = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT **P = NULL;
    const BIGNUM *order;

    if (group == NULL || (n % 2) != 0)
        return NULL;

    if (!(P = OPENSSL_zalloc(n * sizeof(*P)))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    order = EC_GROUP_get0_order(group);

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new_ex(group->libctx);
        if (bn_ctx == NULL)
            goto err;
    }

    BN_CTX_start(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    if (r == NULL)
        goto err;

    for (i = 0; i < n; i++) {
        bp_rand_range(r, order);
        if (!(P[i] = EC_POINT_new(group)) || !EC_POINT_mul(group, P[i], r, NULL,
                                                           NULL, bn_ctx))
            goto err;
    }

    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    return P;

err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    bp_random_ec_points_free(P, n);
    return NULL;
}

void bp_random_ec_points_free(EC_POINT **P, size_t n)
{
    size_t i;

    if (P == NULL)
        return;

    for (i = 0; i < n; i++) {
        EC_POINT_free(P[i]);
    }

    OPENSSL_free(P);
}

EC_POINT *bp_random_ec_point_new(const EC_GROUP *group, BN_CTX *bn_ctx)
{
    BIGNUM *r = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT *P = NULL;
    const BIGNUM *order;

    if (group == NULL)
        return NULL;

    if (bn_ctx == NULL) {
        bctx = bn_ctx = BN_CTX_new_ex(group->libctx);
        if (bn_ctx == NULL)
            goto err;
    }

    order = EC_GROUP_get0_order(group);

    BN_CTX_start(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    if (r == NULL)
        goto err;

    bp_rand_range(r, order);

    if (!(P = EC_POINT_new(group)) || !EC_POINT_mul(group, P, r, NULL, NULL,
                                                    bn_ctx))
        goto err;

    BN_CTX_end(bn_ctx);

    return P;
err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bctx);
    bp_random_ec_point_free(P);
    return NULL;
}

void bp_random_ec_point_free(EC_POINT *P)
{
    if (P == NULL)
        return;

    EC_POINT_free(P);
}

int bp_str2bn(const unsigned char *str, size_t len, BIGNUM *ret)
{
    int r = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];

    if (str == NULL || ret == NULL)
        return r;

    memset(hash_res, 0, sizeof(hash_res));

    if (!SHA256(str, len, hash_res))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, ret))
        goto end;

    r = 1;
end:
    return r;
}

int bp_points_hash2bn(const EC_GROUP *group, EC_POINT *A, EC_POINT *B,
                      BIGNUM *ra, BIGNUM *rb, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t plen;
    unsigned char *transcript_str = NULL;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;
    BIGNUM *a;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *md_ctx1 = NULL, *md_ctx2 = NULL;

    if (group == NULL || A == NULL || B == NULL || bn_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if (ra == NULL && rb == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    BN_CTX_start(bn_ctx);
    a = BN_CTX_get(bn_ctx);
    if (a == NULL)
        goto end;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0)
        goto end;

    transcript_str = OPENSSL_zalloc(plen);
    if (transcript_str == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(md_ctx1 = EVP_MD_CTX_new())
        || !(md_ctx2 = EVP_MD_CTX_new())
        || !(sha256 = EVP_MD_fetch(group->libctx, "sha256", NULL))
        || !EVP_DigestInit_ex(md_ctx1, sha256, NULL)
        || !EVP_DigestInit_ex(md_ctx2, sha256, NULL))
        goto end;

    if (EC_POINT_point2oct(group, A, format, transcript_str, plen, bn_ctx) <= 0
        || !EVP_DigestUpdate(md_ctx1, transcript_str, plen)
        || !EVP_DigestUpdate(md_ctx2, transcript_str, plen)
        || EC_POINT_point2oct(group, B, format, transcript_str, plen, bn_ctx) <= 0
        || !EVP_DigestUpdate(md_ctx1, transcript_str, plen)
        || !EVP_DigestUpdate(md_ctx2, transcript_str, plen)
        || !EVP_DigestFinal(md_ctx1, hash_res, NULL))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, a))
        goto end;

    if (ra != NULL && !BN_copy(ra, a))
        goto end;

    if (rb != NULL && (!EVP_DigestUpdate(md_ctx2, hash_res, SHA256_DIGEST_LENGTH)
                       || !EVP_DigestFinal(md_ctx2, hash_res, NULL)
                       || !BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, rb)))
        goto end;

    ret = 1;
end:
    OPENSSL_free(transcript_str);
    BN_CTX_end(bn_ctx);
    return ret;
}

/* r = SHA256(str_st, bin(P)) */
int bp_bin_point_hash2bn(const EC_GROUP *group, const char *st, size_t len,
                         const EC_POINT *P, BIGNUM *r, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t plen;
    unsigned char *buf = NULL;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;
    EVP_MD *sha256 = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    BN_CTX *bctx = NULL;

    if (group == NULL || P == NULL || r == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    if (bn_ctx == NULL) {
        if (!(bctx = bn_ctx = BN_CTX_new()))
            goto end;
    }

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0)
        goto end;

    buf = OPENSSL_zalloc(plen);
    if (buf == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if (!(md_ctx = EVP_MD_CTX_new())
        || !(sha256 = EVP_MD_fetch(group->libctx, "sha256", NULL))
        || !EVP_DigestInit_ex(md_ctx, sha256, NULL))
        goto end;

    if (st && len > 0 && !EVP_DigestUpdate(md_ctx, st, len))
        goto end;

    if (EC_POINT_point2oct(group, P, format, buf, plen, bn_ctx) <= 0
        || !EVP_DigestUpdate(md_ctx, buf, plen)
        || !EVP_DigestFinal(md_ctx, hash_res, NULL))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, r))
        goto end;

    ret = 1;
end:
    OPENSSL_free(buf);
    BN_CTX_free(bctx);
    return ret;
}

/* r = SHA256(bin(bn_st), bin(P)) */
int bp_bn_point_hash2bn(const EC_GROUP *group, const BIGNUM *bn_st,
                        const EC_POINT *P, BIGNUM *r, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t n;
    char *buf = NULL;

    if (group == NULL || P == NULL || r == NULL)
        goto end;

    if (bn_st == NULL)
        return bp_bin_point_hash2bn(group, NULL, 0, P, r, bn_ctx);

    n = BN_num_bytes(bn_st);
    if (!(buf = OPENSSL_zalloc(n))) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    if ((n = BN_bn2bin(bn_st, (unsigned char *)buf)) <= 0)
        goto end;

    ret = bp_bin_point_hash2bn(group, buf, n, P, r, bn_ctx);
end:
    OPENSSL_free(buf);
    return ret;
}

int bp_random_bn_gen(const EC_GROUP *group, BIGNUM **r, size_t n, BN_CTX *bn_ctx)
{
    size_t i;
    const BIGNUM *order;

    if (group == NULL || r == NULL || bn_ctx == NULL)
        return 0;

    order = EC_GROUP_get0_order(group);

    for (i = 0; i < n; i++) {
        if (!(r[i] = BN_CTX_get(bn_ctx)) || !bp_rand_range(r[i], order))
            return 0;
    }

    return 1;
}

int bp_str2point(const EC_GROUP *group, const unsigned char *str, size_t len,
                 EC_POINT *r, BN_CTX *bn_ctx)
{
    int ret = 0, i = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    unsigned char *p = (unsigned char *)str;
    BN_CTX *ctx = NULL;
    BIGNUM *x;

    memset(hash_res, 0, sizeof(hash_res));

    if (bn_ctx == NULL) {
        if ((ctx = bn_ctx = BN_CTX_new_ex(group->libctx)) == NULL)
            goto end;
    }

    BN_CTX_start(bn_ctx);
    if ((x = BN_CTX_get(bn_ctx)) == NULL)
        goto end;

    do {
        if (!SHA256(p, len, hash_res))
            goto end;

        BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, x);

        p  = &hash_res[0];
        len = sizeof(hash_res);

        if(EC_POINT_set_compressed_coordinates(group, r, x, 0, bn_ctx) == 1) {
            ret = 1;
            break;
        }

        ERR_clear_error();
    } while (i++ < 10);

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(ctx);
    return ret;
}

size_t bp_point2oct(const EC_GROUP *group, const EC_POINT *P,
                    unsigned char *buf, BN_CTX *bn_ctx)
{
    size_t plen;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;

    if (group == NULL || P == NULL || bn_ctx == NULL)
        return -1;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0 || buf == NULL)
        return plen;

    if (EC_POINT_point2oct(group, P, format, buf, plen, bn_ctx) <= 0)
        return -1;

    return plen;
}

int bp_bin_hash2bn(const unsigned char *data, size_t len, BIGNUM *r)
{
    int ret = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];

    if (data == NULL || len <= 0 || r == NULL)
        return ret;

    if (!SHA256(data, len, hash_res))
        goto end;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, r))
        goto end;

    ret = 1;
end:
    return ret;
}
