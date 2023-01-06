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
#include <crypto/ec/ec_local.h>
#include "util.h"

EC_POINT **bp_random_ec_points_new(const EC_GROUP *group, size_t n, BN_CTX *bn_ctx)
{
    size_t i;
    BIGNUM *r = NULL;
    BN_CTX *bctx = NULL;
    EC_POINT **P = NULL;
    const BIGNUM *order;

    if (group == NULL || n > 32)
        return NULL;

    if (!(P = OPENSSL_zalloc(n * sizeof(*P))))
        goto err;

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

    if (group == NULL || A == NULL || B == NULL || bn_ctx == NULL)
        return ret;

    if (ra == NULL && rb == NULL)
        return ret;

    BN_CTX_start(bn_ctx);
    a = BN_CTX_get(bn_ctx);
    if (a == NULL)
        goto end;

    plen = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                              format, NULL, 0, bn_ctx);
    if (plen <= 0)
        goto end;

    transcript_str = OPENSSL_zalloc(plen);
    if (transcript_str == NULL)
        goto end;

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
