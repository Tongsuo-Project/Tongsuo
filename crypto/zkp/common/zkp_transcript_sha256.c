/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/zkperr.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "zkp_transcript.h"

#ifndef __bswap_constant_64
# define __bswap_constant_64(x)                 \
    ((((x) & 0xff00000000000000ull) >> 56)      \
     | (((x) & 0x00ff000000000000ull) >> 40)    \
     | (((x) & 0x0000ff0000000000ull) >> 24)    \
     | (((x) & 0x000000ff00000000ull) >> 8)     \
     | (((x) & 0x00000000ff000000ull) << 8)     \
     | (((x) & 0x0000000000ff0000ull) << 24)    \
     | (((x) & 0x000000000000ff00ull) << 40)    \
     | (((x) & 0x00000000000000ffull) << 56))
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define int64_n2l(x)  (x)
# define int64_l2n(x)  (x)
#else
# define int64_n2l(x)  __bswap_constant_64(x)
# define int64_l2n(x)  __bswap_constant_64(x)
#endif

typedef struct zkp_transcript_sha256_ctx_st {
    EVP_MD *sha256;
    EVP_MD_CTX *md_ctx;
} zkp_transcript_sha256_ctx;

static int zkp_transcript_sha256_init(ZKP_TRANSCRIPT *transcript)
{
    size_t len;
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!(ctx = OPENSSL_zalloc(sizeof(*ctx)))) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ctx->md_ctx = EVP_MD_CTX_new();
    if (ctx->md_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!(ctx->sha256 = EVP_MD_fetch(NULL, "sha256", NULL))
        || !EVP_DigestInit(ctx->md_ctx, ctx->sha256))
        goto err;

    if (transcript->label != NULL) {
        len = strlen(transcript->label);
        if (!EVP_DigestUpdate(ctx->md_ctx, transcript->label, len))
            goto err;
    }

    transcript->data = ctx;

    return 1;
err:
    EVP_MD_CTX_free(ctx->md_ctx);
    OPENSSL_free(ctx);
    return 0;
}

static int zkp_transcript_sha256_reset(ZKP_TRANSCRIPT *transcript)
{
    size_t len;
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx = transcript->data;

    if (!EVP_DigestInit(ctx->md_ctx, ctx->sha256))
        return 0;

    if (transcript->label != NULL) {
        len = strlen(transcript->label);
        if (!EVP_DigestUpdate(ctx->md_ctx, transcript->label, len))
            return 0;
    }

    return 1;
}

static int zkp_transcript_sha256_cleanup(ZKP_TRANSCRIPT *transcript)
{
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx = transcript->data;

    EVP_MD_CTX_free(ctx->md_ctx);

    return 1;
}

static int zkp_transcript_sha256_append_int64(ZKP_TRANSCRIPT *transcript,
                                              const char *label, const int64_t i64)
{
    int64_t num;
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL || label == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx = transcript->data;
    num = int64_l2n(i64);

    return EVP_DigestUpdate(ctx->md_ctx, label, strlen(label))
           && EVP_DigestUpdate(ctx->md_ctx, (char *)&num, sizeof(num));
}

static int zkp_transcript_sha256_append_str(ZKP_TRANSCRIPT *transcript,
                                            const char *label,
                                            const char *str, int len)
{
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL || str == NULL || len <= 0) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    ctx = transcript->data;

    return EVP_DigestUpdate(ctx->md_ctx, label, strlen(label))
           && EVP_DigestUpdate(ctx->md_ctx, str, len);
}

static int zkp_transcript_sha256_append_point(ZKP_TRANSCRIPT *transcript,
                                              const char *label,
                                              const EC_POINT *point,
                                              const EC_GROUP *group)
{
    int ret = 0;
    size_t len;
    unsigned char buf[128], *str = NULL;
    point_conversion_form_t format = POINT_CONVERSION_COMPRESSED;
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL || point == NULL || group == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx = transcript->data;

    len = EC_POINT_point2oct(group, point, format, NULL, 0, NULL);
    if (len > sizeof(buf)) {
        if (!(str = OPENSSL_zalloc(len))) {
            ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        str = &buf[0];
    }

    ret = EVP_DigestUpdate(ctx->md_ctx, label, strlen(label))
          && EC_POINT_point2oct(group, point, format, str, len, NULL) > 0
          && EVP_DigestUpdate(ctx->md_ctx, str, len);

    if (len > sizeof(buf))
        OPENSSL_free(str);

    return ret;
}

static int zkp_transcript_sha256_append_bn(ZKP_TRANSCRIPT *transcript,
                                           const char *label, const BIGNUM *bn)
{
    int ret = 0;
    size_t len;
    unsigned char buf[256] = {0}, *str = NULL;
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL || bn == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx = transcript->data;

    len = BN_is_zero(bn) ? 1 : BN_num_bytes(bn);
    if (len > sizeof(buf)) {
        if (!(str = OPENSSL_zalloc(len))) {
            ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        str = &buf[0];
    }

    ret = EVP_DigestUpdate(ctx->md_ctx, label, strlen(label))
          && BN_bn2binpad(bn, str, len) && EVP_DigestUpdate(ctx->md_ctx, str, len);

    if (len > sizeof(buf))
        OPENSSL_free(str);

    return ret;
}

static int zkp_transcript_sha256_challange(ZKP_TRANSCRIPT *transcript,
                                           const char *label, BIGNUM *out)
{
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    zkp_transcript_sha256_ctx *ctx = NULL;

    if (transcript == NULL || out == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    ctx = transcript->data;

    if (!EVP_DigestUpdate(ctx->md_ctx, label, strlen(label))
        || !EVP_DigestFinal(ctx->md_ctx, hash_res, NULL))
        return 0;

    if (!BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, out))
        return 0;

    if (!EVP_DigestInit(ctx->md_ctx, ctx->sha256))
        return 0;

    return EVP_DigestUpdate(ctx->md_ctx, hash_res, SHA256_DIGEST_LENGTH);
}

const ZKP_TRANSCRIPT_METHOD *ZKP_TRANSCRIPT_METHOD_sha256(void)
{
    static const ZKP_TRANSCRIPT_METHOD ret = {
        zkp_transcript_sha256_init,
        zkp_transcript_sha256_reset,
        zkp_transcript_sha256_cleanup,
        zkp_transcript_sha256_append_int64,
        zkp_transcript_sha256_append_str,
        zkp_transcript_sha256_append_point,
        zkp_transcript_sha256_append_bn,
        zkp_transcript_sha256_challange,
    };

    return &ret;
}
