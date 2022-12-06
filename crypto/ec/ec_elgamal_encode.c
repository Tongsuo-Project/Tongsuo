/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "ec_elgamal.h"
#include <openssl/err.h>
#include <string.h>

/** Creates a new EC_ELGAMAL_CIPHERTEXT object for EC-ELGAMAL oparations
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \return newly created EC_ELGAMAL_CIPHERTEXT object or NULL in case of an error
 */
EC_ELGAMAL_CIPHERTEXT *EC_ELGAMAL_CIPHERTEXT_new(EC_ELGAMAL_CTX *ctx)
{
    EC_POINT *C1 = NULL, *C2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *ciphertext;

    ciphertext = OPENSSL_zalloc(sizeof(*ciphertext));
    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    C1 = EC_POINT_new(ctx->key->group);
    if (C1 == NULL)
        goto err;

    C2 = EC_POINT_new(ctx->key->group);
    if (C2 == NULL)
        goto err;

    ciphertext->C1 = C1;
    ciphertext->C2 = C2;

    return ciphertext;

err:
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    OPENSSL_free(ciphertext);
    return NULL;
}

/** Frees a EC_ELGAMAL_CIPHERTEXT object
 *  \param  ciphertext  EC_ELGAMAL_CIPHERTEXT object to be freed
 */
void EC_ELGAMAL_CIPHERTEXT_free(EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    EC_POINT_free(ciphertext->C1);
    EC_POINT_free(ciphertext->C2);

    OPENSSL_free(ciphertext);
}

/** Encodes EC_ELGAMAL_CIPHERTEXT to binary
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  ciphertext EC_ELGAMAL_CIPHERTEXT object
 *  \param  compressed Whether to compress the encoding (either 0 or 1)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_ELGAMAL_CIPHERTEXT_encode(EC_ELGAMAL_CTX *ctx, unsigned char *out,
                                    size_t size,
                                    const EC_ELGAMAL_CIPHERTEXT *ciphertext,
                                    int compressed)
{
    size_t point_len, ret = 0, len, plen;
    unsigned char *p = out;
    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED :
                                                POINT_CONVERSION_UNCOMPRESSED;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || ciphertext == NULL ||
        ciphertext->C1 == NULL || ciphertext->C2 == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    point_len = EC_POINT_point2oct(ctx->key->group,
                                   EC_GROUP_get0_generator(ctx->key->group),
                                   form, NULL, 0, bn_ctx);
    len = point_len * 2;
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    memset(out, 0, size);

    plen = EC_POINT_point2oct(ctx->key->group, ciphertext->C1, form, p,
                              point_len, bn_ctx);
    if (plen == 0)
        goto end;

    p += point_len;

    plen = EC_POINT_point2oct(ctx->key->group, ciphertext->C2, form, p,
                              point_len, bn_ctx);
    if (plen == 0)
        goto end;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to EC_ELGAMAL_CIPHERTEXT
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded EC_ELGAMAL_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_CIPHERTEXT_decode(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                                 unsigned char *in, size_t size)
{
    int ret = 0;
    size_t point_len;
    unsigned char *p = in, zero[128];
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || r->C1 == NULL ||
        r->C2 == NULL || size % 2 != 0 || in == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    point_len = size / 2;
    memset(zero, 0, sizeof(zero));

    if (!EC_POINT_oct2point(ctx->key->group, r->C1, p, point_len, bn_ctx)) {
        if (memcmp(p, zero, point_len) != 0 ||
            !EC_POINT_set_to_infinity(ctx->key->group, r->C1))
            goto err;
    }

    p += point_len;

    if (!EC_POINT_oct2point(ctx->key->group, r->C2, p, point_len, bn_ctx)) {
        if (memcmp(p, zero, point_len) != 0 ||
            !EC_POINT_set_to_infinity(ctx->key->group, r->C2))
            goto err;
    }

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}
