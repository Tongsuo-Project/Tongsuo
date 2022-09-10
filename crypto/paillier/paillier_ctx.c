/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include "paillier_local.h"

PAILLIER_CTX *PAILLIER_CTX_new(PAILLIER_KEY *key)
{
    PAILLIER_CTX *ctx = NULL;

    ctx = OPENSSL_zalloc(sizeof(*key));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!PAILLIER_KEY_up_ref(key)) {
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->key = key;

    return ctx;
}

void PAILLIER_CTX_free(PAILLIER_CTX *ctx)
{
    if (ctx == NULL)
        return;

    PAILLIER_KEY_free(ctx->key);
    OPENSSL_clear_free((void *)ctx, sizeof(PAILLIER_CTX));
}

PAILLIER_CTX *PAILLIER_CTX_copy(PAILLIER_CTX *dest, PAILLIER_CTX *src)
{
    if (dest == NULL || src == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (dest == src)
        return dest;

    if (!PAILLIER_KEY_copy(dest->key, src->key))
        return NULL;

    return dest;
}

PAILLIER_CTX *PAILLIER_CTX_dup(PAILLIER_CTX *ctx)
{
    PAILLIER_CTX *ret = NULL;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->key = PAILLIER_KEY_dup(ctx->key);
    if (ret->key == NULL)
        goto err;

    return ret;
err:
    OPENSSL_free(ret);
    return NULL;
}
