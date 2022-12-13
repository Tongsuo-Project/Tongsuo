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

/** Creates a new PAILLIER object
 *  \param  key        PAILLIER_KEY to use
 *  \param  threshold  The threshold should be greater than the maximum integer
 *                     that will be encrypted.
 *  \return newly created PAILLIER_CTX object or NULL in case of an error
 */
PAILLIER_CTX *PAILLIER_CTX_new(PAILLIER_KEY *key, int64_t threshold)
{
    char tmp[20];
    PAILLIER_CTX *ctx = NULL;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!PAILLIER_KEY_up_ref(key))
        goto err;

    ctx->key = key;
    ctx->threshold = BN_new();
    if (ctx->threshold == NULL)
        goto err;

    memset(tmp, 0, sizeof(tmp));
    BIO_snprintf(tmp, sizeof(tmp), "%lld", (long long int)threshold);

    if (!BN_dec2bn(&ctx->threshold, (char *)tmp))
        goto err;

    return ctx;

err:
    OPENSSL_free(ctx);
    return NULL;
}

/** Frees a PAILLIER_CTX object
 *  \param  ctx  PAILLIER_CTX object to be freed
 */
void PAILLIER_CTX_free(PAILLIER_CTX *ctx)
{
    if (ctx == NULL)
        return;

    PAILLIER_KEY_free(ctx->key);
    BN_free(ctx->threshold);
    OPENSSL_clear_free((void *)ctx, sizeof(PAILLIER_CTX));
}

/** Copies a PAILLIER_KEY object.
 *  \param  dst  destination PAILLIER_KEY object
 *  \param  src  src PAILLIER_KEY object
 *  \return dst or NULL if an error occurred.
 */
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

/** Creates a new PAILLIER_KEY object and copies the content from src to it.
 *  \param  src  the source PAILLIER_KEY object
 *  \return newly created PAILLIER_KEY object or NULL if an error occurred.
 */
PAILLIER_CTX *PAILLIER_CTX_dup(PAILLIER_CTX *src)
{
    PAILLIER_CTX *ret = NULL;

    if (src == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->key = PAILLIER_KEY_dup(src->key);
    if (ret->key == NULL)
        goto err;

    return ret;
err:
    OPENSSL_free(ret);
    return NULL;
}

#ifndef OPENSSL_NO_ENGINE
/** set ENGINE pointer to the PAILLIER object
 *  \param  ctx        PAILLIER_CTX object.
 *  \param  engine     ENGINE object to use
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_CTX_set_engine(PAILLIER_CTX *ctx, ENGINE *engine)
{
# ifndef OPENSSL_NO_BN_METHOD
    ctx->engine = engine;
    return 1;
# else
    return 0;
# endif
}
#endif
