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

PAILLIER_CIPHERTEXT *PAILLIER_CIPHERTEXT_new(PAILLIER_CTX *ctx)
{
    PAILLIER_CIPHERTEXT *ciphertext = NULL;

    ciphertext = OPENSSL_zalloc(sizeof(*ciphertext));
    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ciphertext->data = BN_new();
    if (ciphertext->data == NULL)
        goto err;

    return ciphertext;
err:
    OPENSSL_free(ciphertext);
    return NULL;
}

void PAILLIER_CIPHERTEXT_free(PAILLIER_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    BN_free(ciphertext->data);
    OPENSSL_clear_free((void *)ciphertext, sizeof(PAILLIER_CIPHERTEXT));
}

size_t PAILLIER_CIPHERTEXT_encode(PAILLIER_CTX *ctx, unsigned char *out,
                                  size_t size,
                                  const PAILLIER_CIPHERTEXT *ciphertext,
                                  int flag)
{
    size_t ret = 0, len;

    if (ctx == NULL || ctx->key == NULL
        || ciphertext == NULL || ciphertext->data == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    len = BN_num_bytes(ciphertext->data) + 1;

    if (out == NULL)
        return len;

    if (size < len)
        goto end;

    *out++ = BN_is_negative(ciphertext->data) ? '1' : '0';

    if (!BN_bn2bin(ciphertext->data, out))
        goto end;

    ret = len;

end:
    return ret;
}

int PAILLIER_CIPHERTEXT_decode(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                               unsigned char *in, size_t size)
{
    int is_negative = 0;

    if (ctx == NULL || ctx->key == NULL || r == NULL || r->data == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    is_negative = (*in == '1' ? 1 : 0);

    in++;
    size--;

    if (!BN_bin2bn(in, (int)size, r->data))
        return 0;

    BN_set_negative(r->data, is_negative);

    return 1;
}
