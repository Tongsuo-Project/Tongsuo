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

/** Creates a new PAILLIER_CIPHERTEXT object for paillier oparations
 *  \param  ctx        PAILLIER_CTX object
 *  \return newly created PAILLIER_CIPHERTEXT object or NULL in case of an error
 */
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

/** Frees a PAILLIER_CIPHERTEXT object
 *  \param  ciphertext  PAILLIER_CIPHERTEXT object to be freed
 */
void PAILLIER_CIPHERTEXT_free(PAILLIER_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    BN_free(ciphertext->data);
    OPENSSL_clear_free((void *)ciphertext, sizeof(PAILLIER_CIPHERTEXT));
}

/** Encodes PAILLIER_CIPHERTEXT to binary
 *  \param  ctx        PAILLIER_CTX object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  ciphertext PAILLIER_CIPHERTEXT object
 *  \param  compressed Whether to compress the encoding (either 0 or 1)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
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

    len = BN_num_bytes(ciphertext->data);

    if (out == NULL)
        return len;

    if (size < len)
        goto end;

    if (!BN_bn2bin(ciphertext->data, out))
        goto end;

    ret = len;

end:
    return ret;
}

/** Decodes binary to PAILLIER_CIPHERTEXT
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded PAILLIER_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_CIPHERTEXT_decode(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                               unsigned char *in, size_t size)
{
    if (ctx == NULL || ctx->key == NULL || r == NULL || r->data == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (!BN_bin2bn(in, (int)size, r->data))
        return 0;

    return 1;
}
