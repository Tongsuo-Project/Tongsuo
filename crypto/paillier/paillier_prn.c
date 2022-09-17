/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/paillier.h>
#include "paillier_local.h"

#ifndef OPENSSL_NO_STDIO
int PAILLIER_KEY_print_fp(FILE *fp, const PAILLIER_KEY *key, int off)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_PAILLIER, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PAILLIER_KEY_print(b, key, off);
    BIO_free(b);
    return ret;
}
#endif

int PAILLIER_KEY_print(BIO *bp, const PAILLIER_KEY *key, int off)
{
    int ret = 0, is_pub = 1;

    if (key == NULL)
        return 0;

    if (key->p && key->q && key->lambda && key->u) {
        is_pub = 0;
        BIO_printf(bp, "Paillier Private Key: \n");
    } else {
        BIO_printf(bp, "Paillier Public Key: \n");
    }

    if (!ASN1_bn_print(bp, "n:", key->n, NULL, off))
        goto end;

    if (!ASN1_bn_print(bp, "g:", key->g, NULL, off))
        goto end;

    if (!is_pub) {
        if (!ASN1_bn_print(bp, "p:", key->p, NULL, off))
            goto end;

        if (!ASN1_bn_print(bp, "q:", key->q, NULL, off))
            goto end;

        if (!ASN1_bn_print(bp, "lambda:", key->lambda, NULL, off))
            goto end;

        if (!ASN1_bn_print(bp, "u:", key->u, NULL, off))
            goto end;
    }

    ret = 1;
end:
    return ret;
}
