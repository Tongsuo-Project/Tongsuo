/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"
#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/paillier.h>
#include "paillier_local.h"

static int paillier_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                       void *exarg)
{
    PAILLIER_KEY *key;
    BN_CTX *bn_ctx = NULL;

    if (operation == ASN1_OP_NEW_PRE) {
        *pval = (ASN1_VALUE *)PAILLIER_KEY_new();
        if (*pval != NULL)
            return 2;
        return 0;
    } else if (operation == ASN1_OP_FREE_PRE) {
        PAILLIER_KEY_free((PAILLIER_KEY *)*pval);
        *pval = NULL;
        return 2;
    } else if (operation == ASN1_OP_D2I_POST) {
        key = (PAILLIER_KEY *)*pval;
        if (key->version != PAILLIER_ASN1_VERSION_MULTI) {
            bn_ctx = BN_CTX_new();
            if (bn_ctx == NULL)
                return 0;

            if (!BN_sqr(key->n_square, key->n, bn_ctx)) {
                BN_CTX_free(bn_ctx);
                return 0;
            }

            BN_CTX_free(bn_ctx);
            return 1;
        }
        return (ossl_paillier_multip_calc_product((PAILLIER_KEY *)*pval) == 1) ? 2 : 0;
    }
    return 1;
}

ASN1_SEQUENCE_cb(PAILLIER_PrivateKey, paillier_cb) = {
        ASN1_EMBED(PAILLIER_KEY, version, INT32),
        ASN1_SIMPLE(PAILLIER_KEY, n, BIGNUM),
        ASN1_SIMPLE(PAILLIER_KEY, p, CBIGNUM),
        ASN1_SIMPLE(PAILLIER_KEY, q, CBIGNUM),
        ASN1_SIMPLE(PAILLIER_KEY, g, CBIGNUM),
        ASN1_SIMPLE(PAILLIER_KEY, lambda, CBIGNUM),
        ASN1_SIMPLE(PAILLIER_KEY, u, CBIGNUM),
} static_ASN1_SEQUENCE_END_cb(PAILLIER_KEY, PAILLIER_PrivateKey)

ASN1_SEQUENCE_cb(PAILLIER_PublicKey, paillier_cb) = {
        ASN1_SIMPLE(PAILLIER_KEY, n, BIGNUM),
        ASN1_SIMPLE(PAILLIER_KEY, g, CBIGNUM),
} static_ASN1_SEQUENCE_END_cb(PAILLIER_KEY, PAILLIER_PublicKey)

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(PAILLIER_KEY, PAILLIER_PrivateKey, PAILLIER_PrivateKey)
IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(PAILLIER_KEY, PAILLIER_PublicKey, PAILLIER_PublicKey)

IMPLEMENT_PEM_rw(PAILLIER_PrivateKey, PAILLIER_KEY, PEM_STRING_PAILLIER_PRIVATE_KEY, PAILLIER_PrivateKey)
IMPLEMENT_PEM_rw(PAILLIER_PublicKey, PAILLIER_KEY, PEM_STRING_PAILLIER_PUBLIC_KEY, PAILLIER_PublicKey)
