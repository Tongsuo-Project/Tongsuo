/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/e_os2.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/x509.h"
#include "crypto/sm2_mldsa65_hybrid.h"

static const uint8_t sm2_mldsa65_hybrid_spkifmt[SM2_MLDSA_HYBRID_SPKI_OVERHEAD] = {
    0x30, 0x82, 0x07, 0xd5, 0x30, 0x0d, 0x06, 0x0b, 0x60, 0x86, 0x48, 0x01,
    0x86, 0xfa, 0x6b, 0x50, 0x09, 0x01, 0x15, 0x03, 0x82, 0x07, 0xc2, 0x00
};

SM2_MLDSA65_HYBRID_KEY *ossl_sm2_mldsa65_hybrid_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                             OSSL_LIB_CTX *libctx, const char *propq)
{
    SM2_MLDSA65_HYBRID_KEY *key = NULL, *ret = NULL;
    const uint8_t *buf;
    int len;
    const X509_ALGOR *palg;

    if (!PKCS8_pkey_get0(NULL, &buf, &len, &palg, p8inf))
        goto err;

    if ((key = sm2_mldsa65_hybrid_key_new(libctx, propq)) == NULL)
        goto err;

    if (!sm2_mldsa65_hybrid_priv_key_deserialize(key, buf, len))
        goto err;

    ret = key;
err:
    if (ret == NULL)
        sm2_mldsa65_hybrid_key_free(key);
    return ret;
}

SM2_MLDSA65_HYBRID_KEY *
ossl_sm2_mldsa65_hybrid_d2i_PUBKEY(const uint8_t *pk, int pk_len, OSSL_LIB_CTX *libctx)
{
    SM2_MLDSA65_HYBRID_KEY *ret;

    if (pk_len != SM2_MLDSA_HYBRID_SPKI_OVERHEAD + (ossl_ssize_t) SM2_MLDSA65_HYBRID_PK_SIZE
        || memcmp(pk, sm2_mldsa65_hybrid_spkifmt, SM2_MLDSA_HYBRID_SPKI_OVERHEAD) != 0)
        return NULL;
    pk_len -= SM2_MLDSA_HYBRID_SPKI_OVERHEAD;
    pk += SM2_MLDSA_HYBRID_SPKI_OVERHEAD;

    if ((ret = sm2_mldsa65_hybrid_key_new(libctx, NULL)) == NULL)
        return NULL;

    if (!sm2_mldsa65_hybrid_pub_key_deserialize(ret, pk, (size_t)pk_len)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
                       "error parsing sm2-mldsa65-hybrid public key from input SPKI");
        sm2_mldsa65_hybrid_key_free(ret);
        return NULL;
    }

    return ret;
}
