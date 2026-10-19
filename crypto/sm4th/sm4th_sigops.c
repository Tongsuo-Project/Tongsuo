/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Bridges the Tongsuo SM4TH_KEY layer onto the aux-notes core
 * (sm4th_core_* in sign.c).
 */
#include "sm4th_sigops.h"

#include "blockcipher.h"
#include "sign.h"

#include <openssl/crypto.h>

#include <string.h>

#define PK_INPUT(pk)  (pk)
#define PK_OUTPUT(pk) ((pk) + 16)
#define SK_INPUT(sk)  (sk)
#define SK_KEY(sk)    ((sk) + 16)

int sm4th_keygen(const params_t *params, uint8_t *pk, uint8_t *sk,
                 const uint8_t *sk_key, const uint8_t *sk_input)
{
    if (params == NULL || pk == NULL || sk == NULL
        || sk_key == NULL || sk_input == NULL || !sm4th_key_is_valid(sk_key))
        return -1;

    memcpy(SK_KEY(sk), sk_key, 16);
    memcpy(SK_INPUT(sk), sk_input, 16);
    sm4_enc(SK_KEY(sk), SK_INPUT(sk), PK_OUTPUT(pk));
    memcpy(PK_INPUT(pk), SK_INPUT(sk), 16);
    return 0;
}

int sm4th_validate(const params_t *params, const uint8_t *pk,
                   const uint8_t *sk)
{
    uint8_t pk_check[SM4TH_PK_BYTES];
    int ok;

    if (params == NULL || sk == NULL || pk == NULL)
        return -1;

    /* Witness bit rule on k0^FK0 (same as core KeyGen). */
    if (!sm4th_key_is_valid(SK_KEY(sk)))
        return 1;

    sm4_enc(SK_KEY(sk), SK_INPUT(sk), PK_OUTPUT(pk_check));
    memcpy(PK_INPUT(pk_check), SK_INPUT(sk), 16);
    ok = CRYPTO_memcmp(pk_check, pk, SM4TH_PK_BYTES) == 0;
    OPENSSL_cleanse(pk_check, sizeof(pk_check));
    return ok ? 0 : 2;
}

int sm4th_sign(const params_t *params, const EVP_MD *shake128_md,
               const uint8_t *sk,
               const uint8_t *msg, size_t msglen,
               const uint8_t *seed, size_t seedlen,
               uint8_t *sig, size_t *siglen)
{
    if (params == NULL || shake128_md == NULL || sk == NULL
        || sig == NULL || siglen == NULL
        || *siglen < (size_t)params->sig_len
        || (!msg && msglen)
        || seed == NULL || seedlen != SM4TH_SEED_BYTES)
        return -1;

    if (sm4th_core_sign(params, shake128_md, msg, msglen, sk, seed, sig) != 0)
        return -1;
    *siglen = (size_t)params->sig_len;
    return 0;
}

int sm4th_verify(const params_t *params, const EVP_MD *shake128_md,
                 const uint8_t *pk, size_t pklen,
                 const uint8_t *msg, size_t msglen,
                 const uint8_t *sig, size_t siglen)
{
    if (params == NULL || shake128_md == NULL || pk == NULL || sig == NULL
        || pklen != SM4TH_PK_BYTES
        || siglen != (size_t)params->sig_len
        || (!msg && msglen)
        || msglen > SM4TH_MAX_MSG)
        return -1;

    /* Core returns 1 accept / 0 reject; bak layer wants 0 success. */
    return sm4th_core_verify(params, shake128_md, msg, msglen,
                             pk, pklen, sig, siglen) == 1
               ? 0 : -1;
}
