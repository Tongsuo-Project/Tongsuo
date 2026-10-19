/*
 * Copyright 2023-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SM4TH_H
# define OSSL_CRYPTO_SM4TH_H
# pragma once

# include <openssl/e_os2.h>
# include <openssl/types.h>
# include <stddef.h>

# ifdef __cplusplus
extern "C" {
# endif

/* Operating on one SM4 block/key of 128 bits. */
# define SM4TH_128_BYTES 16

/* Raw key blob sizes: pk = p || c, sk = p || k. */
# define SM4TH_PK_BYTES (2 * SM4TH_128_BYTES)
# define SM4TH_SK_BYTES (2 * SM4TH_128_BYTES)

/*
 * Active SM4-in-the-Head parameter sets, matching the NGCC submission
 * (Chinith) instances sm4th_f ("fast") and sm4th_s ("small").
 *
 *   sm4th_f : keygen/sign/verify at tau = 16, signature 6724 bytes
 *   sm4th_s : keygen/sign/verify at tau = 11, signature 5056 bytes
 */
# define SN_sm4th_f        "SM4TH-F"
# define LN_sm4th_f        "SM4-in-the-Head-F"
# define SN_sm4th_s        "SM4TH-S"
# define LN_sm4th_s        "SM4-in-the-Head-S"

# define SM4TH_VARIANT_F        0
# define SM4TH_VARIANT_S        1

/*
 * Signing seed length: both SM4th-f and SM4th-s use a 32-byte seed
 * (see SM4th.Sign). Deprecated aliases kept for existing call sites.
 */
# define SM4TH_SEED_BYTES       32
# define SM4TH_F_RANDLEN_BYTES  SM4TH_SEED_BYTES
# define SM4TH_S_RANDLEN_BYTES  SM4TH_SEED_BYTES

typedef struct sm4th_key_st SM4TH_KEY;

/*
 *-----------------------------------------------------------------------------
 * The API below is the internal interface that the SM4th signature
 * provider (providers/implementations/signature/sm4th.c, to be added in a
 * follow-up change) is expected to call:
 *
 *  - keygen  : tons_sm4th_key_new + tons_sm4th_generate_key
 *  - import  : tons_sm4th_key_set_pk / tons_sm4th_key_set_sk
 *  - export  : tons_sm4th_key_get_pk (+ sk access, see below)
 *  - digest/sign/verify       : tons_sm4th_sign / tons_sm4th_verify
 *  - pairwise check (keytest) : tons_sm4th_key_pairwise_check
 *-----------------------------------------------------------------------------
 */

/* Key management ---------------------------------------------------------- */

SM4TH_KEY *tons_sm4th_key_new(OSSL_LIB_CTX *libctx, const char *propq,
                                int variant);
void tons_sm4th_key_free(SM4TH_KEY *key);
int tons_sm4th_generate_key(SM4TH_KEY *key);
int tons_sm4th_key_set_pk(SM4TH_KEY *key, const unsigned char *pk,
                           size_t pklen);
int tons_sm4th_key_set_sk(SM4TH_KEY *key, const unsigned char *sk,
                           size_t sklen);
int tons_sm4th_key_get_pk(const SM4TH_KEY *key, unsigned char *pk,
                           size_t pklen);
int tons_sm4th_key_get_sk(const SM4TH_KEY *key, unsigned char *sk,
                           size_t sklen);
int tons_sm4th_key_has_private(const SM4TH_KEY *key);
int tons_sm4th_key_pairwise_check(const SM4TH_KEY *key);
OSSL_LIB_CTX *tons_sm4th_key_get0_libctx(SM4TH_KEY *key);
int tons_sm4th_key_get_variant(const SM4TH_KEY *key);
const char *tons_sm4th_key_get_name(const SM4TH_KEY *key);
size_t tons_sm4th_key_get_sig_len(const SM4TH_KEY *key);
size_t tons_sm4th_key_get_randomness_len(const SM4TH_KEY *key);

/* Name/params helpers (also usable from the provider core). */
const char *tons_sm4th_variant_name(int variant);

/* Signature operations ----------------------------------------------------- */

/*
 * Deterministic signing from sk only: seed must be SM4TH_SEED_BYTES.
 * A provider sources seed from its libctx RAND before calling in.
 * Uses Chinese specification v1 domains (SM4th-v1/f or SM4th-v1/s).
 * Raw key formats are unchanged; signatures from the earlier untagged
 * protocol are incompatible. The verifier does not fall back to that protocol.
 */
int tons_sm4th_sign(const SM4TH_KEY *key, const unsigned char *msg,
                     size_t msglen, const unsigned char *seed, size_t seedlen,
                     unsigned char *sig, size_t *siglen);
int tons_sm4th_verify(const SM4TH_KEY *key, const unsigned char *msg,
                       size_t msglen, const unsigned char *sig,
                       size_t siglen);

# ifdef __cplusplus
}
# endif

#endif /* OSSL_CRYPTO_SM4TH_H */
