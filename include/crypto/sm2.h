/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM2_H
# define OSSL_CRYPTO_SM2_H
# pragma once

# include <openssl/opensslconf.h>

# if !defined(OPENSSL_NO_SM2) && !defined(FIPS_MODULE)

#  include <openssl/ec.h>
#  include "crypto/types.h"
# ifdef  __cplusplus
extern "C" {
# endif
    typedef struct SM2_Ciphertext_st SM2_Ciphertext;
    DECLARE_STATIC_ASN1_FUNCTIONS(SM2_Ciphertext)

    typedef struct SM2_CiphertextEx_st SM2_CiphertextEx;
    DECLARE_STATIC_ASN1_FUNCTIONS(SM2_CiphertextEx)

    /*described in section 7.4, GMT 0009/2014.*/
    typedef struct SM2_Enveloped_Key_st SM2_Enveloped_Key;
    DECLARE_STATIC_ASN1_FUNCTIONS(SM2_Enveloped_Key)

    BIO* SM2_Enveloped_Key_dataDecode(SM2_Enveloped_Key* sm2evpkey, EVP_PKEY* pkey);



    int SM2_Ciphertext_get0(const SM2_Ciphertext* cipher,
        const BIGNUM** pC1x, const BIGNUM** pC1y,
        const ASN1_OCTET_STRING** pC3, const ASN1_OCTET_STRING** pC2);

    const BIGNUM* SM2_Ciphertext_get0_C1x(const SM2_Ciphertext* cipher);

    const BIGNUM* SM2_Ciphertext_get0_C1y(const SM2_Ciphertext* cipher);

    const ASN1_OCTET_STRING* SM2_Ciphertext_get0_C3(const SM2_Ciphertext* cipher);

    const ASN1_OCTET_STRING* SM2_Ciphertext_get0_C2(const SM2_Ciphertext* cipher);

    int SM2_Ciphertext_set0(SM2_Ciphertext* cipher, BIGNUM* C1x, BIGNUM* C1y, ASN1_OCTET_STRING* C3, ASN1_OCTET_STRING* C2);

    int ossl_sm2_key_private_check(const EC_KEY* eckey);

    /* The default user id as specified in GM/T 0009-2012 */
#  define SM2_DEFAULT_USERID "1234567812345678"

int ossl_sm2_compute_z_digest(uint8_t *out,
                              const EVP_MD *digest,
                              const uint8_t *id,
                              size_t id_len,
                              const EC_KEY *key);
/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *ossl_sm2_do_sign(const EC_KEY *key,
                            const EVP_MD *digest,
                            const uint8_t *id,
                            const size_t id_len,
                            const uint8_t *msg, size_t msg_len);

    int ossl_sm2_do_verify(const EC_KEY* key,
        const EVP_MD* digest,
        const ECDSA_SIG* signature,
        const uint8_t* id,
        const size_t id_len,
        const uint8_t* msg, size_t msg_len);

    /*
     * SM2 signature generation.
     */
    int ossl_sm2_internal_sign(const unsigned char* dgst, int dgstlen,
        unsigned char* sig, unsigned int* siglen,
        EC_KEY* eckey);

    /*
     * SM2 signature verification.
     */
    int ossl_sm2_internal_verify(const unsigned char* dgst, int dgstlen,
        const unsigned char* sig, int siglen,
        EC_KEY* eckey);

    /*
     * SM2 encryption
     */
    int ossl_sm2_ciphertext_size(const EC_KEY* key, const EVP_MD* digest,
        size_t msg_len, size_t* ct_size);

    int ossl_sm2_plaintext_size(const unsigned char* ct, size_t ct_size,
        size_t* pt_size,int en);

    int ossl_sm2_encrypt(const EC_KEY* key,
        const EVP_MD* digest,
        const uint8_t* msg, size_t msg_len,
        uint8_t* ciphertext_buf, size_t* ciphertext_len, int encdata_format);

    int ossl_sm2_decrypt(const EC_KEY* key,
        const EVP_MD* digest,
        const uint8_t* ciphertext, size_t ciphertext_len,
        uint8_t* ptext_buf, size_t* ptext_len, int encdata_format);

int ossl_sm2_ciphertext_decode(const uint8_t *ciphertext, size_t ciphertext_len,
                               EC_POINT **C1p, uint8_t **C2p, size_t *C2_len,
                               uint8_t **C3p, size_t *C3_len);

const unsigned char *ossl_sm2_algorithmidentifier_encoding(int md_nid,
                                                           size_t *len);

    int SM2_compute_key(void* out, size_t outlen, int initiator,
        const uint8_t* peer_id, size_t peer_id_len,
        const uint8_t* self_id, size_t self_id_len,
        const EC_KEY* peer_ecdhe_key, const EC_KEY* self_ecdhe_key,
        const EC_KEY* peer_pub_key, const EC_KEY* self_eckey,
        const EVP_MD* md, OSSL_LIB_CTX* libctx,
        const char* propq);
# ifdef  __cplusplus
}
# endif
# endif /* OPENSSL_NO_SM2 */
#endif
