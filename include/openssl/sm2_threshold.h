/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OPENSSL_SM2_THRESHOLD_H
# define OPENSSL_SM2_THRESHOLD_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_SM2_THRESHOLD_H
# endif

# include <openssl/opensslconf.h>

# if !defined(OPENSSL_NO_SM2_THRESHOLD) && !defined(FIPS_MODULE)

#  include <openssl/ec.h>

#  ifdef __cplusplus
extern "C" {
#  endif

/********************************************************************/
/*               SM2 threshold struct and functions                 */
/********************************************************************/

/** Derives SM2 threshold partial public key from the private key
 *  \param  key         self private key
 *  \return EVP_PKEY object including partial public key on success or NULL on
 *  failure
 */
EVP_PKEY *SM2_THRESHOLD_derive_partial_pubkey(const EVP_PKEY *key);

/** Derives SM2 threshold complete public key from the private key key1 and
 * public key pubkey2 from another participant
 *  \param  self_key         self private key
 *  \param  peer_pubkey      partial public key from another participant
 *  \return EVP_PKEY object including complete public key or NULL on failure
 */
EVP_PKEY *SM2_THRESHOLD_derive_complete_pubkey(const EVP_PKEY *self_key,
                                               const EVP_PKEY *peer_pubkey);

/** 1st step of SM2 threshold signature, generates the message digest
 * \param pubkey        complete public key
 * \param type          the digest algorithm
 * \param id            userid to calculate digest
 * \param id_len        length of userid
 * \param msg           message to calculate digest
 * \param msg_len       length of message
 * \param digest        the output buffer of message digest
 * \param dlen          length of digest
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign1_oneshot(const EVP_PKEY *pubkey,
                                const EVP_MD *type,
                                const uint8_t *id,
                                const size_t id_len,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t *digest, size_t *dlen);
/** The 1st step of SM2 threshold signature, initialize the EVP_MD_CTX
 * \param ctx           EVP_MD_CTX object.
 * \param digest        the digest algorithm
 * \param pubkey        EVP_PKEY object including complete public key
 * \param id            userid to calculate digest
 * \param id_len        length of userid
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign1_init(EVP_MD_CTX *ctx, const EVP_MD *digest,
                             const EVP_PKEY *pubkey, const uint8_t *id,
                             const size_t id_len);
/** The 1st step of SM2 threshold signature, update the EVP_MD_CTX
 * \param ctx           EVP_MD_CTX object.
 * \param msg           message to calculate digest
 * \param msg_len       length of message
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign1_update(EVP_MD_CTX *ctx, const uint8_t *msg,
                               size_t msg_len);
/** The 1st step of SM2 threshold signature, finalize the EVP_MD_CTX
 * \param ctx           EVP_MD_CTX object.
 * \param digest        the output buffer of message digest
 * \param dlen          length of digest
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign1_final(EVP_MD_CTX *ctx, uint8_t *digest, size_t *dlen);
/** The 2nd step of SM2 threshold signature, generate the partial threshold signature
 * \param key           EVP_PKEY object
 * \param peer_Q1       the peer temporary public key
 * \param digest        the message digest generated in the 1st part of signature
 * \param dlen          length of digest
 * \param sig           output partial signature
 * \param siglen        length of sig
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign2(const EVP_PKEY *key, const EVP_PKEY *peer_Q1,
                        uint8_t *digest, size_t dlen, unsigned char **sig, size_t *siglen);
/** The 3rd step of SM2 threshold signature，generate the final threshold signature
 * \param key           EVP_PKEY object
 * \param temp_key      the temporary private key
 * \param sig2          the partial signature generated in the 2nd part of signature
 * \param sig2_len      length of sig2
 * \param sig           output final signature
 * \param siglen        length of sig
 * \return 1 on success and 0 if an error occurred.
 */
int SM2_THRESHOLD_sign3(const EVP_PKEY *key, const EVP_PKEY *temp_key,
                        const unsigned char *sig2, size_t sig2_len,
                        unsigned char **sig, size_t *siglen);

#  ifdef  __cplusplus
}
#  endif

# endif
#endif
