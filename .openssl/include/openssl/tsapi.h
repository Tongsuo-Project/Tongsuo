/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef TONGSUO_API_H
# define TONGSUO_API_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_TSAPI_H
# endif

# include <stddef.h>
# include <openssl/opensslconf.h>
# include <openssl/evp.h>
# include <openssl/sdf.h>

# ifdef  __cplusplus
extern "C" {
# endif

unsigned char *TSAPI_GetEntropy(int entropy, size_t *outlen);
void TSAPI_FreeEntropy(unsigned char *ent, size_t len);
char *TSAPI_Version(void);
unsigned char *TSAPI_RandBytes(size_t len);

# ifndef OPENSSL_NO_SM2
EVP_PKEY *TSAPI_SM2Keygen(void);
#  ifndef OPENSSL_NO_SM3
unsigned char *TSAPI_SM2Sign(EVP_PKEY *key, const unsigned char *tbs,
                             size_t tbslen, size_t *siglen);
int TSAPI_SM2Verify(EVP_PKEY *key, const unsigned char *tbs, size_t tbslen,
                    const unsigned char *sig, size_t siglen);
#  endif
unsigned char *TSAPI_SM2Encrypt(EVP_PKEY *key, const unsigned char *in,
                                size_t inlen, size_t *outlen);
unsigned char *TSAPI_SM2Decrypt(EVP_PKEY *key, const unsigned char *in,
                                size_t inlen, size_t *outlen);
unsigned char *TSAPI_SM2EncryptWithISK(int isk, const unsigned char *in,
                                       size_t inlen, size_t *outlen);
unsigned char *TSAPI_SM2DecryptWithISK(int isk, const unsigned char *in,
                                       size_t inlen, size_t *outlen);
unsigned char *TSAPI_ECCCipher_to_SM2Ciphertext(const OSSL_ECCCipher *ecc,
                                                size_t *ciphertext_len);
OSSL_ECCCipher *TSAPI_SM2Ciphertext_to_ECCCipher(const unsigned char *ciphertext,
                                                 size_t ciphertext_len);
int TSAPI_ImportSM2Key(int index, int sign, const char *user,
                       const char *password, const EVP_PKEY *sm2_pkey);
OSSL_ECCrefPublicKey *TSAPI_EVP_PKEY_get_ECCrefPublicKey(const EVP_PKEY *pkey);
OSSL_ECCrefPrivateKey *TSAPI_EVP_PKEY_get_ECCrefPrivateKey(const EVP_PKEY *pkey);
EVP_PKEY *TSAPI_ExportSM2KeyWithIndex(int index, int sign, const char *user,
                                      const char *password);
EVP_PKEY *TSAPI_EVP_PKEY_new_from_ECCrefKey(const OSSL_ECCrefPublicKey *pubkey,
                                            const OSSL_ECCrefPrivateKey *privkey);
int TSAPI_ImportSM2KeyWithEvlp(int index, int sign, const char *user,
                               const char *password, unsigned char *key,
                               size_t keylen, unsigned char *dek,
                               size_t deklen);
int TSAPI_ExportSM2KeyWithEvlp(int index, int sign, const char *user,
                               const char *password, EVP_PKEY *sm2_pubkey,
                               unsigned char **priv, size_t *privlen,
                               unsigned char **pub, size_t *publen,
                               unsigned char **outevlp, size_t *outevlplen);
int TSAPI_GenerateSM2KeyWithIndex(int index, int sign, const char *user, const char *password);
int TSAPI_DelSm2KeyWithIndex(int index, int sign, const char *user,
                                const char *password);
int TSAPI_UpdateSm2KeyWithIndex(int index, int sign, const char *user,
                                const char *password);
EVP_PKEY *TSAPI_ExportSM2PubKeyWithIndex(int index, int sign);
# endif

# ifndef OPENSSL_NO_SM4
unsigned char *TSAPI_SM4Encrypt(int mode, const unsigned char *key,
                                size_t keylen, int isk,
                                const unsigned char *iv,
                                const unsigned char *in, size_t inlen,
                                size_t *outlen);
unsigned char *TSAPI_SM4Decrypt(int mode, const unsigned char *key,
                                size_t keylen, int isk,
                                const unsigned char *iv,
                                const unsigned char *in, size_t inlen,
                                size_t *outlen);
# endif
# ifndef OPENSSL_NO_SM3
unsigned char *TSAPI_SM3(const void *data, size_t datalen, size_t *outlen);
# endif

# ifdef  __cplusplus
}
# endif

#endif
