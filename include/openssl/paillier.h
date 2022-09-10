/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_PAILLIER_H
# define HEADER_PAILLIER_H

# include <stdlib.h>
# include <openssl/macros.h>
# include <openssl/opensslconf.h>
# include <openssl/pem.h>
# include <openssl/bn.h>

# ifndef OPENSSL_NO_PAILLIER
# ifdef  __cplusplus
extern "C" {
# endif

# define PEM_STRING_PAILLIER_PRIVATE_KEY      "PAILLIER PRIVATE KEY"
# define PEM_STRING_PAILLIER_PUBLIC_KEY       "PAILLIER PUBLIC KEY"

# define PAILLIER_ASN1_VERSION_DEFAULT        0
# define PAILLIER_ASN1_VERSION_MULTI          1

typedef struct paillier_key_st PAILLIER_KEY;
typedef struct paillier_ctx_st PAILLIER_CTX;
typedef struct paillier_ciphertext_st PAILLIER_CIPHERTEXT;

DECLARE_PEM_rw(PAILLIER_PrivateKey, PAILLIER_KEY)
DECLARE_PEM_rw(PAILLIER_PublicKey, PAILLIER_KEY)

PAILLIER_KEY *PAILLIER_KEY_new();
void PAILLIER_KEY_free(PAILLIER_KEY *key);
PAILLIER_KEY *PAILLIER_KEY_copy(PAILLIER_KEY *dest, PAILLIER_KEY *src);
PAILLIER_KEY *PAILLIER_KEY_dup(PAILLIER_KEY *key);
int PAILLIER_KEY_up_ref(PAILLIER_KEY *key);
int PAILLIER_KEY_generate_key(PAILLIER_KEY *key, int strength);

int PAILLIER_encrypt(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *out, int32_t m);
int PAILLIER_decrypt(PAILLIER_CTX *ctx, int32_t *out, PAILLIER_CIPHERTEXT *c);
int PAILLIER_add(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c1, PAILLIER_CIPHERTEXT *c2);
int PAILLIER_add_plain(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                       PAILLIER_CIPHERTEXT *c1, int32_t m);
int PAILLIER_sub(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c1, PAILLIER_CIPHERTEXT *c2);
int PAILLIER_mul(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c, int32_t m);

PAILLIER_CTX *PAILLIER_CTX_new(PAILLIER_KEY *key);
void PAILLIER_CTX_free(PAILLIER_CTX *ctx);
PAILLIER_CTX *PAILLIER_CTX_copy(PAILLIER_CTX *dest, PAILLIER_CTX *src);
PAILLIER_CTX *PAILLIER_CTX_dup(PAILLIER_CTX *ctx);

PAILLIER_CIPHERTEXT *PAILLIER_CIPHERTEXT_new(PAILLIER_CTX *ctx);
void PAILLIER_CIPHERTEXT_free(PAILLIER_CIPHERTEXT *ciphertext);
size_t PAILLIER_CIPHERTEXT_encode(PAILLIER_CTX *ctx, unsigned char *out,
                                  size_t size,
                                  const PAILLIER_CIPHERTEXT *ciphertext,
                                  int flag);
int PAILLIER_CIPHERTEXT_decode(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                               unsigned char *in, size_t size);

# ifdef  __cplusplus
}
# endif
# endif

#endif
