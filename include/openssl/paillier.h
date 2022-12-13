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

# define PAILLIER_FLAG_G_OPTIMIZE             0x01

# define PAILLIER_KEY_TYPE_PUBLIC             0
# define PAILLIER_KEY_TYPE_PRIVATE            1

# define PAILLIER_MAX_THRESHOLD               ((((uint64_t)1) << 63) - 1)

typedef struct paillier_key_st PAILLIER_KEY;
typedef struct paillier_ctx_st PAILLIER_CTX;
typedef struct paillier_ciphertext_st PAILLIER_CIPHERTEXT;

DECLARE_PEM_rw(PAILLIER_PrivateKey, PAILLIER_KEY)
DECLARE_PEM_rw(PAILLIER_PublicKey, PAILLIER_KEY)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(PAILLIER_KEY, PAILLIER_PrivateKey)
DECLARE_ASN1_ENCODE_FUNCTIONS_only(PAILLIER_KEY, PAILLIER_PublicKey)

/**
 *  Creates a new PAILLIER_KEY object.
 *  \return PAILLIER_KEY object or NULL if an error occurred.
 */
PAILLIER_KEY *PAILLIER_KEY_new(void);

/** Frees a PAILLIER_KEY object.
 *  \param  key  PAILLIER_KEY object to be freed.
 */
void PAILLIER_KEY_free(PAILLIER_KEY *key);

/** Copies a PAILLIER_KEY object.
 *  \param  dst  destination PAILLIER_KEY object
 *  \param  src  src PAILLIER_KEY object
 *  \return dst or NULL if an error occurred.
 */
PAILLIER_KEY *PAILLIER_KEY_copy(PAILLIER_KEY *dest, PAILLIER_KEY *src);

/** Creates a new PAILLIER_KEY object and copies the content from src to it.
 *  \param  src  the source PAILLIER_KEY object
 *  \return newly created PAILLIER_KEY object or NULL if an error occurred.
 */
PAILLIER_KEY *PAILLIER_KEY_dup(PAILLIER_KEY *key);

/** Increases the internal reference count of a PAILLIER_KEY object.
 *  \param  key  PAILLIER_KEY object
 *  \return 1 on success and 0 if an error occurred.
 */
int PAILLIER_KEY_up_ref(PAILLIER_KEY *key);

/** Creates a new paillier private (and optional a new public) key.
 *  \param  key  PAILLIER_KEY object
 *  \param  bits use BN_generate_prime_ex() to generate a pseudo-random prime number
 *  of bit length
 *  \return 1 on success and 0 if an error occurred.
 */
int PAILLIER_KEY_generate_key(PAILLIER_KEY *key, int bits);

/** Returns the type of the PAILLIER_KEY.
 *  \param  key  PAILLIER_KEY object
 *  \return PAILLIER_KEY_TYPE_PRIVATE or PAILLIER_KEY_TYPE_PUBLIC.
 */
int PAILLIER_KEY_type(PAILLIER_KEY *key);

/** Encrypts an Integer with additadive homomorphic Paillier
 *  \param  ctx        PAILLIER_CTX object.
 *  \param  r          PAILLIER_CIPHERTEXT object that stores the result of
 *                     the encryption
 *  \param  m          The plaintext integer to be encrypted
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_encrypt(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *out, int32_t m);

/** Decrypts the ciphertext
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          The resulting plaintext integer
 *  \param  c          PAILLIER_CIPHERTEXT object to be decrypted
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_decrypt(PAILLIER_CTX *ctx, int32_t *out, PAILLIER_CIPHERTEXT *c);

/** Adds two paillier ciphertext and stores it in r:
 *  E(r) = E(c1 + c2) = E(c1) * E(c2)
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          The PAILLIER_CIPHERTEXT object that stores the addition
 *                     result
 *  \param  c1         PAILLIER_CIPHERTEXT object
 *  \param  c2         PAILLIER_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_add(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c1, PAILLIER_CIPHERTEXT *c2);

/** Add a paillier ciphertext to a plaintext, and stores it in r:
 *  E(r) = E(c1 + m) = E(c1) * g^m
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          The PAILLIER_CIPHERTEXT object that stores the addition
 *                     result
 *  \param  c1         PAILLIER_CIPHERTEXT object
 *  \param  m          The plaintext integer to be added
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_add_plain(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                       PAILLIER_CIPHERTEXT *c1, int32_t m);

/** Substracts two paillier ciphertext and stores it in r:
 *  E(r) = E(c1 - c2) = E(c1) * E(-c2) = E(c1) / E(c2)
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          The PAILLIER_CIPHERTEXT object that stores the
 *                     subtraction result
 *  \param  c1         PAILLIER_CIPHERTEXT object
 *  \param  c2         PAILLIER_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_sub(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c1, PAILLIER_CIPHERTEXT *c2);

/** Ciphertext multiplication, computes E(r) = E(c * m) = E(c) ^ m
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          The PAILLIER_CIPHERTEXT object that stores the
 *                     multiplication result
 *  \param  c1         PAILLIER_CIPHERTEXT object
 *  \param  m          The plaintext integer to be multiplied
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_mul(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                 PAILLIER_CIPHERTEXT *c, int32_t m);

/** Creates a new PAILLIER object
 *  \param  key        PAILLIER_KEY to use
 *  \param  threshold  The threshold should be greater than the maximum integer
 *                     that will be encrypted.
 *  \return newly created PAILLIER_CTX object or NULL in case of an error
 */
PAILLIER_CTX *PAILLIER_CTX_new(PAILLIER_KEY *key, int64_t threshold);

/** Frees a PAILLIER_CTX object
 *  \param  ctx  PAILLIER_CTX object to be freed
 */
void PAILLIER_CTX_free(PAILLIER_CTX *ctx);

/** Copies a PAILLIER_KEY object.
 *  \param  dst  destination PAILLIER_KEY object
 *  \param  src  src PAILLIER_KEY object
 *  \return dst or NULL if an error occurred.
 */
PAILLIER_CTX *PAILLIER_CTX_copy(PAILLIER_CTX *dest, PAILLIER_CTX *src);

/** Creates a new PAILLIER_KEY object and copies the content from src to it.
 *  \param  src  the source PAILLIER_KEY object
 *  \return newly created PAILLIER_KEY object or NULL if an error occurred.
 */
PAILLIER_CTX *PAILLIER_CTX_dup(PAILLIER_CTX *src);

#ifndef OPENSSL_NO_ENGINE
/** set ENGINE pointer to the PAILLIER object
 *  \param  ctx        PAILLIER_CTX object.
 *  \param  engine     ENGINE object to use
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_CTX_set_engine(PAILLIER_CTX *ctx, ENGINE *engine);
#endif

/** Creates a new PAILLIER_CIPHERTEXT object for paillier oparations
 *  \param  ctx        PAILLIER_CTX object
 *  \return newly created PAILLIER_CIPHERTEXT object or NULL in case of an error
 */
PAILLIER_CIPHERTEXT *PAILLIER_CIPHERTEXT_new(PAILLIER_CTX *ctx);

/** Frees a PAILLIER_CIPHERTEXT object
 *  \param  ciphertext  PAILLIER_CIPHERTEXT object to be freed
 */
void PAILLIER_CIPHERTEXT_free(PAILLIER_CIPHERTEXT *ciphertext);

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
                                  int flag);

/** Decodes binary to PAILLIER_CIPHERTEXT
 *  \param  ctx        PAILLIER_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded PAILLIER_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int PAILLIER_CIPHERTEXT_decode(PAILLIER_CTX *ctx, PAILLIER_CIPHERTEXT *r,
                               unsigned char *in, size_t size);

int PAILLIER_KEY_print_fp(FILE *fp, const PAILLIER_KEY *key, int indent);
int PAILLIER_KEY_print(BIO *bp, const PAILLIER_KEY *key, int indent);

# ifdef  __cplusplus
}
# endif
# endif

#endif
