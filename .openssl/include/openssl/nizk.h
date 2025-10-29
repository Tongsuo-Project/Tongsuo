/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_NIZK_H
# define HEADER_NIZK_H

# include <stdlib.h>
# include <openssl/macros.h>
# include <openssl/opensslconf.h>
# include <openssl/types.h>
# include <openssl/pem.h>
# include <openssl/ec.h>
# include <openssl/safestack.h>
# include <openssl/zkp_transcript.h>
# include <openssl/zkpbperr.h>

# ifndef OPENSSL_NO_NIZK
#  ifdef  __cplusplus
extern "C" {
#  endif

STACK_OF(EC_POINT);

typedef struct nizk_pub_param_st                    NIZK_PUB_PARAM;
typedef struct nizk_witness_st                      NIZK_WITNESS;
typedef struct nizk_plaintext_knowledge_ctx_st      NIZK_PLAINTEXT_KNOWLEDGE_CTX;
typedef struct nizk_plaintext_knowledge_proof_st    NIZK_PLAINTEXT_KNOWLEDGE_PROOF;
typedef struct nizk_plaintext_equality_ctx_st       NIZK_PLAINTEXT_EQUALITY_CTX;
typedef struct nizk_plaintext_equality_proof_st     NIZK_PLAINTEXT_EQUALITY_PROOF;
typedef struct nizk_dlog_knowledge_ctx_st           NIZK_DLOG_KNOWLEDGE_CTX;
typedef struct nizk_dlog_knowledge_proof_st         NIZK_DLOG_KNOWLEDGE_PROOF;
typedef struct nizk_dlog_equality_ctx_st            NIZK_DLOG_EQUALITY_CTX;
typedef struct nizk_dlog_equality_proof_st          NIZK_DLOG_EQUALITY_PROOF;

NIZK_PUB_PARAM *NIZK_PUB_PARAM_new(const EC_GROUP *group, const EC_POINT *G,
                                   const EC_POINT *H);
void NIZK_PUB_PARAM_free(NIZK_PUB_PARAM *pp);
int NIZK_PUB_PARAM_up_ref(NIZK_PUB_PARAM *pp);
int NIZK_PUB_PARAM_down_ref(NIZK_PUB_PARAM *pp);
NIZK_WITNESS *NIZK_WITNESS_new(const NIZK_PUB_PARAM *pp, const BIGNUM *r,
                               const BIGNUM *v);
void NIZK_WITNESS_free(NIZK_WITNESS *witness);
int NIZK_WITNESS_up_ref(NIZK_WITNESS *witness);
int NIZK_WITNESS_down_ref(NIZK_WITNESS *witness);

NIZK_PLAINTEXT_KNOWLEDGE_CTX *NIZK_PLAINTEXT_KNOWLEDGE_CTX_new(ZKP_TRANSCRIPT *transcript,
                                                               NIZK_PUB_PARAM *pp,
                                                               NIZK_WITNESS *witness,
                                                               EC_POINT *pk,
                                                               EC_ELGAMAL_CIPHERTEXT *ct);
void NIZK_PLAINTEXT_KNOWLEDGE_CTX_free(NIZK_PLAINTEXT_KNOWLEDGE_CTX *ctx);
NIZK_PLAINTEXT_KNOWLEDGE_PROOF *NIZK_PLAINTEXT_KNOWLEDGE_PROOF_new(NIZK_PLAINTEXT_KNOWLEDGE_CTX *ctx);
void NIZK_PLAINTEXT_KNOWLEDGE_PROOF_free(NIZK_PLAINTEXT_KNOWLEDGE_PROOF *proof);
NIZK_PLAINTEXT_KNOWLEDGE_PROOF *NIZK_PLAINTEXT_KNOWLEDGE_PROOF_prove(NIZK_PLAINTEXT_KNOWLEDGE_CTX *ctx);
int NIZK_PLAINTEXT_KNOWLEDGE_PROOF_verify(NIZK_PLAINTEXT_KNOWLEDGE_CTX *ctx,
                                          NIZK_PLAINTEXT_KNOWLEDGE_PROOF *proof);

NIZK_PLAINTEXT_EQUALITY_CTX *NIZK_PLAINTEXT_EQUALITY_CTX_new(ZKP_TRANSCRIPT *transcript,
                                                             NIZK_PUB_PARAM *pp,
                                                             NIZK_WITNESS *witness,
                                                             STACK_OF(EC_POINT) *pk,
                                                             EC_ELGAMAL_MR_CIPHERTEXT *ct);
void NIZK_PLAINTEXT_EQUALITY_CTX_free(NIZK_PLAINTEXT_EQUALITY_CTX *ctx);
NIZK_PLAINTEXT_EQUALITY_PROOF *NIZK_PLAINTEXT_EQUALITY_PROOF_new(NIZK_PLAINTEXT_EQUALITY_CTX *ctx);
void NIZK_PLAINTEXT_EQUALITY_PROOF_free(NIZK_PLAINTEXT_EQUALITY_PROOF *proof);
NIZK_PLAINTEXT_EQUALITY_PROOF *NIZK_PLAINTEXT_EQUALITY_PROOF_prove(NIZK_PLAINTEXT_EQUALITY_CTX *ctx);
int NIZK_PLAINTEXT_EQUALITY_PROOF_verify(NIZK_PLAINTEXT_EQUALITY_CTX *ctx,
                                         NIZK_PLAINTEXT_EQUALITY_PROOF *proof);

NIZK_DLOG_KNOWLEDGE_CTX *NIZK_DLOG_KNOWLEDGE_CTX_new(ZKP_TRANSCRIPT *transcript,
                                                     NIZK_PUB_PARAM *pp,
                                                     NIZK_WITNESS *witness);
void NIZK_DLOG_KNOWLEDGE_CTX_free(NIZK_DLOG_KNOWLEDGE_CTX *ctx);
NIZK_DLOG_KNOWLEDGE_PROOF *NIZK_DLOG_KNOWLEDGE_PROOF_new(NIZK_DLOG_KNOWLEDGE_CTX *ctx);
void NIZK_DLOG_KNOWLEDGE_PROOF_free(NIZK_DLOG_KNOWLEDGE_PROOF *proof);
NIZK_DLOG_KNOWLEDGE_PROOF *NIZK_DLOG_KNOWLEDGE_PROOF_prove(NIZK_DLOG_KNOWLEDGE_CTX *ctx);
int NIZK_DLOG_KNOWLEDGE_PROOF_verify(NIZK_DLOG_KNOWLEDGE_CTX *ctx,
                                     NIZK_DLOG_KNOWLEDGE_PROOF *proof);

NIZK_DLOG_EQUALITY_CTX *NIZK_DLOG_EQUALITY_CTX_new(ZKP_TRANSCRIPT *transcript,
                                                   NIZK_PUB_PARAM *pp,
                                                   NIZK_WITNESS *witness,
                                                   const EC_POINT *G,
                                                   const EC_POINT *H);
void NIZK_DLOG_EQUALITY_CTX_free(NIZK_DLOG_EQUALITY_CTX *ctx);
NIZK_DLOG_EQUALITY_PROOF *NIZK_DLOG_EQUALITY_PROOF_new(NIZK_DLOG_EQUALITY_CTX *ctx);
void NIZK_DLOG_EQUALITY_PROOF_free(NIZK_DLOG_EQUALITY_PROOF *proof);
NIZK_DLOG_EQUALITY_PROOF *NIZK_DLOG_EQUALITY_PROOF_prove(NIZK_DLOG_EQUALITY_CTX *ctx);
int NIZK_DLOG_EQUALITY_PROOF_verify(NIZK_DLOG_EQUALITY_CTX *ctx, NIZK_DLOG_EQUALITY_PROOF *proof);

size_t NIZK_PUB_PARAM_encode(const NIZK_PUB_PARAM *pp, unsigned char *out, size_t size);
NIZK_PUB_PARAM *NIZK_PUB_PARAM_decode(const unsigned char *in, size_t size);
size_t NIZK_WITNESS_encode(const NIZK_WITNESS *witness, unsigned char *out,
                           size_t size, int flag);
NIZK_WITNESS *NIZK_WITNESS_decode(const unsigned char *in, size_t size, int flag);
size_t NIZK_PLAINTEXT_KNOWLEDGE_PROOF_encode(const NIZK_PLAINTEXT_KNOWLEDGE_PROOF *proof,
                                             unsigned char *out, size_t size);
NIZK_PLAINTEXT_KNOWLEDGE_PROOF *NIZK_PLAINTEXT_KNOWLEDGE_PROOF_decode(const unsigned char *in,
                                                                      size_t size);
size_t NIZK_PLAINTEXT_EQUALITY_PROOF_encode(const NIZK_PLAINTEXT_EQUALITY_PROOF *proof,
                                            unsigned char *out, size_t size);
NIZK_PLAINTEXT_EQUALITY_PROOF *NIZK_PLAINTEXT_EQUALITY_PROOF_decode(const unsigned char *in,
                                                                    size_t size);
size_t NIZK_DLOG_KNOWLEDGE_PROOF_encode(const NIZK_DLOG_KNOWLEDGE_PROOF *proof,
                                        unsigned char *out, size_t size);
NIZK_DLOG_KNOWLEDGE_PROOF *NIZK_DLOG_KNOWLEDGE_PROOF_decode(const unsigned char *in,
                                                            size_t size);
size_t NIZK_DLOG_EQUALITY_PROOF_encode(const NIZK_DLOG_EQUALITY_PROOF *proof,
                                       unsigned char *out, size_t size);
NIZK_DLOG_EQUALITY_PROOF *NIZK_DLOG_EQUALITY_PROOF_decode(const unsigned char *in,
                                                          size_t size);

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
