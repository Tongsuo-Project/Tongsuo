/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_ZKP_GADGET_H
# define HEADER_ZKP_GADGET_H

# include <stdlib.h>
# include <openssl/macros.h>
# include <openssl/opensslconf.h>
# include <openssl/types.h>
# include <openssl/zkpbperr.h>
# include <openssl/ec.h>
# include <openssl/zkp_transcript.h>
# include <openssl/bulletproofs.h>

# ifndef OPENSSL_NO_ZKP_GADGET
#  ifdef  __cplusplus
extern "C" {
#  endif

typedef struct zkp_range_pub_param_st   ZKP_RANGE_PUB_PARAM;
typedef struct zkp_range_witness_st     ZKP_RANGE_WITNESS;
typedef struct zkp_range_ctx_st         ZKP_RANGE_CTX;
typedef struct zkp_range_proof_st       ZKP_RANGE_PROOF;

ZKP_RANGE_PUB_PARAM *ZKP_RANGE_PUB_PARAM_raw_new(BP_PUB_PARAM *bp_pp);
ZKP_RANGE_PUB_PARAM *ZKP_RANGE_PUB_PARAM_new(const EC_GROUP *group, int max_bits);
void ZKP_RANGE_PUB_PARAM_free(ZKP_RANGE_PUB_PARAM *pp);
int ZKP_RANGE_PUB_PARAM_up_ref(ZKP_RANGE_PUB_PARAM *pp);
int ZKP_RANGE_PUB_PARAM_down_ref(ZKP_RANGE_PUB_PARAM *pp);

ZKP_RANGE_WITNESS *ZKP_RANGE_WITNESS_new(const ZKP_RANGE_PUB_PARAM *pp,
                                         const BIGNUM *r, const BIGNUM *v);
void ZKP_RANGE_WITNESS_free(ZKP_RANGE_WITNESS *witness);
int ZKP_RANGE_WITNESS_up_ref(ZKP_RANGE_WITNESS *witness);
int ZKP_RANGE_WITNESS_down_ref(ZKP_RANGE_WITNESS *witness);

ZKP_RANGE_CTX *ZKP_RANGE_CTX_raw_new(ZKP_TRANSCRIPT *transcript,
                                     ZKP_RANGE_PUB_PARAM *pp,
                                     ZKP_RANGE_WITNESS *witness,
                                     const EC_POINT *pk,
                                     EC_ELGAMAL_CTX *enc_ctx,
                                     EC_ELGAMAL_CIPHERTEXT *enc_ct);
ZKP_RANGE_CTX *ZKP_RANGE_CTX_new(ZKP_TRANSCRIPT *transcript,
                                 ZKP_RANGE_PUB_PARAM *pp,
                                 ZKP_RANGE_WITNESS *witness,
                                 EC_KEY *key);
void ZKP_RANGE_CTX_free(ZKP_RANGE_CTX *ctx);

ZKP_RANGE_PROOF *ZKP_RANGE_PROOF_new(void);
void ZKP_RANGE_PROOF_free(ZKP_RANGE_PROOF *proof);
ZKP_RANGE_PROOF *ZKP_RANGE_PROOF_prove(ZKP_RANGE_CTX *ctx, int left_bound_bits,
                                       int right_bound_bits);
int ZKP_RANGE_PROOF_verify(ZKP_RANGE_CTX *ctx, ZKP_RANGE_PROOF *proof,
                           int left_bound_bits, int right_bound_bits);

#  ifdef  __cplusplus
}
#  endif
# endif

#endif
