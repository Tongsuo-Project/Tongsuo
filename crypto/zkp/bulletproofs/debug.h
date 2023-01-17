/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BP_DEBUG_LOCAL_H
# define HEADER_BP_DEBUG_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"
# include "bullet_proof.h"
# include "inner_product.h"

int bp_rand_range(BIGNUM *rnd, const BIGNUM *range);

void BN_print2(BIO *b, const BIGNUM *n, const char *name);
void EC_POINT_print(BIO *b, const EC_POINT *p, const char *name);
void EC_POINT_print_affine(BIO *b, const EC_GROUP *group, const EC_POINT *p,
                           const char *name, BN_CTX *ctx);

void BULLET_PROOF_PUB_PARAM_print(BULLET_PROOF_PUB_PARAM *pp, const char *note);
void BULLET_PROOF_WITNESS_print(BULLET_PROOF_WITNESS *witness, const char *note);
void BULLET_PROOF_print(BULLET_PROOF *proof, const EC_GROUP *group, const char *note);

void bp_inner_product_pub_param_print(bp_inner_product_pub_param_t *pp,
                                      const char *note);
void bp_inner_product_witness_print(bp_inner_product_witness_t *witness,
                                    const char *note);
void bp_inner_product_proof_print(bp_inner_product_proof_t *proof,
                                  const EC_GROUP *group, const char *note);
void bp_bn_vector_print(BIO *bio, BIGNUM **bv, size_t n, const char *note);
void bp_point_vector_print(BIO *bio, const EC_GROUP *group,
                           EC_POINT **pv, size_t n,
                           const char *note, BN_CTX *bn_ctx);

# ifdef  __cplusplus
}
# endif

#endif

