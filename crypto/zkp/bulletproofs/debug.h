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
# include "bulletproofs.h"
# include "range_proof.h"
# include "inner_product.h"

int bp_rand_range(BIGNUM *rnd, const BIGNUM *range);

int bp_buf2hexstr_print(BIO *bio, const unsigned char *buf, size_t size,
                        char *field, int text);

void BN_debug_print(BIO *b, const BIGNUM *n, const char *name);
void EC_POINT_debug_print(BIO *b, const EC_POINT *p, const char *name);
void EC_POINT_debug_print_affine(BIO *b, const EC_GROUP *group, const EC_POINT *p,
                                 const char *name, BN_CTX *ctx);

void BP_PUB_PARAM_debug_print(BP_PUB_PARAM *pp, const char *note);
void BP_WITNESS_debug_print(BP_WITNESS *witness, const char *note);
void BP_RANGE_PROOF_debug_print(BP_RANGE_PROOF *proof, const EC_GROUP *group, const char *note);

void bp_inner_product_pub_param_debug_print(bp_inner_product_pub_param_t *pp,
                                            const char *note);
void bp_inner_product_witness_debug_print(bp_inner_product_witness_t *witness,
                                          const char *note);
void bp_inner_product_proof_debug_print(bp_inner_product_proof_t *proof,
                                        const EC_GROUP *group, const char *note);
void bp_bn_vector_debug_print(BIO *bio, BIGNUM **bv, int n, const char *note);
void bp_point_vector_debug_print(BIO *bio, const EC_GROUP *group,
                                 EC_POINT **pv, int n,
                                 const char *note, BN_CTX *bn_ctx);
void bp_stack_of_bignum_debug_print(BIO *bio, STACK_OF(BIGNUM) *sk, const char *name);
void bp_stack_of_point_debug_print(BIO *bio, STACK_OF(EC_POINT) *sk, const char *nam);
void bp_stack_of_variable_debug_print(BIO *bio, STACK_OF(BP_VARIABLE) *sk, const char *name);

# ifdef  __cplusplus
}
# endif

#endif

