/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_ZKP_DEBUG_LOCAL_H
# define HEADER_ZKP_DEBUG_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"

STACK_OF(BIGNUM);
STACK_OF(EC_POINT);

int zkp_rand_range_debug_one(BIGNUM *rnd, const BIGNUM *range);

int zkp_buf2hexstr_print(BIO *bio, const unsigned char *buf, size_t size,
                        char *field, int text);

void BN_debug_print(BIO *b, const BIGNUM *n, const char *name);
void EC_POINT_debug_print(BIO *b, const EC_POINT *p, const char *name);
void EC_POINT_debug_print_affine(BIO *b, const EC_GROUP *group, const EC_POINT *p,
                                 const char *name, BN_CTX *ctx);

void zkp_bn_vector_debug_print(BIO *bio, BIGNUM **bv, int n, const char *note);
void zkp_point_vector_debug_print(BIO *bio, const EC_GROUP *group, EC_POINT **pv,
                                  int n, const char *note, BN_CTX *bn_ctx);
void zkp_stack_of_bignum_debug_print(BIO *bio, STACK_OF(BIGNUM) *sk, const char *name);
void zkp_stack_of_point_debug_print(BIO *bio, STACK_OF(EC_POINT) *sk, const char *nam);

# ifdef  __cplusplus
}
# endif

#endif

