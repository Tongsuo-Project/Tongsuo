/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BP_UTIL_LOCAL_H
# define HEADER_BP_UTIL_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"

# define bp_rand_range BN_rand_range

typedef struct bp_poly3_st {
    int n;
    const BIGNUM *order;
    BN_CTX *bn_ctx;
    BIGNUM **x0;
    BIGNUM **x1;
    BIGNUM **x2;
    BIGNUM **x3;
} bp_poly3_t;

typedef struct bp_poly6_st {
    const BIGNUM *order;
    BN_CTX *bn_ctx;
    BIGNUM *t1;
    BIGNUM *t2;
    BIGNUM *t3;
    BIGNUM *t4;
    BIGNUM *t5;
    BIGNUM *t6;
} bp_poly6_t;

typedef struct bp_poly_points_st {
    int capacity;
    int num;
    EC_POINT **points;
    BIGNUM **scalars;
} bp_poly_points_t;

EC_POINT *bp_random_ec_point_new(const EC_GROUP *group, BN_CTX *bn_ctx);
void bp_random_ec_point_free(EC_POINT *P);
int bp_random_bn_gen(const EC_GROUP *group, BIGNUM **r, size_t n, BN_CTX *bn_ctx);
int bp_str2point(const EC_GROUP *group, const unsigned char *str, size_t len,
                 EC_POINT *r, BN_CTX *bn_ctx);
size_t bp_point2oct(const EC_GROUP *group, const EC_POINT *P,
                    unsigned char *buf, BN_CTX *bn_ctx);
int bp_bin_hash2bn(const unsigned char *data, size_t len, BIGNUM *r);
int bp_next_power_of_two(int num);
int bp_floor_log2(int x);
int bp_inner_product(BIGNUM *r, int num, const BIGNUM *a[], const BIGNUM *b[],
                     const BIGNUM *order, BN_CTX *bn_ctx);

bp_poly3_t *bp_poly3_new(int n, const BIGNUM *order);
void bp_poly3_free(bp_poly3_t *poly3);
STACK_OF(BIGNUM) *bp_poly3_eval(bp_poly3_t *poly3, const BIGNUM *x);
int bp_poly3_special_inner_product(bp_poly6_t *r, bp_poly3_t *lhs, bp_poly3_t *rhs);
bp_poly6_t *bp_poly6_new(const BIGNUM *order);
void bp_poly6_free(bp_poly6_t *poly6);
int bp_poly6_eval(bp_poly6_t *poly6, const BIGNUM *x, BIGNUM *r);

bp_poly_points_t *bp_poly_points_new(int capacity);
void bp_poly_points_free(bp_poly_points_t *ps);
void bp_poly_points_reset(bp_poly_points_t *ps);
int bp_poly_points_append(bp_poly_points_t *ps, EC_POINT *point, BIGNUM *scalar);
int bp_poly_points_mul(bp_poly_points_t *ps, EC_POINT *r, BIGNUM *scalar,
                       const EC_GROUP *group, BN_CTX *bn_ctx);
# ifdef  __cplusplus
}
# endif

#endif

