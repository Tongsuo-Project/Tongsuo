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
    BIGNUM **x0;
    BIGNUM **x1;
    BIGNUM **x2;
    BIGNUM **x3;
    BIGNUM **eval;
} bp_poly3_t;

typedef struct bp_poly6_st {
    BIGNUM *t1;
    BIGNUM *t2;
    BIGNUM *t3;
    BIGNUM *t4;
    BIGNUM *t5;
    BIGNUM *t6;
} bp_poly6_t;

typedef struct bp_poly_ps_st {
    int pos;
    int num;
    EC_POINT **points;
    BIGNUM **scalars;
} bp_poly_ps_t;

EC_POINT **bp_random_ec_points_new(const EC_GROUP *group, size_t n, BN_CTX *bn_ctx);
void bp_random_ec_points_free(EC_POINT **P, size_t n);
EC_POINT *bp_random_ec_point_new(const EC_GROUP *group, BN_CTX *bn_ctx);
void bp_random_ec_point_free(EC_POINT *P);
int bp_str2bn(const unsigned char *str, size_t len, BIGNUM *ret);
int bp_points_hash2bn(const EC_GROUP *group, EC_POINT *A, EC_POINT *B,
                      BIGNUM *ra, BIGNUM *rb, BN_CTX *bn_ctx);
/* r = SHA256(st, bin(P)) */
int bp_bin_point_hash2bn(const EC_GROUP *group, const char *st, size_t len,
                         const EC_POINT *P, BIGNUM *r, BN_CTX *bn_ctx);
/* r = SHA256(bin(bn_st), bin(P)) */
int bp_bn_point_hash2bn(const EC_GROUP *group, const BIGNUM *bn_st,
                        const EC_POINT *P, BIGNUM *r, BN_CTX *bn_ctx);
int bp_random_bn_gen(const EC_GROUP *group, BIGNUM **r, size_t n, BN_CTX *bn_ctx);
int bp_str2point(const EC_GROUP *group, const unsigned char *str, size_t len,
                 EC_POINT *r, BN_CTX *bn_ctx);
size_t bp_point2oct(const EC_GROUP *group, const EC_POINT *P,
                    unsigned char *buf, BN_CTX *bn_ctx);
int bp_bin_hash2bn(const unsigned char *data, size_t len, BIGNUM *r);
int bp_next_power_of_two(int num);
int bp_floor_log2(int x);
int bp_inner_product(BIGNUM *r, int num, const BIGNUM *a[], const BIGNUM *b[],
                     BN_CTX *bn_ctx);

bp_poly3_t *bp_poly3_new(int n, BN_CTX *bn_ctx);
void bp_poly3_free(bp_poly3_t *poly3);
int bp_poly3_eval(bp_poly3_t *poly3, const BIGNUM *x, BN_CTX *bn_ctx);
int bp_poly3_special_inner_product(bp_poly6_t *r, bp_poly3_t *lhs, bp_poly3_t *rhs,
                                   BN_CTX *bn_ctx);
bp_poly6_t *bp_poly6_new(BN_CTX *bn_ctx);
void bp_poly6_free(bp_poly6_t *poly6);
int bp_poly6_eval(bp_poly6_t *poly6, BIGNUM *r, const BIGNUM *x, BN_CTX *bn_ctx);

bp_poly_ps_t *bp_poly_ps_new(int num);
void bp_poly_ps_free(bp_poly_ps_t *ps);
int bp_poly_ps_append(bp_poly_ps_t *ps, EC_POINT *point, BIGNUM *scalar);
int bp_poly_ps_eval(bp_poly_ps_t *ps, EC_POINT *r, BIGNUM *scalar,
                    const EC_GROUP *group, BN_CTX *bn_ctx);
# ifdef  __cplusplus
}
# endif

#endif

