/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_ZKP_UTIL_LOCAL_H
# define HEADER_ZKP_UTIL_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif

# include <openssl/bn.h>
# include <openssl/ec.h>
# include "internal/refcount.h"

#ifdef __bswap_constant_32
# undef __bswap_constant_32
#endif
#define __bswap_constant_32(x)                  \
    ((((uint32_t)(x) & 0xff000000u) >> 24) |    \
     (((uint32_t)(x) & 0x00ff0000u) >>  8) |    \
     (((uint32_t)(x) & 0x0000ff00u) <<  8) |    \
     (((uint32_t)(x) & 0x000000ffu) << 24))

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define zkp_n2l(x)  (x)
# define zkp_l2n(x)  (x)
#else
# define zkp_n2l(x)  __bswap_constant_32(x)
# define zkp_l2n(x)  __bswap_constant_32(x)
#endif

# define zkp_rand_range BN_rand_range

STACK_OF(EC_POINT);

typedef struct zkp_poly_points_st {
    int capacity;
    int num;
    EC_POINT **points;
    BIGNUM **scalars;
} zkp_poly_points_t;

int zkp_str2point(const EC_GROUP *group, const unsigned char *str, size_t len,
                  EC_POINT *r, BN_CTX *bn_ctx);
size_t zkp_point2oct(const EC_GROUP *group, const EC_POINT *P,
                     unsigned char *buf, BN_CTX *bn_ctx);
int zkp_bin_hash2bn(const unsigned char *data, size_t len, BIGNUM *r);
int zkp_next_power_of_two(int num);
int zkp_floor_log2(int x);
int zkp_inner_product(BIGNUM *r, int num, const BIGNUM *a[], const BIGNUM *b[],
                      const BIGNUM *order, BN_CTX *bn_ctx);

zkp_poly_points_t *zkp_poly_points_new(int capacity);
void zkp_poly_points_free(zkp_poly_points_t *ps);
void zkp_poly_points_reset(zkp_poly_points_t *ps);
int zkp_poly_points_append(zkp_poly_points_t *ps, EC_POINT *point, BIGNUM *scalar);
int zkp_poly_points_mul(zkp_poly_points_t *ps, EC_POINT *r, BIGNUM *scalar,
                        const EC_GROUP *group, BN_CTX *bn_ctx);

int zkp_bignum_encode(BIGNUM *bn, unsigned char *out, int bn_len);
BIGNUM *zkp_bignum_decode(const unsigned char *in, int *len, int bn_len);
int zkp_stack_of_bignum_encode(STACK_OF(BIGNUM) *sk, unsigned char *out,
                               int bn_len);
STACK_OF(BIGNUM) *zkp_stack_of_bignum_decode(const unsigned char *in,
                                             int *len, int bn_len);
int zkp_stack_of_point_encode(STACK_OF(EC_POINT) *sk, unsigned char *out,
                              const EC_GROUP *group, BN_CTX *bn_ctx);
STACK_OF(EC_POINT) *zkp_stack_of_point_decode(const unsigned char *in, int *len,
                                              const EC_GROUP *group,
                                              BN_CTX *bn_ctx);

# ifdef  __cplusplus
}
# endif

#endif


