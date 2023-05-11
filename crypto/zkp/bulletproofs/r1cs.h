/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_BULLET_PROOF_R1CS_LOCAL_H
# define HEADER_BULLET_PROOF_R1CS_LOCAL_H

# include <openssl/opensslconf.h>

# ifdef  __cplusplus
extern "C" {
# endif
# include <openssl/bn.h>
# include <openssl/ec.h>
# include <openssl/safestack.h>
# include <openssl/bulletproofs.h>
# include "internal/refcount.h"
# include "bulletproofs.h"
# include "inner_product.h"

DEFINE_STACK_OF(BP_R1CS_VARIABLE)
DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM)
DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION)

typedef enum bp_r1cs_op_type {
    BP_R1CS_OP_UNKOWN,
    BP_R1CS_OP_PROVE,
    BP_R1CS_OP_VERIFY,
} bp_r1cs_op_type_t;

struct bp_r1cs_variable_st {
    BP_R1CS_VARIABLE_TYPE   type;
    uint64_t                value;
    /* commitment */
    EC_POINT               *C;
    char                   *name;
    CRYPTO_RWLOCK          *lock;
    CRYPTO_REF_COUNT        references;
};

struct bp_r1cs_linear_combination_item_st {
    BP_R1CS_VARIABLE       *variable;
    BIGNUM                 *scalar;
};

struct bp_r1cs_linear_combination_st {
    STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM) *items;
    CRYPTO_RWLOCK                             *lock;
    CRYPTO_REF_COUNT                           references;
};

struct bp_r1cs_ctx_st {
    BP_TRANSCRIPT *transcript;
    bp_r1cs_op_type_t op;
    const EC_POINT *G;
    EC_GROUP *group;
    BP_PUB_PARAM *pp;
    STACK_OF(BP_R1CS_LINEAR_COMBINATION) *p_constraints;
    STACK_OF(BP_R1CS_LINEAR_COMBINATION) *v_constraints;
    STACK_OF(BP_R1CS_VARIABLE) *V;
    STACK_OF(BIGNUM) *aL;
    STACK_OF(BIGNUM) *aR;
    STACK_OF(BIGNUM) *aO;
    STACK_OF(BIGNUM) *v;
    STACK_OF(BIGNUM) *r;
    int vars_num;
};

struct bp_r1cs_proof_st {
    EC_POINT *AI1;
    EC_POINT *AO1;
    EC_POINT *S1;
    EC_POINT *AI2;
    EC_POINT *AO2;
    EC_POINT *S2;
    EC_POINT *T1;
    EC_POINT *T3;
    EC_POINT *T4;
    EC_POINT *T5;
    EC_POINT *T6;
    BIGNUM *taux;
    BIGNUM *mu;
    BIGNUM *tx;
    bp_inner_product_proof_t *ip_proof;
    CRYPTO_RWLOCK *lock;
    CRYPTO_REF_COUNT references;
};


# ifdef  __cplusplus
}
# endif

#endif

