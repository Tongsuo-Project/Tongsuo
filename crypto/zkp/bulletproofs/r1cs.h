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
# include <openssl/zkp_transcript.h>
# include <openssl/bulletproofs.h>
# include "internal/refcount.h"
# include "bulletproofs.h"
# include "inner_product.h"

STACK_OF(BP_R1CS_VARIABLE);
STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM);
STACK_OF(BP_R1CS_LINEAR_COMBINATION);

typedef enum bp_r1cs_variable_type {
    BP_R1CS_VARIABLE_COMMITTED,
    BP_R1CS_VARIABLE_MULTIPLIER_LEFT,
    BP_R1CS_VARIABLE_MULTIPLIER_RIGHT,
    BP_R1CS_VARIABLE_MULTIPLIER_OUTPUT,
    BP_R1CS_VARIABLE_ONE,
} BP_R1CS_VARIABLE_TYPE;

typedef enum bp_r1cs_lc_type {
    BP_R1CS_LC_TYPE_UNKOWN,
    BP_R1CS_LC_TYPE_PROVE,
    BP_R1CS_LC_TYPE_VERIFY,
} BP_R1CS_LC_TYPE;

struct bp_r1cs_variable_st {
    BP_R1CS_VARIABLE_TYPE   type;
    uint64_t                value;
    CRYPTO_RWLOCK          *lock;
    CRYPTO_REF_COUNT        references;
};

struct bp_r1cs_linear_combination_item_st {
    BP_R1CS_VARIABLE       *variable;
    BIGNUM                 *scalar;
};

struct bp_r1cs_linear_combination_st {
    BP_R1CS_LC_TYPE                            type;
    STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM) *items;
    CRYPTO_RWLOCK                             *lock;
    CRYPTO_REF_COUNT                           references;
};

struct bp_r1cs_ctx_st {
    ZKP_TRANSCRIPT *transcript;
    BP_PUB_PARAM *pp;
    BP_WITNESS *witness;
    STACK_OF(BP_R1CS_LINEAR_COMBINATION) *constraints;
    STACK_OF(BIGNUM) *aL;
    STACK_OF(BIGNUM) *aR;
    STACK_OF(BIGNUM) *aO;
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

BP_R1CS_VARIABLE *BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_TYPE type, uint64_t value);
BP_R1CS_VARIABLE *BP_R1CS_VARIABLE_dup(const BP_R1CS_VARIABLE *var);
void BP_R1CS_VARIABLE_free(BP_R1CS_VARIABLE *var);
BP_R1CS_LC_ITEM *BP_R1CS_LC_ITEM_new(BP_R1CS_VARIABLE *var, const BIGNUM *scalar);
BP_R1CS_LC_ITEM *BP_R1CS_LC_ITEM_dup(BP_R1CS_LC_ITEM *item);
void BP_R1CS_LC_ITEM_free(BP_R1CS_LC_ITEM *item);

BP_R1CS_LINEAR_COMBINATION *BP_R1CS_LINEAR_COMBINATION_new_from_param(BP_R1CS_VARIABLE *var,
                                                                      const BIGNUM *scalar);

# ifdef  __cplusplus
}
# endif

#endif

