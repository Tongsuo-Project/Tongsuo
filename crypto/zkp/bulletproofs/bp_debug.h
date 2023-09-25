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

STACK_OF(EC_POINT);
STACK_OF(BP_VARIABLE);

void BP_PUB_PARAM_debug_print(BP_PUB_PARAM *pp, const char *note);
void BP_WITNESS_debug_print(BP_WITNESS *witness, const char *note);
void BP_RANGE_PROOF_debug_print(BP_RANGE_PROOF *proof, const EC_GROUP *group, const char *note);

void bp_inner_product_pub_param_debug_print(bp_inner_product_pub_param_t *pp,
                                            const char *note);
void bp_inner_product_witness_debug_print(bp_inner_product_witness_t *witness,
                                          const char *note);
void bp_inner_product_proof_debug_print(bp_inner_product_proof_t *proof,
                                        const EC_GROUP *group, const char *note);
void bp_stack_of_variable_debug_print(BIO *bio, STACK_OF(BP_VARIABLE) *sk, const char *name);

# ifdef  __cplusplus
}
# endif

#endif

