/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bulletproofs.h>
#include <crypto/ec/ec_local.h>
#include <crypto/zkp/common/zkp_debug.h>
#include "bp_debug.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)
DEFINE_STACK_OF(BP_VARIABLE)

void BP_WITNESS_debug_print(BP_WITNESS *witness, const char *note)
{
    BIO *bio = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "witness->n: %d\n", sk_BP_VARIABLE_num(witness->sk_V));

    bp_stack_of_variable_debug_print(bio, witness->sk_V, "witness->sk_V");
    zkp_stack_of_bignum_debug_print(bio, witness->sk_r, "witness->sk_r");
    zkp_stack_of_bignum_debug_print(bio, witness->sk_v, "witness->sk_v");

err:
    BIO_free(bio);
}

void BP_RANGE_PROOF_debug_print(BP_RANGE_PROOF *proof, const EC_GROUP *group, const char *note)
{
    BIO *bio = NULL;
    BN_CTX *bn_ctx = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    BIO_printf(bio, "%s: \n", note);

    EC_POINT_debug_print_affine(bio, group, proof->A, "proof->A", bn_ctx);
    EC_POINT_debug_print_affine(bio, group, proof->S, "proof->S", bn_ctx);
    EC_POINT_debug_print_affine(bio, group, proof->T1, "proof->T1", bn_ctx);
    EC_POINT_debug_print_affine(bio, group, proof->T2, "proof->T2", bn_ctx);
    BN_debug_print(bio, proof->taux, "proof->taux");
    BN_debug_print(bio, proof->mu, "proof->mu");
    BN_debug_print(bio, proof->tx, "proof->tx");
    bp_inner_product_proof_debug_print(proof->ip_proof, group, "ip_proof");

err:
    BN_CTX_free(bn_ctx);
    BIO_free(bio);
}

void bp_inner_product_pub_param_debug_print(bp_inner_product_pub_param_t *pp,
                                            const char *note)
{
    BIO *bio = NULL;
    int curve_id;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    curve_id = EC_GROUP_get_curve_name(pp->group);

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_pp->curve_id: %zu\n", curve_id);
    BIO_printf(bio, "ip_pp->n: %zu\n", sk_EC_POINT_num(pp->sk_G));

    zkp_stack_of_point_debug_print(bio, pp->sk_G, "ip_pp->sk_G");
    zkp_stack_of_point_debug_print(bio, pp->sk_H, "ip_pp->sk_H");

err:
    BIO_free(bio);
}

void bp_inner_product_witness_debug_print(bp_inner_product_witness_t *witness,
                                          const char *note)
{
    BIO *bio = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_witness->n: %zu\n", sk_BIGNUM_num(witness->sk_a));

    zkp_stack_of_bignum_debug_print(bio, witness->sk_a, "ip_witness->sk_a");
    zkp_stack_of_bignum_debug_print(bio, witness->sk_b, "ip_witness->sk_b");

err:
    BIO_free(bio);
}

void bp_inner_product_proof_debug_print(bp_inner_product_proof_t *proof,
                                        const EC_GROUP *group, const char *note)
{
    BIO *bio = NULL;

    if (!(bio = BIO_new(BIO_s_file())))
        goto err;

    BIO_set_fp(bio, stderr, BIO_NOCLOSE);

    BIO_printf(bio, "%s: \n", note);
    BIO_printf(bio, "ip_proof->n: %zu\n", sk_EC_POINT_num(proof->sk_L));

    zkp_stack_of_point_debug_print(bio, proof->sk_L, "ip_proof->sk_L");
    zkp_stack_of_point_debug_print(bio, proof->sk_R, "ip_proof->sk_R");

    BN_debug_print(bio, proof->a, "ip_proof->a");
    BN_debug_print(bio, proof->b, "ip_proof->b");

err:
    BIO_free(bio);
}

void bp_stack_of_variable_debug_print(BIO *bio, STACK_OF(BP_VARIABLE) *sk, const char *name)
{
    BIO *b = NULL;
    int i, n;
    EC_POINT *V;
    BP_VARIABLE *var;

    if (sk == NULL)
        return;

    if (bio == NULL) {
        b = bio = BIO_new(BIO_s_file());
        BIO_set_fp(b, stderr, BIO_NOCLOSE);
    }

    n = sk_BP_VARIABLE_num(sk);
    for (i = 0; i < n; i++) {
        var = sk_BP_VARIABLE_value(sk, i);
        if (var == NULL)
            goto err;

        V = var->point;

        BIO_printf(b, "%s[%d], name: %s, X: ", name, var->name, i);
        BN_print(b, V->X);
        BIO_printf(b, ", Y: ");
        BN_print(b, V->Y);
        BIO_printf(b, ", Z: ");
        BN_print(b, V->Z);
        BIO_printf(b, "\n");
    }

err:
    BIO_free(b);
}
