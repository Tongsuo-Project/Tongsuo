/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <openssl/zkperr.h>
#include <openssl/bulletproofs.h>
#include <openssl/nizk.h>
#include <openssl/zkp_gadget.h>
#include <crypto/ec.h>
#include <crypto/ec/ec_elgamal.h>
#include <crypto/zkp/bulletproofs/bulletproofs.h>
#include <crypto/zkp/nizk/nizk.h>
#include <crypto/zkp/nizk/nizk_plaintext_knowledge.h>
#include <crypto/zkp/common/zkp_util.h>
#include "zkp_range_proof.h"

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(BP_VARIABLE)

static int zkp_bp_range_witness_adjust(BP_WITNESS *witness, int left_bound_bits,
                                       int right_bound_bits, int range_bits,
                                       int is_prove, const EC_GROUP *group)
{
    int ret = 0;
    BIGNUM *bn1, *bn2, *bn_left_bound, *bn_right_bound, *bn_range, *bn_delta, *v0, *v1;
    BN_CTX *bn_ctx = NULL;
    BP_VARIABLE *var0, *var1;
    EC_POINT *P = NULL;
    zkp_poly_points_t *poly = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        return 0;

    bn1 = BN_CTX_get(bn_ctx);
    bn2 = BN_CTX_get(bn_ctx);
    bn_left_bound = BN_CTX_get(bn_ctx);
    bn_right_bound = BN_CTX_get(bn_ctx);
    bn_range = BN_CTX_get(bn_ctx);
    bn_delta = BN_CTX_get(bn_ctx);
    if (bn_delta == NULL)
        goto err;

    BN_one(bn1);
    BN_set_word(bn2, 2);
    BN_set_word(bn_left_bound, left_bound_bits);
    BN_set_word(bn_right_bound, right_bound_bits);
    BN_set_word(bn_range, range_bits);

    if (!BN_exp(bn_left_bound, bn2, bn_left_bound, bn_ctx)
        || !BN_exp(bn_right_bound, bn2, bn_right_bound, bn_ctx)
        || !BN_exp(bn_range, bn2, bn_range, bn_ctx)
        || !BN_sub(bn_delta, bn_range, bn_right_bound))
        goto err;

    if (is_prove == 1) {
        v0 = sk_BIGNUM_value(witness->sk_v, 0);
        v1 = sk_BIGNUM_value(witness->sk_v, 1);

        if (!BN_sub(v0, v0, bn_left_bound) || !BN_add(v1, v1, bn_delta))
            goto err;
    }

    P = EC_POINT_new(group);
    if (P == NULL)
        goto err;

    var0 = sk_BP_VARIABLE_value(witness->sk_V, 0);
    var1 = sk_BP_VARIABLE_value(witness->sk_V, 1);

    BN_set_negative(bn_left_bound, 1);

    if (!(poly = zkp_poly_points_new(2)))
        goto err;

    if (!zkp_poly_points_append(poly, var0->point, bn1)
        || !zkp_poly_points_append(poly, witness->H, bn_left_bound))
        goto err;

    if (!zkp_poly_points_mul(poly, var0->point, NULL, group, bn_ctx))
        goto err;

    zkp_poly_points_reset(poly);

    if (!zkp_poly_points_append(poly, var1->point, bn1)
        || !zkp_poly_points_append(poly, witness->H, bn_delta))
        goto err;

    if (!zkp_poly_points_mul(poly, var1->point, NULL, group, bn_ctx))
        goto err;

    ret = 1;
err:
    zkp_poly_points_free(poly);
    EC_POINT_free(P);
    BN_CTX_free(bn_ctx);
    return ret;
}

ZKP_RANGE_PUB_PARAM *ZKP_RANGE_PUB_PARAM_raw_new(BP_PUB_PARAM *bp_pp)
{
    ZKP_RANGE_PUB_PARAM *pp = NULL;

    if (bp_pp == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    pp = OPENSSL_zalloc(sizeof(*pp));
    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!BP_PUB_PARAM_up_ref(bp_pp))
        goto err;

    pp->bp_pp = bp_pp;

    pp->references = 1;
    if ((pp->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    return pp;
err:
    ZKP_RANGE_PUB_PARAM_free(pp);
    return NULL;
}

ZKP_RANGE_PUB_PARAM *ZKP_RANGE_PUB_PARAM_new(const EC_GROUP *group, int max_bits)
{
    BP_PUB_PARAM *bp_pp = NULL;
    ZKP_RANGE_PUB_PARAM *pp = NULL;

    if (group == NULL || max_bits > 64) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    if (!(bp_pp = BP_PUB_PARAM_new(group, max_bits, 2)))
        return NULL;

    pp = ZKP_RANGE_PUB_PARAM_raw_new(bp_pp);
    BP_PUB_PARAM_free(bp_pp);
    return pp;
}

void ZKP_RANGE_PUB_PARAM_free(ZKP_RANGE_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return;

    CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock);
    REF_PRINT_COUNT("ZKP_RANGE_PUB_PARAM", pp);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    BP_PUB_PARAM_down_ref(pp->bp_pp);
    OPENSSL_clear_free((void *)pp, sizeof(*pp));
}

int ZKP_RANGE_PUB_PARAM_up_ref(ZKP_RANGE_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return 0;

    if (CRYPTO_UP_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("ZKP_RANGE_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

int ZKP_RANGE_PUB_PARAM_down_ref(ZKP_RANGE_PUB_PARAM *pp)
{
    int ref;

    if (pp == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&pp->references, &ref, pp->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("ZKP_RANGE_PUB_PARAM", pp);
    REF_ASSERT_ISNT(ref < 0);
    return ((ref > 0) ? 1 : 0);
}

ZKP_RANGE_WITNESS *ZKP_RANGE_WITNESS_new(const ZKP_RANGE_PUB_PARAM *pp,
                                         const BIGNUM *r, const BIGNUM *v)

{
    ZKP_RANGE_WITNESS *witness = NULL;

    if (pp == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(witness = OPENSSL_zalloc(sizeof(*witness)))) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(witness->order = BN_dup(EC_GROUP_get0_order(pp->bp_pp->group)))
        || !(witness->r = BN_new())
        || !(witness->v = BN_new())) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (r != NULL) {
        if (!BN_copy(witness->r, r))
            goto err;
    } else {
        zkp_rand_range(witness->r, witness->order);
    }

    if (v != NULL && !BN_copy(witness->v, v))
        goto err;

    witness->references = 1;
    if ((witness->lock = CRYPTO_THREAD_lock_new()) == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    return witness;
err:
    ZKP_RANGE_WITNESS_free(witness);
    return NULL;
}

void ZKP_RANGE_WITNESS_free(ZKP_RANGE_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return;

    CRYPTO_DOWN_REF(&witness->references, &ref, witness->lock);
    REF_PRINT_COUNT("ZKP_RANGE_WITNESS", witness);
    if (ref > 0)
        return;
    REF_ASSERT_ISNT(ref < 0);

    BN_free(witness->order);
    BN_free(witness->r);
    BN_free(witness->v);
    CRYPTO_THREAD_lock_free(witness->lock);
    OPENSSL_free(witness);
}

int ZKP_RANGE_WITNESS_up_ref(ZKP_RANGE_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return 0;

    if (CRYPTO_UP_REF(&witness->references, &ref, witness->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("ZKP_RANGE_WITNESS", witness);
    REF_ASSERT_ISNT(ref < 2);
    return ((ref > 1) ? 1 : 0);
}

int ZKP_RANGE_WITNESS_down_ref(ZKP_RANGE_WITNESS *witness)
{
    int ref;

    if (witness == NULL)
        return 0;

    if (CRYPTO_DOWN_REF(&witness->references, &ref, witness->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("ZKP_RANGE_WITNESS", witness);
    REF_ASSERT_ISNT(ref < 0);
    return ((ref > 0) ? 1 : 0);
}

ZKP_RANGE_CTX *ZKP_RANGE_CTX_raw_new(ZKP_TRANSCRIPT *transcript,
                                     ZKP_RANGE_PUB_PARAM *pp,
                                     ZKP_RANGE_WITNESS *witness,
                                     const EC_POINT *pk,
                                     EC_ELGAMAL_CTX *enc_ctx,
                                     EC_ELGAMAL_CIPHERTEXT *enc_ct)
{
    ZKP_RANGE_CTX *ctx = NULL;

    if (transcript == NULL || pp == NULL || witness == NULL || pk == NULL
        || enc_ct == NULL || enc_ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (enc_ctx->flag != EC_ELGAMAL_FLAG_TWISTED) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ctx->transcript = transcript;

    if (!ZKP_RANGE_PUB_PARAM_up_ref(pp))
        goto err;

    ctx->pp = pp;

    if (!ZKP_RANGE_WITNESS_up_ref(witness))
        goto err;

    ctx->witness = witness;

    ctx->PK = EC_POINT_dup(pk, pp->bp_pp->group);
    if (ctx->PK == NULL)
        goto err;

    ctx->enc_ctx = EC_ELGAMAL_CTX_dup(enc_ctx);
    ctx->enc_ct = EC_ELGAMAL_CIPHERTEXT_dup(enc_ct, pp->bp_pp->group);
    if (ctx->enc_ctx == NULL || ctx->enc_ct == NULL)
        goto err;

    return ctx;

err:
    ZKP_RANGE_CTX_free(ctx);
    return NULL;
}

ZKP_RANGE_CTX *ZKP_RANGE_CTX_new(ZKP_TRANSCRIPT *transcript,
                                 ZKP_RANGE_PUB_PARAM *pp,
                                 ZKP_RANGE_WITNESS *witness,
                                 EC_KEY *key)
{
    ZKP_RANGE_CTX *ret = NULL;
    EC_ELGAMAL_CTX *enc_ctx = NULL;
    EC_ELGAMAL_CIPHERTEXT *enc_ct = NULL;

    if (transcript == NULL || pp == NULL || witness == NULL || key == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!(enc_ctx = EC_ELGAMAL_CTX_new(key, pp->bp_pp->H, EC_ELGAMAL_FLAG_TWISTED)))
        goto err;

    if (!(enc_ct = EC_ELGAMAL_CIPHERTEXT_new(enc_ctx)))
        goto err;

    if (!EC_ELGAMAL_bn_encrypt(enc_ctx, enc_ct, witness->v, witness->r))
        goto err;

    ret = ZKP_RANGE_CTX_raw_new(transcript, pp, witness, key->pub_key, enc_ctx, enc_ct);
err:
    EC_ELGAMAL_CIPHERTEXT_free(enc_ct);
    EC_ELGAMAL_CTX_free(enc_ctx);
    return ret;
}

void ZKP_RANGE_CTX_free(ZKP_RANGE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    ZKP_RANGE_PUB_PARAM_down_ref(ctx->pp);
    ZKP_RANGE_WITNESS_down_ref(ctx->witness);
    EC_ELGAMAL_CIPHERTEXT_free(ctx->enc_ct);
    EC_ELGAMAL_CTX_free(ctx->enc_ctx);
    OPENSSL_clear_free((void *)ctx, sizeof(*ctx));
}

ZKP_RANGE_PROOF *ZKP_RANGE_PROOF_new(void)
{
    ZKP_RANGE_PROOF *proof = NULL;

    proof = OPENSSL_zalloc(sizeof(*proof));
    if (proof == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return proof;
}

void ZKP_RANGE_PROOF_free(ZKP_RANGE_PROOF *proof)
{
    if (proof == NULL)
        return;

    NIZK_PLAINTEXT_KNOWLEDGE_PROOF_free(proof->ptke_proof);
    BP_RANGE_PROOF_free(proof->bp_proof);
}

ZKP_RANGE_PROOF *ZKP_RANGE_PROOF_prove(ZKP_RANGE_CTX *ctx, int left_bound_bits,
                                       int right_bound_bits)
{
    EC_GROUP *group;
    const EC_POINT *G, *H;
    ZKP_RANGE_PUB_PARAM *pp;
    ZKP_RANGE_WITNESS *witness;
    ZKP_RANGE_PROOF *proof = NULL, *ret = NULL;
    NIZK_PUB_PARAM *nizk_pp = NULL;
    NIZK_WITNESS *nizk_witness = NULL;
    NIZK_PLAINTEXT_KNOWLEDGE_CTX *ptke_ctx = NULL;
    BIGNUM *v1 = NULL, *v2 = NULL;
    BP_WITNESS *bp_witness = NULL;
    BP_VARIABLE *bp_var1 = NULL, *bp_var2 = NULL;
    BP_RANGE_CTX *bp_ctx = NULL;

    if (ctx == NULL || ctx->pp == NULL || ctx->pp->bp_pp == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    pp = ctx->pp;
    witness = ctx->witness;
    group = pp->bp_pp->group;
    G = EC_GROUP_get0_generator(group);
    H = pp->bp_pp->H;

    if (left_bound_bits < 0
        || right_bound_bits < 0
        || left_bound_bits > right_bound_bits
        || right_bound_bits > pp->bp_pp->gens_capacity) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    proof = ZKP_RANGE_PROOF_new();
    if (proof == NULL)
        return NULL;

    nizk_pp = NIZK_PUB_PARAM_new(group, G, H);
    if (nizk_pp == NULL)
        goto err;

    nizk_witness = NIZK_WITNESS_new(nizk_pp, witness->r, witness->v);
    if (nizk_witness == NULL)
        goto err;

    ptke_ctx = NIZK_PLAINTEXT_KNOWLEDGE_CTX_new(ctx->transcript, nizk_pp,
                                                nizk_witness, ctx->PK, ctx->enc_ct);
    if (ptke_ctx == NULL)
        goto err;

    proof->ptke_proof = NIZK_PLAINTEXT_KNOWLEDGE_PROOF_prove(ptke_ctx);
    if (proof->ptke_proof == NULL) {
        ERR_raise(ERR_LIB_ZKP, ZKP_R_RANGE_PROVE_FAILED);
        goto err;
    }

    bp_witness = BP_WITNESS_new(pp->bp_pp);
    if (bp_witness == NULL)
        goto err;

    bp_var1 = BP_VARIABLE_new(NULL, ctx->enc_ct->C2, group);
    bp_var2 = BP_VARIABLE_new(NULL, ctx->enc_ct->C2, group);
    if (bp_var1 == NULL || bp_var2 == NULL)
        goto err;

    v1 = BN_dup(ctx->witness->v);
    v2 = BN_dup(ctx->witness->v);
    if (v1 == NULL || v2 == NULL)
        goto err;

    if (sk_BIGNUM_push(bp_witness->sk_r, ctx->witness->r) <= 0
        || sk_BIGNUM_push(bp_witness->sk_r, ctx->witness->r) <= 1
        || sk_BIGNUM_push(bp_witness->sk_v, v1) <= 0
        || sk_BIGNUM_push(bp_witness->sk_v, v2) <= 1
        || sk_BP_VARIABLE_push(bp_witness->sk_V, bp_var1) <= 0
        || sk_BP_VARIABLE_push(bp_witness->sk_V, bp_var2) <= 1)
        goto err;

    if (!zkp_bp_range_witness_adjust(bp_witness, left_bound_bits, right_bound_bits,
                                     pp->bp_pp->gens_capacity, 1, group))
        goto err;

    bp_ctx = BP_RANGE_CTX_new(pp->bp_pp, bp_witness, ctx->transcript);
    if (bp_ctx == NULL)
        goto err;

    proof->bp_proof = BP_RANGE_PROOF_new_prove(bp_ctx);
    if (proof->bp_proof == NULL) {
        ERR_raise(ERR_LIB_ZKP, ZKP_R_RANGE_PROVE_FAILED);
        goto err;
    }

    ret = proof;
    proof = NULL;

err:
    BP_RANGE_CTX_free(bp_ctx);
    BN_free(v1);
    BN_free(v2);
    BP_VARIABLE_free(bp_var1);
    BP_VARIABLE_free(bp_var2);
    if (bp_witness != NULL) {
        sk_BIGNUM_zero(bp_witness->sk_r);
        sk_BIGNUM_zero(bp_witness->sk_v);
        sk_BP_VARIABLE_zero(bp_witness->sk_V);
        BP_WITNESS_free(bp_witness);
    }
    NIZK_PLAINTEXT_KNOWLEDGE_CTX_free(ptke_ctx);
    NIZK_WITNESS_free(nizk_witness);
    NIZK_PUB_PARAM_free(nizk_pp);
    ZKP_RANGE_PROOF_free(proof);
    return ret;
}

int ZKP_RANGE_PROOF_verify(ZKP_RANGE_CTX *ctx, ZKP_RANGE_PROOF *proof,
                           int left_bound_bits, int right_bound_bits)
{
    int ret = 0;
    EC_GROUP *group;
    const EC_POINT *G, *H;
    ZKP_RANGE_PUB_PARAM *pp;
    NIZK_PUB_PARAM *nizk_pp = NULL;
    NIZK_WITNESS *nizk_witness = NULL;
    NIZK_PLAINTEXT_KNOWLEDGE_CTX *ptke_ctx = NULL;
    BP_WITNESS *bp_witness = NULL;
    BP_VARIABLE *bp_var1 = NULL, *bp_var2 = NULL;
    BP_RANGE_CTX *bp_ctx = NULL;

    if (ctx == NULL || ctx->pp == NULL || ctx->pp->bp_pp == NULL
        || proof->ptke_proof == NULL || proof->bp_proof == NULL) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    pp = ctx->pp;
    group = pp->bp_pp->group;
    G = EC_GROUP_get0_generator(group);
    H = pp->bp_pp->H;

    if (left_bound_bits < 0
        || right_bound_bits < 0
        || left_bound_bits > right_bound_bits
        || right_bound_bits > pp->bp_pp->gens_capacity) {
        ERR_raise(ERR_LIB_ZKP, ERR_R_PASSED_INVALID_ARGUMENT);
        return ret;
    }

    nizk_pp = NIZK_PUB_PARAM_new(group, G, H);
    if (nizk_pp == NULL)
        goto err;

    ptke_ctx = NIZK_PLAINTEXT_KNOWLEDGE_CTX_new(ctx->transcript, nizk_pp, NULL,
                                                ctx->PK, ctx->enc_ct);
    if (ptke_ctx == NULL)
        goto err;

    if (!NIZK_PLAINTEXT_KNOWLEDGE_PROOF_verify(ptke_ctx, proof->ptke_proof)) {
        ERR_raise(ERR_LIB_ZKP, ZKP_R_RANGE_VERIFY_FAILED);
        goto err;
    }

    bp_witness = BP_WITNESS_new(pp->bp_pp);
    if (bp_witness == NULL)
        goto err;

    bp_var1 = BP_VARIABLE_new(NULL, ctx->enc_ct->C2, group);
    if (bp_var1 == NULL)
        goto err;

    bp_var2 = BP_VARIABLE_new(NULL, ctx->enc_ct->C2, group);
    if (bp_var2 == NULL)
        goto err;

    if (sk_BP_VARIABLE_push(bp_witness->sk_V, bp_var1) <= 0
        || sk_BP_VARIABLE_push(bp_witness->sk_V, bp_var2) <= 1)
        goto err;

    if (!zkp_bp_range_witness_adjust(bp_witness, left_bound_bits, right_bound_bits,
                                     pp->bp_pp->gens_capacity, 0, group))
        goto err;

    bp_ctx = BP_RANGE_CTX_new(pp->bp_pp, bp_witness, ctx->transcript);
    if (bp_ctx == NULL)
        goto err;

    if (!BP_RANGE_PROOF_verify(bp_ctx, proof->bp_proof)) {
        ERR_raise(ERR_LIB_ZKP, ZKP_R_RANGE_VERIFY_FAILED);
        goto err;
    }

    ret = 1;

err:
    BP_RANGE_CTX_free(bp_ctx);
    BP_VARIABLE_free(bp_var1);
    BP_VARIABLE_free(bp_var2);

    if (bp_witness != NULL) {
        sk_BP_VARIABLE_zero(bp_witness->sk_V);
        BP_WITNESS_free(bp_witness);
    }

    NIZK_PLAINTEXT_KNOWLEDGE_CTX_free(ptke_ctx);
    NIZK_WITNESS_free(nizk_witness);
    NIZK_PUB_PARAM_free(nizk_pp);
    return ret;
}
