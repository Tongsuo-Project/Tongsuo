/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <crypto/bn.h>
#include <crypto/ec/ec_local.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bulletproofs.h>
#include "range_proof.h"
#include "r1cs.h"

/* Number of octets per line */
#define ASN1_BUF_PRINT_WIDTH    127
/* Maximum indent */
#define ASN1_PRINT_MAX_INDENT   128

DEFINE_STACK_OF(BIGNUM)
DEFINE_STACK_OF(EC_POINT)
DEFINE_STACK_OF(BP_VARIABLE)

static int bp_bio_printf(BIO *bio, int indent, const char *format, ...)
{
    va_list args;
    int ret;

    if (!BIO_indent(bio, indent, ASN1_PRINT_MAX_INDENT))
        return 0;

    va_start(args, format);

    ret = BIO_vprintf(bio, format, args);

    va_end(args);
    return ret;
}

static int bp_buf_print(BIO *bp, const unsigned char *buf, size_t buflen,
                        int indent)
{
    size_t i;

    for (i = 0; i < buflen; i++) {
        if ((i % ASN1_BUF_PRINT_WIDTH) == 0) {
            if (i > 0 && BIO_puts(bp, "\n") <= 0)
                return 0;
            if (!BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT))
                return 0;
        }
        /*
         * Use colon separators for each octet for compatibility as
         * this function is used to print out key components.
         */
        if (BIO_printf(bp, "%02x%s", buf[i],
                       (i == buflen - 1) ? "" : ":") <= 0)
                return 0;
    }
    if (BIO_write(bp, "\n", 1) <= 0)
        return 0;
    return 1;
}

static int bp_point_print(BIO *bp, const EC_GROUP *group, const EC_POINT *point,
                          const char *name, int indent, BN_CTX *bn_ctx)
{
    int ret = 0;
    size_t point_len;
    unsigned char *p = NULL;

    if (bp == NULL || group == NULL || point == NULL || bn_ctx == NULL)
        return ret;

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
    p = OPENSSL_zalloc(point_len);
    if (p == NULL)
        goto end;

    if (!BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT))
        goto end;

    if (name != NULL)
        BIO_printf(bp, "%s", name);

    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                           p, point_len, bn_ctx) == 0)
        goto end;

    if (!bp_buf_print(bp, p, point_len, 0))
        goto end;

    ret = 1;
end:
    OPENSSL_free(p);
    return ret;
}

static int bp_bn_print(BIO *bp, const char *name, const BIGNUM *num,
                       unsigned char *ign, int indent)
{
    int n, rv = 0;
    const char *neg;
    unsigned char *buf = NULL, *tmp = NULL;
    int buflen;

    if (num == NULL)
        return 1;
    neg = BN_is_negative(num) ? "-" : "";
    if (!BIO_indent(bp, indent, ASN1_PRINT_MAX_INDENT))
        return 0;
    if (BN_is_zero(num)) {
        if (name != NULL)
            BIO_printf(bp, "%s: ", name);

        if (BIO_printf(bp, "0\n") <= 0)
            return 0;
        return 1;
    }

    if (BN_num_bytes(num) <= BN_BYTES) {
        if (name != NULL)
            BIO_printf(bp, "%s: ", name);

        if (BIO_printf(bp, "%s%lu (%s0x%lx)\n", neg,
                       (unsigned long)bn_get_words(num)[0], neg,
                       (unsigned long)bn_get_words(num)[0]) <= 0)
            return 0;
        return 1;
    }

    buflen = BN_num_bytes(num) + 1;
    buf = tmp = OPENSSL_malloc(buflen);
    if (buf == NULL)
        goto err;
    buf[0] = 0;

    if (name != NULL)
        BIO_printf(bp, "%s: ", name);

    BIO_printf(bp, "%s", neg);

    n = BN_bn2bin(num, buf + 1);

    if (buf[1] & 0x80)
        n++;
    else
        tmp++;

    if (bp_buf_print(bp, tmp, n, 0) == 0)
        goto err;
    rv = 1;
    err:
    OPENSSL_clear_free(buf, buflen);
    return rv;
}

static int bp_inner_product_proof_print(BIO *bp,
                                        const bp_inner_product_proof_t *ip_proof,
                                        const EC_GROUP *group, BN_CTX *bn_ctx,
                                        int indent)
{
    int ret = 0, i, n;
    EC_POINT *L, *R;

    if (bp == NULL || ip_proof == NULL || group == NULL || bn_ctx == NULL)
        return ret;

    bp_bio_printf(bp, indent, "inner proof:\n");
    indent += 4;
    n = sk_EC_POINT_num(ip_proof->sk_L);
    bp_bio_printf(bp, indent, "n: %zu\n", n);

    bp_bio_printf(bp, indent, "L[n]:\n");
    for (i = 0; i < n; i++) {
        L = sk_EC_POINT_value(ip_proof->sk_L, i);
        if (L == NULL)
            goto end;

        bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
        if (!bp_point_print(bp, group, L, NULL, 0, bn_ctx))
            goto end;
    }

    bp_bio_printf(bp, indent, "R[n]:\n");
    for (i = 0; i < n; i++) {
        R = sk_EC_POINT_value(ip_proof->sk_R, i);
        if (R == NULL)
            goto end;

        bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
        if (!bp_point_print(bp, group, R, NULL, 0, bn_ctx))
            goto end;
    }

    if (!bp_bn_print(bp, "a", ip_proof->a, NULL, indent)
        || !bp_bn_print(bp, "b", ip_proof->b, NULL, indent))
        goto end;

    ret = 1;
end:
    return ret;
}

#ifndef OPENSSL_NO_STDIO
int BP_PUB_PARAM_print_fp(FILE *fp, const BP_PUB_PARAM *pp, int indent)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = BP_PUB_PARAM_print(b, pp, indent);
    BIO_free(b);
    return ret;
}

int BP_WITNESS_print_fp(FILE *fp, const BP_WITNESS *witness, int indent, int flag)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = BP_WITNESS_print(b, witness, indent, flag);
    BIO_free(b);
    return ret;
}

int BP_RANGE_PROOF_print_fp(FILE *fp, const BP_RANGE_PROOF *proof, int indent)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = BP_RANGE_PROOF_print(b, proof, indent);
    BIO_free(b);
    return ret;
}

int BP_R1CS_PROOF_print_fp(FILE *fp, const BP_R1CS_PROOF *proof, int indent)
{
    BIO *b;
    int ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = BP_R1CS_PROOF_print(b, proof, indent);
    BIO_free(b);
    return ret;
}
#endif

int BP_PUB_PARAM_print(BIO *bp, const BP_PUB_PARAM *pp, int indent)
{
    int ret = 0, i, n, curve_id;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *G, *H;
    EC_GROUP *group = NULL;

    if (pp == NULL)
        return 0;

    curve_id = EC_GROUP_get_curve_name(pp->group);

    bp_bio_printf(bp, indent, "Bulletproofs Public Parameter: \n");
    bp_bio_printf(bp, indent, "curve: %s (%d)\n", OSSL_EC_curve_nid2name(curve_id),
                               curve_id);
    bp_bio_printf(bp, indent, "gens_capacity: %zu\n", pp->gens_capacity);
    bp_bio_printf(bp, indent, "party_capacity: %zu\n", pp->party_capacity);

    group = pp->group;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;

    bp_bio_printf(bp, indent, "G[n]:\n");
    n = pp->gens_capacity * pp->party_capacity;
    for (i = 0; i < n; i++) {
        G = sk_EC_POINT_value(pp->sk_G, i);
        if (G == NULL)
            goto end;

        bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
        if (!bp_point_print(bp, group, G, NULL, 0, bn_ctx))
            goto end;
    }

    bp_bio_printf(bp, indent, "H[n]:\n");
    for (i = 0; i < n; i++) {
        H = sk_EC_POINT_value(pp->sk_H, i);
        if (H == NULL)
            goto end;

        bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
        if (!bp_point_print(bp, group, H, NULL, 0, bn_ctx))
            goto end;
    }

    if (!bp_point_print(bp, group, pp->U, "U: ", indent, bn_ctx)
        || !bp_point_print(bp, group, pp->H, "H: ", indent, bn_ctx))
        goto end;

    ret = 1;
end:
    BN_CTX_free(bn_ctx);
    return ret;
}

int BP_WITNESS_print(BIO *bp, const BP_WITNESS *witness, int indent, int flag)
{
    int ret = 0, i, n, curve_id;
    BN_CTX *bn_ctx = NULL;
    BP_VARIABLE *var;
    BIGNUM *v, *r;
    EC_GROUP *group = NULL;

    if (witness == NULL)
        return 0;

    group = witness->group;
    curve_id = EC_GROUP_get_curve_name(group);

    bp_bio_printf(bp, indent, "Witness: \n");
    bp_bio_printf(bp, indent, "curve: %s (%d)\n", OSSL_EC_curve_nid2name(curve_id),
                               curve_id);

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;

    bp_bio_printf(bp, indent, "H: ");
    if (!bp_point_print(bp, group, witness->H, NULL, 0, bn_ctx))
        goto end;

    bp_bio_printf(bp, indent, "V[n]:\n");
    n = sk_BP_VARIABLE_num(witness->sk_V);
    for (i = 0; i < n; i++) {
        var = sk_BP_VARIABLE_value(witness->sk_V, i);
        if (var == NULL)
            goto end;

        if (var->name != NULL)
            bp_bio_printf(bp, indent + 4, "[%s]: ", var->name);
        else
            bp_bio_printf(bp, indent + 4, "[%zu]: ", i);

        if (!bp_point_print(bp, group, var->point, NULL, 0, bn_ctx))
            goto end;
    }

    n = sk_BIGNUM_num(witness->sk_v);
    if (n != 0 && flag == 1) {
        bp_bio_printf(bp, indent, "v[n]:\n");
        for (i = 0; i < n; i++) {
            var = sk_BP_VARIABLE_value(witness->sk_V, i);
            v = sk_BIGNUM_value(witness->sk_v, i);
            if (v == NULL)
                goto end;

            if (var->name != NULL)
                bp_bio_printf(bp, indent + 4, "[%s]: ", var->name);
            else
                bp_bio_printf(bp, indent + 4, "[%zu]: ", i);

            if (!bp_bn_print(bp, NULL, v, NULL, 0))
                goto end;
        }

        bp_bio_printf(bp, indent, "r[n]:\n");
        for (i = 0; i < n; i++) {
            r = sk_BIGNUM_value(witness->sk_r, i);
            if (r == NULL)
                goto end;

            bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
            if (!bp_bn_print(bp, NULL, r, NULL, 0))
                goto end;
        }
    }

    ret = 1;
end:
    BN_CTX_free(bn_ctx);
    return ret;
}

int BP_RANGE_PROOF_print(BIO *bp, const BP_RANGE_PROOF *proof, int indent)
{
    int ret = 0, curve_id;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (proof == NULL)
        return 0;

    bp_bio_printf(bp, indent, "Range Proof: \n");

    curve_id = EC_POINT_get_curve_name(proof->A);
    if (curve_id <= 0)
        goto end;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;

    if (!bp_point_print(bp, group, proof->A, "A: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->S, "S: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T1, "T1: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T2, "T2: ", indent, bn_ctx)
        || !bp_bn_print(bp, "taux", proof->taux, NULL, indent)
        || !bp_bn_print(bp, "mu", proof->mu, NULL, indent)
        || !bp_bn_print(bp, "tx", proof->tx, NULL, indent))
        goto end;

    if (proof->ip_proof != NULL) {
        ret = bp_inner_product_proof_print(bp, proof->ip_proof, group, bn_ctx, indent);
    } else {
        bp_bio_printf(bp, indent, "inner proof: not found\n");
    }

    ret = 1;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}

int BP_R1CS_PROOF_print(BIO *bp, const BP_R1CS_PROOF *proof, int indent)
{
    int ret = 0, curve_id;
    BN_CTX *bn_ctx = NULL;
    EC_GROUP *group = NULL;

    if (proof == NULL)
        return 0;

    bp_bio_printf(bp, indent, "R1CS Proof: \n");

    curve_id = EC_POINT_get_curve_name(proof->AI1);
    if (curve_id <= 0)
        goto end;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, curve_id);
    if (group == NULL)
        goto end;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;

    if (!bp_point_print(bp, group, proof->AI1, "AI1: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->AO1, "AO1: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->S1, "S1: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->AI2, "AI2: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->AO2, "AO2: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->S2, "S2: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T1, "T1: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T3, "T3: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T4, "T4: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T5, "T5: ", indent, bn_ctx)
        || !bp_point_print(bp, group, proof->T6, "T6: ", indent, bn_ctx)
        || !bp_bn_print(bp, "taux", proof->taux, NULL, indent)
        || !bp_bn_print(bp, "mu", proof->mu, NULL, indent)
        || !bp_bn_print(bp, "tx", proof->tx, NULL, indent))
        goto end;

    if (proof->ip_proof != NULL) {
        ret = bp_inner_product_proof_print(bp, proof->ip_proof, group, bn_ctx, indent);
    } else {
        bp_bio_printf(bp, indent, "inner proof: not found\n");
    }

    ret = 1;
end:
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}
