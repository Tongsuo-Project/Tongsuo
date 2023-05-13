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

/* Number of octets per line */
#define ASN1_BUF_PRINT_WIDTH    127
/* Maximum indent */
#define ASN1_PRINT_MAX_INDENT   128

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

static int bp_bn_print(BIO *bp, const char *number, const BIGNUM *num,
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
        if (BIO_printf(bp, "%s: 0\n", number) <= 0)
            return 0;
        return 1;
    }

    if (BN_num_bytes(num) <= BN_BYTES) {
        if (BIO_printf(bp, "%s: %s%lu (%s0x%lx)\n", number, neg,
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
    if (BIO_printf(bp, "%s: %s", number, neg) <= 0)
        goto err;
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
#endif

int BP_PUB_PARAM_print(BIO *bp, const BP_PUB_PARAM *pp, int indent)
{
    int ret = 0, i, n, curve_id;
    size_t point_len;
    unsigned char *p = NULL;
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

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
    p = OPENSSL_zalloc(point_len);
    if (p == NULL)
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
    OPENSSL_free(p);
    BN_CTX_free(bn_ctx);
    return ret;
}

int BP_RANGE_PROOF_print(BIO *bp, const BP_RANGE_PROOF *proof, int indent)
{
    int ret = 0, curve_id, i, n;
    size_t point_len;
    unsigned char *p = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *L, *R;
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

    point_len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                   POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
    p = OPENSSL_zalloc(point_len);
    if (p == NULL)
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
        bp_bio_printf(bp, indent, "inner proof:\n");
        indent += 4;
        n = sk_EC_POINT_num(proof->ip_proof->sk_L);
        bp_bio_printf(bp, indent, "n: %zu\n", n);

        bp_bio_printf(bp, indent, "L[n]:\n");
        for (i = 0; i < n; i++) {
            L = sk_EC_POINT_value(proof->ip_proof->sk_L, i);
            if (L == NULL)
                goto end;

            bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
            if (!bp_point_print(bp, group, L, NULL, 0, bn_ctx))
                goto end;
        }

        bp_bio_printf(bp, indent, "R[n]:\n");
        for (i = 0; i < n; i++) {
            R = sk_EC_POINT_value(proof->ip_proof->sk_R, i);
            if (R == NULL)
                goto end;

            bp_bio_printf(bp, indent + 4, "[%zu]: ", i);
            if (!bp_point_print(bp, group, R, NULL, 0, bn_ctx))
                goto end;
        }

        if (!bp_bn_print(bp, "a", proof->ip_proof->a, NULL, indent)
            || !bp_bn_print(bp, "b", proof->ip_proof->b, NULL, indent))
            goto end;

    } else {
        bp_bio_printf(bp, indent, "inner proof: not found\n");
    }

    ret = 1;
end:
    OPENSSL_free(p);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
    return ret;
}
