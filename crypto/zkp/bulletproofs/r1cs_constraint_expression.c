/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/err.h>
#include <crypto/ec.h>
#include "crypto/ctype.h"
#include "internal/cryptlib.h"
#include <openssl/bulletproofs.h>
#include "r1cs.h"

typedef struct bp_r1cs_expression_st {
    char *expression;
    int len;
    int pos;
    int is_prove;
    int var_found;
} bp_r1cs_expression_t;

DEFINE_STACK_OF(BP_R1CS_LINEAR_COMBINATION_ITEM)

static bp_r1cs_expression_t *bp_r1cs_expression_new(const char *exp_str, int is_prove);
static void bp_r1cs_expression_free(bp_r1cs_expression_t *e);
static int bp_r1cs_expression_evaluate_expression(bp_r1cs_expression_t *e,
                                                  BP_R1CS_LINEAR_COMBINATION *lc,
                                                  BP_R1CS_CTX *ctx);
static int bp_r1cs_expression_evaluate_term(bp_r1cs_expression_t *e,
                                            BP_R1CS_LINEAR_COMBINATION *lc,
                                            BP_R1CS_CTX *ctx);
static int bp_r1cs_expression_evaluate_factor(bp_r1cs_expression_t *e,
                                              BP_R1CS_LINEAR_COMBINATION *lc,
                                              BP_R1CS_CTX *ctx);
static int bp_r1cs_expression_evaluate_number(bp_r1cs_expression_t *e,
                                              BP_R1CS_LINEAR_COMBINATION *lc,
                                              BP_R1CS_CTX *ctx);
static int bp_r1cs_expression_evaluate_variable(bp_r1cs_expression_t *e,
                                                BP_R1CS_LINEAR_COMBINATION *lc,
                                                BP_R1CS_CTX *ctx);
static void bp_r1cs_expression_skip_whitespace(bp_r1cs_expression_t *e);

static bp_r1cs_expression_t *bp_r1cs_expression_new(const char *exp_str, int is_prove)
{
    bp_r1cs_expression_t *e;

    if (exp_str == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    e = OPENSSL_malloc(sizeof(*e));
    if (e == NULL) {
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    e->expression = OPENSSL_strdup(exp_str);
    if (e->expression == NULL) {
        OPENSSL_free(e);
        ERR_raise(ERR_LIB_ZKP_BP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    e->len = strlen(e->expression);
    e->pos = 0;
    e->var_found = 0;
    e->is_prove = is_prove;

    return e;
}

static void bp_r1cs_expression_free(bp_r1cs_expression_t *e)
{
    if (e == NULL)
        return;

    OPENSSL_free(e->expression);
    OPENSSL_free(e);
}

static int bp_r1cs_expression_evaluate_expression(bp_r1cs_expression_t *e,
                                                  BP_R1CS_LINEAR_COMBINATION *lc,
                                                  BP_R1CS_CTX *ctx)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *right = NULL;

    if (e == NULL)
        return 0;

    if (!bp_r1cs_expression_evaluate_term(e, lc, ctx))
        return 0;

    right = BP_R1CS_LINEAR_COMBINATION_new();
    if (right == NULL)
        return 0;

    while (e->expression[e->pos] == '+' || e->expression[e->pos] == '-') {
        char operator = e->expression[e->pos++];
        bp_r1cs_expression_skip_whitespace(e);

        if (!bp_r1cs_expression_evaluate_term(e, right, ctx))
            goto err;

        if (operator == '+') {
            if (!BP_R1CS_LINEAR_COMBINATION_add(lc, right))
                goto err;
        } else {
            if (!BP_R1CS_LINEAR_COMBINATION_sub(lc, right))
                goto err;
        }

        if (!BP_R1CS_LINEAR_COMBINATION_clean(right))
            goto err;
    }

    bp_r1cs_expression_skip_whitespace(e);
    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(right);
    return ret;
}

static int bp_r1cs_expression_evaluate_term(bp_r1cs_expression_t *e,
                                            BP_R1CS_LINEAR_COMBINATION *lc,
                                            BP_R1CS_CTX *ctx)
{
    int ret = 0;
    BP_R1CS_LINEAR_COMBINATION *right = NULL;

    if (e == NULL)
        return 0;

    if (!bp_r1cs_expression_evaluate_factor(e, lc, ctx))
        return 0;

    right = BP_R1CS_LINEAR_COMBINATION_new();
    if (right == NULL)
        return 0;

    while (e->expression[e->pos] == '*') {
        e->pos++;
        bp_r1cs_expression_skip_whitespace(e);

        if (!bp_r1cs_expression_evaluate_factor(e, right, ctx))
            goto err;

        if (!BP_R1CS_LINEAR_COMBINATION_mul(lc, right, ctx))
            goto err;

        if (!BP_R1CS_LINEAR_COMBINATION_clean(right))
            goto err;
    }

    ret = 1;

err:
    BP_R1CS_LINEAR_COMBINATION_free(right);
    return ret;
}

static int bp_r1cs_expression_evaluate_factor(bp_r1cs_expression_t *e,
                                              BP_R1CS_LINEAR_COMBINATION *lc,
                                              BP_R1CS_CTX *ctx)
{
    if (e == NULL)
        return 0;

    if (e->expression[e->pos] == '(') {
        e->pos++;
        bp_r1cs_expression_skip_whitespace(e);
        if (!bp_r1cs_expression_evaluate_expression(e, lc, ctx))
            return 0;

        if (e->expression[e->pos] != ')') {
            ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_R1CS_CONSTRAINT_EXPRESSION_FORMAT_ERROR);
            return 0;
        }

        e->pos++;
        return 1;
    } else if (ossl_isalpha(e->expression[e->pos])) {
        return bp_r1cs_expression_evaluate_variable(e, lc, ctx);
    } else if (ossl_isdigit(e->expression[e->pos])) {
        return bp_r1cs_expression_evaluate_number(e, lc, ctx);
    }

    return 0;
}

static int bp_r1cs_expression_evaluate_number(bp_r1cs_expression_t *e,
                                              BP_R1CS_LINEAR_COMBINATION *lc,
                                              BP_R1CS_CTX *ctx)
{
    int number = 0;
    BIGNUM *bn = NULL;
    BP_R1CS_LC_ITEM *item = NULL;

    if (e == NULL)
        return 0;

    if (!ossl_isdigit(e->expression[e->pos]))
        return 0;

    while (ossl_isdigit(e->expression[e->pos])) {
        number = 10 * number + (e->expression[e->pos] - '0');
        e->pos++;
    }

    bp_r1cs_expression_skip_whitespace(e);

    bn = BN_new();
    if (bn == NULL)
        return 0;

    BN_set_word(bn, number);

    if ((item = BP_R1CS_LC_ITEM_new(NULL, bn)) == NULL
        || sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc->items, item) <= 0)
        goto err;

    lc->type = e->is_prove ? BP_R1CS_LC_TYPE_PROVE : BP_R1CS_LC_TYPE_VERIFY;

    BN_free(bn);
    return 1;
err:
    BN_free(bn);
    BP_R1CS_LC_ITEM_free(item);
    return 0;
}

static int bp_r1cs_expression_evaluate_variable(bp_r1cs_expression_t *e,
                                                BP_R1CS_LINEAR_COMBINATION *lc,
                                                BP_R1CS_CTX *ctx)
{
    int i = 0;
    char var[BP_VARIABLE_NAME_MAX_LEN + 1];
    BP_R1CS_VARIABLE *r1cs_var = NULL;
    BP_R1CS_LC_ITEM *item = NULL;

    if (e == NULL)
        return 0;

    if (!ossl_isalpha(e->expression[e->pos]))
        return 0;

    memset(var, 0, sizeof(var));

    while (ossl_isalpha(e->expression[e->pos]) || ossl_isdigit(e->expression[e->pos])
           || e->expression[e->pos] == '_') {
        if (i > BP_VARIABLE_NAME_MAX_LEN) {
            ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_R1CS_CONSTRAINT_EXPRESSION_VAR_TOO_LONG);
            return 0;
        }

        var[i++] = e->expression[e->pos++];
    }

    bp_r1cs_expression_skip_whitespace(e);

    i = BP_WITNESS_get_variable_index(ctx->witness, var);
    if (i < 0) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_R1CS_CONSTRAINT_EXPRESSION_VAR_NOT_FOUND);
        return 0;
    }

    if ((r1cs_var = BP_R1CS_VARIABLE_new(BP_R1CS_VARIABLE_COMMITTED, i)) == NULL)
        goto err;

    if ((item = BP_R1CS_LC_ITEM_new(r1cs_var, NULL)) == NULL
        || sk_BP_R1CS_LINEAR_COMBINATION_ITEM_push(lc->items, item) <= 0)
        goto err;

    lc->type = e->is_prove ? BP_R1CS_LC_TYPE_PROVE : BP_R1CS_LC_TYPE_VERIFY;
    e->var_found = 1;

    BP_R1CS_VARIABLE_free(r1cs_var);
    return 1;
err:
    BP_R1CS_VARIABLE_free(r1cs_var);
    BP_R1CS_LC_ITEM_free(item);
    return 0;
}

static void bp_r1cs_expression_skip_whitespace(bp_r1cs_expression_t *e)
{
    if (e == NULL)
        return;

    while (ossl_isspace(e->expression[e->pos]))
        e->pos++;
}

static int bp_r1cs_expression_process(bp_r1cs_expression_t *e,
                                      BP_R1CS_LINEAR_COMBINATION *lc,
                                      BP_R1CS_CTX *ctx)
{
    if (!bp_r1cs_expression_evaluate_expression(e, lc, ctx)) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_R1CS_CONSTRAINT_EXPRESSION_PROCESS_ERROR);
        return 0;
    }

    if (e->pos != e->len) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_R1CS_CONSTRAINT_EXPRESSION_FORMAT_ERROR);
        return 0;
    }

    if (!e->var_found) {
        ERR_raise(ERR_LIB_ZKP_BP, ZKP_BP_R_R1CS_CONSTRAINT_EXPRESSION_NO_VAR);
        return 0;
    }

    return 1;
}

int BP_R1CS_constraint_expression(BP_R1CS_CTX *ctx, const char *constraint, int is_prove)
{
    int ret = 0;
    bp_r1cs_expression_t *e = NULL;
    BP_R1CS_LINEAR_COMBINATION *lc = NULL;

    e = bp_r1cs_expression_new(constraint, is_prove);
    lc = BP_R1CS_LINEAR_COMBINATION_new();
    if (e == NULL || lc == NULL)
        goto err;

    if (!bp_r1cs_expression_process(e, lc, ctx))
        goto err;

    ret = BP_R1CS_LINEAR_COMBINATION_constrain(lc, ctx);

err:
    BP_R1CS_LINEAR_COMBINATION_free(lc);
    bp_r1cs_expression_free(e);
    return ret;
}
