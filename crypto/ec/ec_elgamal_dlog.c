/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "ec_elgamal.h"
#include <openssl/err.h>
#include <string.h>

#define EC_ELGAMAL_MSG_BITS 32
#define EC_ELGAMAL_ECDLP_BABY_BITS 11
#define EC_ELGAMAL_ECDLP_GIANT_BITS (EC_ELGAMAL_MSG_BITS-EC_ELGAMAL_ECDLP_BABY_BITS)

static EC_ELGAMAL_dec_tbl_entry *EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_CTX *ctx,
                                                              EC_POINT *point,
                                                              int32_t value);
static void EC_ELGAMAL_dec_tbl_entry_free(EC_ELGAMAL_dec_tbl_entry *entry);

static unsigned long EC_ELGAMAL_dec_tbl_entry_hash(const EC_ELGAMAL_dec_tbl_entry *e)
{
    int i = e->key_len;
    unsigned char *p = e->key;

    while (*p == 0 && i-- > 0)
        p++;

    return ossl_lh_strcasehash((const char *)p);
}

static int EC_ELGAMAL_dec_tbl_entry_cmp(const EC_ELGAMAL_dec_tbl_entry *a,
                                        const EC_ELGAMAL_dec_tbl_entry *b)
{
    if (a->key_len != b->key_len)
        return -1;

    return memcmp(a->key, b->key, a->key_len);
}

/** Finds the value r with brute force s.t. M=rG
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting integer
 *  \param  M          EC_POINT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_dlog_brute(EC_ELGAMAL_CTX *ctx, int32_t *r, EC_POINT *M)
{
    int ret = 0;
    int64_t i = 1, max = 1LL << EC_ELGAMAL_MAX_BITS;
    const EC_POINT *G;
    EC_POINT *P = NULL;
    BN_CTX *bn_ctx = NULL;

    if (EC_POINT_is_at_infinity(ctx->key->group, M)) {
        ERR_raise(ERR_LIB_EC, EC_R_POINT_AT_INFINITY);
        goto err;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    P = EC_POINT_new(ctx->key->group);
    if (P == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    G = EC_GROUP_get0_generator(ctx->key->group);
    EC_POINT_set_to_infinity(ctx->key->group, P);

    for (; i < max; i++) {
        if (!EC_POINT_add(ctx->key->group, P, P, G, bn_ctx))
            goto err;
        if (EC_POINT_cmp(ctx->key->group, P, M, bn_ctx) == 0)
            break;
    }

    if (i >= max) {
        ERR_raise(ERR_LIB_EC, EC_R_ELGAMAL_DLOG_FAILED);
        goto err;
    }

    *r = (int32_t)i;
    ret = 1;

err:
    EC_POINT_free(P);
    BN_CTX_free(bn_ctx);
    return ret;
}

static
int EC_ELGAMAL_dec_tbl_entries_dlog(EC_ELGAMAL_CTX *ctx, int32_t *r,
                                    LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *entries,
                                    EC_POINT *M, EC_POINT *Q, BN_CTX *bn_ctx)
{
    int ret = 0;
    int64_t i, max;
    EC_POINT *P = NULL;
    EC_ELGAMAL_dec_tbl_entry *entry = NULL, *entry_res = NULL;

    max = 1L << ctx->decrypt_table->baby_step_bits;

    if ((P = EC_POINT_dup(M, ctx->key->group)) == NULL)
        goto err;

    for (i = 0; i < max; i++) {
        entry = EC_ELGAMAL_dec_tbl_entry_new(ctx, P, (int32_t)i);
        if (entry == NULL)
            goto err;

        entry_res = lh_EC_ELGAMAL_dec_tbl_entry_retrieve(entries, entry);
        if (entry_res != NULL) {
            ret = 1;
            *r = (int32_t)(i * ctx->decrypt_table->size + entry_res->value);
            break;
        }

        if (!EC_POINT_add(ctx->key->group, P, P, Q, bn_ctx))
            goto err;

        EC_ELGAMAL_dec_tbl_entry_free(entry);
        entry = NULL;
    }

err:
    EC_ELGAMAL_dec_tbl_entry_free(entry);
    EC_POINT_free(P);
    return ret;
}

/** Finds the value r with ecdlp bsgs hashtable.
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting integer
 *  \param  M          EC_POINT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_dlog_bsgs(EC_ELGAMAL_CTX *ctx, int32_t *r, EC_POINT *M)
{
    int ret = 0;
    int32_t result = 0;
    EC_POINT *Q = NULL;
    EC_ELGAMAL_DECRYPT_TABLE *table = ctx->decrypt_table;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return ret;
    }


    if (table->flag == 0 || (table->flag & EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE))
        ret = EC_ELGAMAL_dec_tbl_entries_dlog(ctx, &result, table->positive_entries,
                                              M, table->mG_inv, bn_ctx);

    if (ret) {
        *r = result;
    } else if (table->flag & (EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE |
                              EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE_FIRST |
                              EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE_ONLY)) {
        if ((Q = EC_POINT_dup(table->mG_inv, ctx->key->group)) == NULL)
            goto err;

        if (!EC_POINT_invert(ctx->key->group, Q, bn_ctx))
            goto err;

        ret = EC_ELGAMAL_dec_tbl_entries_dlog(ctx, &result,
                                              table->negative_entries, M, Q,
                                              bn_ctx);
        if (!ret && (table->flag & EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE_FIRST))
            ret = EC_ELGAMAL_dec_tbl_entries_dlog(ctx, &result, table->positive_entries,
                                                  M, table->mG_inv, bn_ctx);

        if (ret)
            *r = -result;
        else
            ERR_raise(ERR_LIB_EC, EC_R_ELGAMAL_DLOG_FAILED);
    }

err:
    EC_POINT_free(Q);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Creates a new EC_ELGAMAL_dec_tbl_entry object
 *  \param  ctx   EC_ELGAMAL_CTX object
 *  \param  point EC_POINT object
 *  \return newly created EC_ELGAMAL_dec_tbl_entry object or NULL in case of an error
 */
static EC_ELGAMAL_dec_tbl_entry *EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_CTX *ctx,
                                                              EC_POINT *point,
                                                              int32_t value)
{
    EC_ELGAMAL_dec_tbl_entry *entry = NULL;
    size_t point_size = 0, len = 0;
    unsigned char *point_key = NULL;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    point_size = EC_POINT_point2oct(ctx->key->group, point,
                                    POINT_CONVERSION_COMPRESSED, NULL, 0,
                                    bn_ctx);
    if (point_size <= 0)
        goto err;

    entry = OPENSSL_zalloc(sizeof(*entry));
    if (entry == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    point_key = OPENSSL_zalloc(point_size + 1);
    if (point_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((len = EC_POINT_point2oct(ctx->key->group, point,
                                  POINT_CONVERSION_COMPRESSED, point_key,
                                  point_size, bn_ctx)) != point_size)
        goto err;

    entry->key_len = (int)point_size;
    entry->key = point_key;
    entry->value = value;

    BN_CTX_free(bn_ctx);

    return entry;

err:
    OPENSSL_free(point_key);
    OPENSSL_free(entry);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_dec_tbl_entry object
 *  \param  entry  EC_ELGAMAL_dec_tbl_entry object to be freed
 */
static void EC_ELGAMAL_dec_tbl_entry_free(EC_ELGAMAL_dec_tbl_entry *entry)
{
    if (entry == NULL)
        return;

    OPENSSL_free(entry->key);
    OPENSSL_free(entry);
}

static int EC_ELGAMAL_dec_table_entries_init(EC_ELGAMAL_CTX *ctx,
                                             LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *entries,
                                             int32_t size, const EC_POINT *G,
                                             BN_CTX *bn_ctx)
{
    int ret = 0;
    int32_t i;
    EC_POINT *P;
    EC_GROUP *group;
    EC_ELGAMAL_dec_tbl_entry *entry = NULL, *entry_old = NULL;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    group = ctx->key->group;

    P = EC_POINT_new(group);
    if (P == NULL)
        return ret;

    EC_POINT_set_to_infinity(group, P);

    for (i = 0; i < size; i++) {
        entry = EC_ELGAMAL_dec_tbl_entry_new(ctx, P, i);
        if (entry == NULL)
            goto err;

        entry_old = lh_EC_ELGAMAL_dec_tbl_entry_insert(entries, entry);
        if (lh_EC_ELGAMAL_dec_tbl_entry_error(entries) && entry_old == NULL)
            goto err;

        if (entry_old != NULL)
            EC_ELGAMAL_dec_tbl_entry_free(entry_old);

        entry = NULL;

        if (!EC_POINT_add(group, P, P, G, bn_ctx))
            goto err;
    }

    ret = 1;
err:
    EC_ELGAMAL_dec_tbl_entry_free(entry);
    EC_POINT_free(P);
    return ret;
}

/** Creates a new EC_ELGAMAL_DECRYPT_TABLE object
 *  \param  ctx              EC_ELGAMAL_CTX object
 *  \param  decrypt_negative Whether negative numbers can be decrypted (1 or 0)
 *  \return newly created EC_ELGAMAL_DECRYPT_TABLE object or NULL in case of an error
 */
EC_ELGAMAL_DECRYPT_TABLE *EC_ELGAMAL_DECRYPT_TABLE_new(EC_ELGAMAL_CTX *ctx,
                                                       int32_t decrypt_negative)
{
    return EC_ELGAMAL_DECRYPT_TABLE_new_ex(ctx, EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE,
                                           EC_ELGAMAL_ECDLP_BABY_BITS,
                                           EC_ELGAMAL_ECDLP_GIANT_BITS);
}

/** Creates a new EC_ELGAMAL_DECRYPT_TABLE object with some extra paramers
 *  \param  ctx             EC_ELGAMAL_CTX object
 *  \param  flag            the flag of decrypt table
 *  \param  baby_step_bits  baby step exponent/bits
 *  \param  giant_step_bits giant step exponent/bits
 *  \return newly created EC_ELGAMAL_DECRYPT_TABLE object or NULL in case of an error
 */
EC_ELGAMAL_DECRYPT_TABLE *EC_ELGAMAL_DECRYPT_TABLE_new_ex(EC_ELGAMAL_CTX *ctx,
                                                          int32_t flag,
                                                          uint32_t baby_step_bits,
                                                          uint32_t giant_step_bits)
{
    int32_t size;
    EC_ELGAMAL_DECRYPT_TABLE *table = NULL;
    LHASH_OF(EC_ELGAMAL_dec_tbl_entry) *positive_entries = NULL, *negative_entries = NULL;
    EC_GROUP *group;
    EC_POINT *mG_inv = NULL, *Q = NULL;
    const EC_POINT *G;
    BIGNUM *bn_size = NULL;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (giant_step_bits > 32 || baby_step_bits > 32 ||
        (giant_step_bits + baby_step_bits) > 32)
        return NULL;

    size = 1L << giant_step_bits;
    group = ctx->key->group;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    table = OPENSSL_zalloc(sizeof(*table));
    if (table == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    table->size = size;

    bn_size = BN_CTX_get(bn_ctx);
    if (bn_size == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    BN_set_word(bn_size, (BN_ULONG)size);
    BN_set_negative(bn_size, 0);

    G = EC_GROUP_get0_generator(group);

    mG_inv = EC_POINT_new(group);
    if (mG_inv == NULL)
        goto err;

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (ctx->flag == EC_ELGAMAL_FLAG_TWISTED) {
        if (!EC_POINT_mul(group, mG_inv, NULL, ctx->h, bn_size, bn_ctx))
            goto err;
        G = ctx->h;
    } else
#endif
    if (!EC_POINT_mul(group, mG_inv, bn_size, NULL, NULL, bn_ctx))
        goto err;

    if (!EC_POINT_invert(group, mG_inv, bn_ctx))
        goto err;

    positive_entries = lh_EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_dec_tbl_entry_hash,
                                                       EC_ELGAMAL_dec_tbl_entry_cmp);
    if (positive_entries == NULL
        || !EC_ELGAMAL_dec_table_entries_init(ctx, positive_entries, size, G, bn_ctx))
        goto err;

    if (flag & (EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE |
                EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE_FIRST |
                EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE_ONLY)) {
        negative_entries = lh_EC_ELGAMAL_dec_tbl_entry_new(EC_ELGAMAL_dec_tbl_entry_hash,
                                                           EC_ELGAMAL_dec_tbl_entry_cmp);
        if (negative_entries == NULL)
            goto err;

        if ((Q = EC_POINT_dup(G, group)) == NULL)
            goto err;

        if (!EC_POINT_invert(group, Q, bn_ctx))
            goto err;

        if (!EC_ELGAMAL_dec_table_entries_init(ctx, negative_entries, size, Q, bn_ctx))
            goto err;

        EC_POINT_free(Q);
        table->flag |= EC_ELGAMAL_DECRYPT_TABLE_FLAG_NEGATIVE;
    }

    table->mG_inv = mG_inv;
    table->positive_entries = positive_entries;
    table->negative_entries = negative_entries;
    table->flag = flag;
    table->baby_step_bits = baby_step_bits;
    table->giant_step_bits = giant_step_bits;

    table->references = 1;
    table->lock = CRYPTO_THREAD_lock_new();

    BN_CTX_free(bn_ctx);

    return table;

err:
    lh_EC_ELGAMAL_dec_tbl_entry_doall(positive_entries, EC_ELGAMAL_dec_tbl_entry_free);
    lh_EC_ELGAMAL_dec_tbl_entry_free(positive_entries);

    lh_EC_ELGAMAL_dec_tbl_entry_doall(negative_entries, EC_ELGAMAL_dec_tbl_entry_free);
    lh_EC_ELGAMAL_dec_tbl_entry_free(negative_entries);

    EC_POINT_free(Q);
    EC_POINT_free(mG_inv);
    OPENSSL_free(table);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_DECRYPT_TABLE object
 *  \param  table  EC_ELGAMAL_DECRYPT_TABLE object to be freed
 */
void EC_ELGAMAL_DECRYPT_TABLE_free(EC_ELGAMAL_DECRYPT_TABLE *table)
{
    int i;

    if (table == NULL)
        return;

    CRYPTO_DOWN_REF(&table->references, &i, table->lock);

    if (i > 0)
        return;

    lh_EC_ELGAMAL_dec_tbl_entry_doall(table->positive_entries, EC_ELGAMAL_dec_tbl_entry_free);
    lh_EC_ELGAMAL_dec_tbl_entry_free(table->positive_entries);

    lh_EC_ELGAMAL_dec_tbl_entry_doall(table->negative_entries, EC_ELGAMAL_dec_tbl_entry_free);
    lh_EC_ELGAMAL_dec_tbl_entry_free(table->negative_entries);

    EC_POINT_free(table->mG_inv);
    CRYPTO_THREAD_lock_free(table->lock);
    OPENSSL_free(table);
}

/** Sets a EC_ELGAMAL_DECRYPT_TABLE object for decryption.
 *  \param  ctx   EC_ELGAMAL_CTX object
 *  \param  table EC_ELGAMAL_DECRYPT_TABLE object
 */
void EC_ELGAMAL_CTX_set_decrypt_table(EC_ELGAMAL_CTX *ctx,
                                      EC_ELGAMAL_DECRYPT_TABLE *table)
{
    int i;

    ctx->decrypt_table = table;
    CRYPTO_UP_REF(&table->references, &i, table->lock);
}
