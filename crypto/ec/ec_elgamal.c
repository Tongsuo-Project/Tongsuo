/*
 * Copyright 2021 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

#include "ec_elgamal.h"
#include <string.h>

static EC_ELGAMAL_BSGS_ENTRY *EC_ELGAMAL_BSGS_ENTRY_new(EC_ELGAMAL_CTX *ctx,
                                                        EC_POINT *point,
                                                        uint32_t value);
static void EC_ELGAMAL_BSGS_ENTRY_free(EC_ELGAMAL_BSGS_ENTRY *entry);

static EC_ELGAMAL_BSGS_HASH_TABLE *EC_ELGAMAL_BSGS_HASH_TABLE_new(EC_ELGAMAL_CTX *ctx,
                                                                  uint32_t size);
static void EC_ELGAMAL_BSGS_HASH_TABLE_free(EC_ELGAMAL_BSGS_HASH_TABLE *table);

static unsigned long EC_ELGAMAL_BSGS_ENTRY_hash(const EC_ELGAMAL_BSGS_ENTRY *e)
{
    int i = e->key_len;
    unsigned char *p = e->key;

    while (*p == 0 && i-- > 0) {
        p++;
    }

    return openssl_lh_strcasehash((const char *)p);
}

static int EC_ELGAMAL_BSGS_ENTRY_cmp(const EC_ELGAMAL_BSGS_ENTRY *a,
                                     const EC_ELGAMAL_BSGS_ENTRY *b)
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
static int EC_ELGAMAL_discrete_log_brute(EC_ELGAMAL_CTX *ctx, uint32_t *r,
                                         EC_POINT *M)
{
    int ret = 0;
    uint64_t i = 1, max = 1L << EC_ELGAMAL_MAX_BITS;
    const EC_POINT *G;
    EC_POINT *P = NULL;
    BN_CTX *bn_ctx = NULL;

    if (EC_POINT_is_at_infinity(ctx->key->group, M))
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    P = EC_POINT_new(ctx->key->group);
    if (P == NULL)
        goto err;

    G = EC_GROUP_get0_generator(ctx->key->group);
    EC_POINT_set_to_infinity(ctx->key->group, P);

    for (; i < max; i++) {
        if (!EC_POINT_add(ctx->key->group, P, P, G, bn_ctx))
            goto err;
        if (EC_POINT_cmp(ctx->key->group, P, M, bn_ctx) == 0)
            break;
    }

    *r = i;
    ret = 1;

err:
    EC_POINT_free(P);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Finds the value r with ecdlp bsgs hashtable.
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting integer
 *  \param  M          EC_POINT object
 *  \return 1 on success and 0 otherwise
 */
static int EC_ELGAMAL_discrete_log_bsgs(EC_ELGAMAL_CTX *ctx, uint32_t *r,
                                        EC_POINT *M)
{
    uint64_t i = 0, max = 1L << EC_ELGAMAL_MAX_BITS;
    EC_POINT *P = NULL;
    EC_ELGAMAL_BSGS_ENTRY *entry = NULL, *entry_res = NULL;
    EC_ELGAMAL_BSGS_HASH_TABLE *table = ctx->bsgs_hash_table;

    if ((P = EC_POINT_dup(M, ctx->key->group)) == NULL)
		goto err;

    while (i <= max) {
        entry = EC_ELGAMAL_BSGS_ENTRY_new(ctx, P, i);
        if (entry == NULL)
            goto err;

        entry_res = lh_EC_ELGAMAL_BSGS_ENTRY_retrieve(table->bsgs_entries, entry);
        if (entry_res != NULL) {
            *r = i * table->size + entry_res->value;
            EC_ELGAMAL_BSGS_ENTRY_free(entry);
            break;
        }
        if (!EC_POINT_add(ctx->key->group, P, P, table->mG_neg, NULL))
			goto err;

        EC_ELGAMAL_BSGS_ENTRY_free(entry);
        i++;
    }

    if (i > max)
		goto err;

    EC_POINT_free(P);
    return 1;

err:
    EC_ELGAMAL_BSGS_ENTRY_free(entry);
    EC_POINT_free(P);
	return 0;
}

/** Creates a new EC_ELGAMAL_BSGS_ENTRY object
 *  \param  ctx   EC_ELGAMAL_CTX object
 *  \param  point EC_POINT object
 *  \return newly created EC_ELGAMAL_BSGS_ENTRY object or NULL in case of an error
 */
static EC_ELGAMAL_BSGS_ENTRY *EC_ELGAMAL_BSGS_ENTRY_new(EC_ELGAMAL_CTX *ctx,
                                                        EC_POINT *point,
                                                        uint32_t value)
{
    EC_ELGAMAL_BSGS_ENTRY *entry = NULL;
    size_t point_size = 0, len = 0;
    unsigned char *point_key = NULL;
    BN_CTX *bn_ctx = NULL;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    point_size = EC_POINT_point2oct(ctx->key->group, point,
                                    POINT_CONVERSION_COMPRESSED, NULL, 0,
                                    bn_ctx);
    if (point_size <= 0)
        goto err;

    entry = OPENSSL_zalloc(sizeof(EC_ELGAMAL_BSGS_ENTRY));
    if (entry == NULL)
        goto err;

    point_key = OPENSSL_zalloc(point_size + 1);
    if (point_key == NULL)
        goto err;

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

/** Frees a EC_ELGAMAL_BSGS_ENTRY object
 *  \param  entry  EC_ELGAMAL_BSGS_ENTRY object to be freed
 */
static void EC_ELGAMAL_BSGS_ENTRY_free(EC_ELGAMAL_BSGS_ENTRY *entry)
{
    if (entry == NULL)
        return;

    OPENSSL_free(entry->key);
    OPENSSL_free(entry);
}

/** Creates a new EC_ELGAMAL_BSGS_HASH_TABLE object
 *  \param  ctx   EC_ELGAMAL_CTX object
 *  \param  size  the size of the ecdlp bsgs hash table
 *  \return newly created EC_ELGAMAL_BSGS_HASH_TABLE object or NULL in case of an error
 */
static EC_ELGAMAL_BSGS_HASH_TABLE *EC_ELGAMAL_BSGS_HASH_TABLE_new(EC_ELGAMAL_CTX *ctx,
                                                                  uint32_t size)
{
    EC_ELGAMAL_BSGS_HASH_TABLE *table = NULL;
    EC_ELGAMAL_BSGS_ENTRY *entry = NULL, *entry_old = NULL;
    LHASH_OF(EC_ELGAMAL_BSGS_ENTRY) *entries = NULL;
    EC_POINT *P = NULL, *mG_neg = NULL;
    const EC_POINT *G;
    BIGNUM *bn_size = NULL;
    BN_CTX *bn_ctx = NULL;
    uint32_t i;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    table = OPENSSL_zalloc(sizeof(EC_ELGAMAL_BSGS_HASH_TABLE));
    if (table == NULL)
        goto err;

    table->size = size;

    bn_size = BN_CTX_get(bn_ctx);
    if (bn_size == NULL)
        goto err;
    BN_set_word(bn_size,  (BN_ULONG)size);
    BN_set_negative(bn_size, 1);

    G = EC_GROUP_get0_generator(ctx->key->group);

    mG_neg = EC_POINT_new(ctx->key->group);
    if (mG_neg == NULL)
        goto err;

    if (!EC_POINT_mul(ctx->key->group, mG_neg, bn_size, NULL, NULL, bn_ctx))
        goto err;

    table->mG_neg = mG_neg;

    entries = lh_EC_ELGAMAL_BSGS_ENTRY_new(EC_ELGAMAL_BSGS_ENTRY_hash,
                                           EC_ELGAMAL_BSGS_ENTRY_cmp);
    if (entries == NULL)
        goto err;

    P = EC_POINT_new(ctx->key->group);
    if (P == NULL)
        goto err;

    EC_POINT_set_to_infinity(ctx->key->group, P);
    for (i = 0; i <= size; i++) {
        entry = EC_ELGAMAL_BSGS_ENTRY_new(ctx, P, i);
        if (entry == NULL)
            goto err;

        entry_old = lh_EC_ELGAMAL_BSGS_ENTRY_insert(entries, entry);
        if (lh_EC_ELGAMAL_BSGS_ENTRY_error(entries) && entry_old == NULL)
            goto err;

        if (entry_old != NULL)
            EC_ELGAMAL_BSGS_ENTRY_free(entry_old);

        entry = NULL;

        if (!EC_POINT_add(ctx->key->group, P, P, G, bn_ctx))
            goto err;
    }

    table->bsgs_entries = entries;

    EC_POINT_free(P);
    BN_CTX_free(bn_ctx);

    return table;

err:
    EC_ELGAMAL_BSGS_ENTRY_free(entry);
    lh_EC_ELGAMAL_BSGS_ENTRY_doall(entries, EC_ELGAMAL_BSGS_ENTRY_free);
    lh_EC_ELGAMAL_BSGS_ENTRY_free(entries);
    EC_POINT_free(P);
    EC_POINT_free(mG_neg);
    OPENSSL_free(table);
    BN_CTX_free(bn_ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_BSGS_HASH_TABLE object
 *  \param  table  EC_ELGAMAL_BSGS_HASH_TABLE object to be freed
 */
static void EC_ELGAMAL_BSGS_HASH_TABLE_free(EC_ELGAMAL_BSGS_HASH_TABLE *table)
{
    if (table == NULL)
        return;

    lh_EC_ELGAMAL_BSGS_ENTRY_doall(table->bsgs_entries, EC_ELGAMAL_BSGS_ENTRY_free);

    lh_EC_ELGAMAL_BSGS_ENTRY_free(table->bsgs_entries);
    EC_POINT_free(table->mG_neg);
    OPENSSL_free(table);
}

/** Creates a new EC_ELGAMAL object
 *  \param  key  EC_KEY to use
 *  \param  bsgs_htable_size  Specified the size of the ecdlp bsgs hash table,
 *                            and if set to 0, the bsgs algorithm is not used,
 *                            but the brute algorithm is used
 *  \return newly created EC_ELGAMAL_CTX object or NULL in case of an error
 */
EC_ELGAMAL_CTX *EC_ELGAMAL_CTX_new(EC_KEY *key, uint32_t bsgs_htable_size)
{
    EC_ELGAMAL_CTX *ctx = NULL;

    if (key == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(EC_ELGAMAL_CTX));
    if (ctx == NULL)
        goto err;

    EC_KEY_up_ref(key);
    ctx->key = key;

    if (bsgs_htable_size > 0) {
        ctx->bsgs_hash_table = EC_ELGAMAL_BSGS_HASH_TABLE_new(ctx, bsgs_htable_size);
        if (ctx->bsgs_hash_table == NULL)
            goto err;
    }

    return ctx;

err:
    OPENSSL_free(ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_CTX object
 *  \param  ctx  EC_ELGAMAL_CTX object to be freed
 */
void EC_ELGAMAL_CTX_free(EC_ELGAMAL_CTX *ctx)
{
    if (ctx == NULL)
        return;

    EC_KEY_free(ctx->key);
    EC_ELGAMAL_BSGS_HASH_TABLE_free(ctx->bsgs_hash_table);
    OPENSSL_free(ctx);
}

/** Creates a new EC_ELGAMAL_CIPHERTEXT object for EC-ELGAMAL oparations
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \return newly created EC_ELGAMAL_CIPHERTEXT object or NULL in case of an error
 */
EC_ELGAMAL_CIPHERTEXT *EC_ELGAMAL_CIPHERTEXT_new(EC_ELGAMAL_CTX *ctx)
{
    EC_POINT *C1 = NULL, *C2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *ciphertext;

    ciphertext = OPENSSL_zalloc(sizeof(EC_ELGAMAL_CIPHERTEXT));
    if (ciphertext == NULL)
        return NULL;

    C1 = EC_POINT_new(ctx->key->group);
    if (C1 == NULL)
        goto err;

    C2 = EC_POINT_new(ctx->key->group);
    if (C2 == NULL)
        goto err;

    ciphertext->C1 = C1;
    ciphertext->C2 = C2;

    return ciphertext;

err:
    EC_POINT_free(C1);
    EC_POINT_free(C2);
    OPENSSL_free(ciphertext);
    return NULL;
}

/** Frees a EC_ELGAMAL_CIPHERTEXT object
 *  \param  ciphertext  EC_ELGAMAL_CIPHERTEXT object to be freed
 */
void EC_ELGAMAL_CIPHERTEXT_free(EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    if (ciphertext == NULL)
        return;

    EC_POINT_free(ciphertext->C1);
    EC_POINT_free(ciphertext->C2);

    OPENSSL_free(ciphertext);
}

/** Encodes EC_ELGAMAL_CIPHERTEXT to binary
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  out        the buffer for the result (if NULL the function returns
 *                     number of bytes needed).
 *  \param  size       The memory size of the out pointer object
 *  \param  ciphertext EC_ELGAMAL_CIPHERTEXT object
 *  \param  compressed Whether to compress the encoding (either 0 or 1)
 *  \return the length of the encoded octet string or 0 if an error occurred
 */
size_t EC_ELGAMAL_CIPHERTEXT_encode(EC_ELGAMAL_CTX *ctx, unsigned char *out,
                                    size_t size, EC_ELGAMAL_CIPHERTEXT *ciphertext,
                                    int compressed)
{
    size_t point_len, ret = 0, len;
    unsigned char *p = out;
    point_conversion_form_t form = compressed ? POINT_CONVERSION_COMPRESSED :
                                                POINT_CONVERSION_UNCOMPRESSED;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto end;

    point_len = EC_POINT_point2oct(ctx->key->group,
                                   EC_GROUP_get0_generator(ctx->key->group),
                                   form, NULL, 0, bn_ctx);
    len = point_len * 2;
    if (out == NULL) {
        ret = len;
        goto end;
    }

    if (size < len)
        goto end;

    if (ciphertext == NULL || ciphertext->C1 == NULL || ciphertext->C2 == NULL)
        goto end;

    if (EC_POINT_point2oct(ctx->key->group, ciphertext->C1, form, p, point_len,
                           bn_ctx) != point_len)
        goto end;

    p += point_len;

    if (EC_POINT_point2oct(ctx->key->group, ciphertext->C2, form, p, point_len,
                           bn_ctx) != point_len)
        goto end;

    ret = len;

end:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Decodes binary to EC_ELGAMAL_CIPHERTEXT
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          the resulting ciphertext
 *  \param  in         Memory buffer with the encoded EC_ELGAMAL_CIPHERTEXT
 *                     object
 *  \param  size       The memory size of the in pointer object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_CIPHERTEXT_decode(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                                 unsigned char *in, size_t size)
{
    int ret = 0;
    size_t point_len;
    unsigned char *p = in;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || r->C1 == NULL ||
        r->C2 == NULL || size % 2 != 0)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    point_len = EC_POINT_point2oct(ctx->key->group,
                                   EC_GROUP_get0_generator(ctx->key->group),
                                   POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
    if (size < (point_len * 2))
        goto err;

    point_len = size / 2;

    if (!EC_POINT_oct2point(ctx->key->group, r->C1, p, point_len, bn_ctx))
        goto err;

    p += point_len;

    if (!EC_POINT_oct2point(ctx->key->group, r->C2, p, point_len, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Encrypts an Integer with additadive homomorphic EC-ElGamal
 *  \param  ctx        EC_ELGAMAL_CTX object.
 *  \param  r          EC_ELGAMAL_CIPHERTEXT object that stores the result of
 *                     the encryption
 *  \param  plaintext  The plaintext integer to be encrypted
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_encrypt(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r, uint32_t plaintext)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_plain = NULL, *ord = NULL, *rand = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub_key == NULL || r == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    bn_plain = BN_CTX_get(bn_ctx);
    ord = BN_CTX_get(bn_ctx);
    rand = BN_CTX_get(bn_ctx);
    if (rand == NULL)
        goto err;

    if (r->C1 == NULL) {
        r->C1 = EC_POINT_new(ctx->key->group);
        if (r->C1 == NULL)
            goto err;
    }

    if (r->C2 == NULL) {
        r->C2 = EC_POINT_new(ctx->key->group);
        if (r->C2 == NULL)
            goto err;
    }

    EC_GROUP_get_order(ctx->key->group, ord, bn_ctx);
    BN_rand_range(rand, ord);

    BN_set_word(bn_plain, plaintext);

    if (!EC_POINT_mul(ctx->key->group, r->C1, rand, NULL, NULL, bn_ctx))
        goto err;

    if (!EC_POINT_mul(ctx->key->group, r->C2, bn_plain, ctx->key->pub_key,
                      rand, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);

    if (!ret) {
        EC_POINT_free(r->C1);
        EC_POINT_free(r->C2);
        r->C1 = NULL;
        r->C2 = NULL;
    }

    return ret;
}

/** Decrypts the ciphertext
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The resulting plaintext integer
 *  \param  cihpertext EC_ELGAMAL_CIPHERTEXT object to be decrypted
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_decrypt(EC_ELGAMAL_CTX *ctx, uint32_t *r, EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    int ret = 0;
    uint32_t plaintext;
    EC_POINT *M = NULL;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->priv_key == NULL || r == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    M = EC_POINT_new(ctx->key->group);
    if (M == NULL)
        goto err;

    if (!EC_POINT_mul(ctx->key->group, M, NULL, ciphertext->C1,
                      ctx->key->priv_key, bn_ctx))
        goto err;

    if (!EC_POINT_invert(ctx->key->group, M, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, M, ciphertext->C2, M, bn_ctx))
        goto err;

    if (ctx->bsgs_hash_table != NULL) {
        if (!EC_ELGAMAL_discrete_log_bsgs(ctx, &plaintext, M))
            goto err;
    } else {
        if (!EC_ELGAMAL_discrete_log_brute(ctx, &plaintext, M))
            goto err;
    }

    *r = plaintext;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    EC_POINT_free(M);
    return ret;
}

/** Adds two EC-Elgamal ciphertext and stores it in r (r = c1 + c2).
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The EC_ELGAMAL_CIPHERTEXT object that stores the addition
 *                     result
 *  \param  c1         EC_ELGAMAL_CIPHERTEXT object
 *  \param  c2         EC_ELGAMAL_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_add(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                   EC_ELGAMAL_CIPHERTEXT *c1, EC_ELGAMAL_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c1 == NULL || c2 == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C1, c1->C1, c2->C1, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C2, c1->C2, c2->C2, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Substracts two EC-Elgamal ciphertext and stores it in r (r = c1 - c2).
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The EC_ELGAMAL_CIPHERTEXT object that stores the
 *                     subtraction result
 *  \param  c1         EC_ELGAMAL_CIPHERTEXT object
 *  \param  c2         EC_ELGAMAL_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_sub(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                   EC_ELGAMAL_CIPHERTEXT *c1, EC_ELGAMAL_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_1 = NULL;
    EC_POINT *C2C1_neg = NULL, *C2C2_neg = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c1 == NULL || c2 == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    if ((C2C1_neg = EC_POINT_dup(c2->C1, ctx->key->group)) == NULL)
        goto err;

    if ((C2C2_neg = EC_POINT_dup(c2->C2, ctx->key->group)) == NULL)
        goto err;

    bn_1 = BN_CTX_get(bn_ctx);
    if (bn_1 == NULL)
        goto err;
    BN_set_word(bn_1,  (BN_ULONG)1);
    BN_set_negative(bn_1, 1);

    if (!EC_POINT_mul(ctx->key->group, C2C1_neg, NULL, C2C1_neg, bn_1, bn_ctx))
        goto err;

    if (!EC_POINT_mul(ctx->key->group, C2C2_neg, NULL, C2C2_neg, bn_1, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C1, c1->C1, C2C1_neg, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C2, c1->C2, C2C2_neg, bn_ctx))
        goto err;

    ret = 1;

err:
    EC_POINT_free(C2C1_neg);
    EC_POINT_free(C2C2_neg);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Ciphertext multiplication, computes r = c * m
 *  \param  ctx        EC_ELGAMAL_CTX object
 *  \param  r          The EC_ELGAMAL_CIPHERTEXT object that stores the
 *                     multiplication result
 *  \param  c1         EC_ELGAMAL_CIPHERTEXT object
 *  \param  c2         EC_ELGAMAL_CIPHERTEXT object
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_mul(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                   EC_ELGAMAL_CIPHERTEXT *c, uint32_t m)
{
    int ret = 0;
    BIGNUM *bn_m;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c == NULL)
        return ret;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL)
        goto err;

    bn_m = BN_CTX_get(bn_ctx);
    if (bn_m == NULL)
        goto err;
    BN_set_word(bn_m,  (BN_ULONG)m);

    if (!EC_POINT_mul(ctx->key->group, r->C1, NULL, c->C1, bn_m, bn_ctx))
        goto err;

    if (!EC_POINT_mul(ctx->key->group, r->C2, NULL, c->C2, bn_m, bn_ctx))
        goto err;

    ret = 1;

err:
    BN_CTX_free(bn_ctx);
    return ret;
}
