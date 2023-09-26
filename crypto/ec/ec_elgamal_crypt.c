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

DEFINE_STACK_OF(EC_KEY)
DEFINE_STACK_OF(EC_POINT)

/** Creates a new EC_ELGAMAL_CTX object
 *  \param  key      EC_KEY to use
 *  \param  h        EC_POINT object pointer
 *  \param  flag     flag of ctx
 *  \return newly created EC_ELGAMAL_CTX object or NULL in case of an error
 */
EC_ELGAMAL_CTX *EC_ELGAMAL_CTX_new(EC_KEY *key, const EC_POINT *h, int32_t flag)
{
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    size_t len;
    unsigned char *buf = NULL;
    BN_CTX *bn_ctx = NULL;
#endif
    EC_ELGAMAL_CTX *ctx = NULL;

    if (key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (flag == EC_ELGAMAL_FLAG_TWISTED) {
        bn_ctx = BN_CTX_new();
        if (bn_ctx == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (h != NULL) {
            if (!(ctx->h = EC_POINT_dup(h, key->group)))
                return 0;
        } else {
            ctx->h = EC_POINT_new(key->group);
            if (ctx->h == NULL) {
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            len = EC_POINT_point2oct(key->group, EC_GROUP_get0_generator(key->group),
                                     POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
            if (len <= 0)
                goto err;

            buf = OPENSSL_zalloc(len);
            if (buf == NULL)
                goto err;

            if (!EC_POINT_point2oct(key->group, EC_GROUP_get0_generator(key->group),
                                    POINT_CONVERSION_COMPRESSED, buf, len, bn_ctx))
                goto err;

            if (!EC_POINT_from_string(key->group, ctx->h, buf, len))
                goto err;
        }

        if (key->priv_key) {
            ctx->pk_inv = BN_new();
            if (ctx->pk_inv == NULL) {
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!BN_mod_inverse(ctx->pk_inv, key->priv_key,
                                EC_GROUP_get0_order(key->group), bn_ctx))
                goto err;
        }

        OPENSSL_free(buf);
        BN_CTX_free(bn_ctx);
    }
#endif

    EC_KEY_up_ref(key);
    ctx->key = key;
    ctx->flag = flag;

    return ctx;
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
err:
    OPENSSL_free(buf);
    BN_CTX_free(bn_ctx);
    EC_ELGAMAL_CTX_free(ctx);
    return NULL;
#endif
}

EC_ELGAMAL_CTX *EC_ELGAMAL_CTX_dup(EC_ELGAMAL_CTX *ctx)
{
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    return EC_ELGAMAL_CTX_new(ctx->key, ctx->h, ctx->flag);
#else
    return EC_ELGAMAL_CTX_new(ctx->key, NULL, ctx->flag);
#endif
}

/** Frees a EC_ELGAMAL_CTX object
 *  \param  ctx  EC_ELGAMAL_CTX object to be freed
 */
void EC_ELGAMAL_CTX_free(EC_ELGAMAL_CTX *ctx)
{
    if (ctx == NULL)
        return;

    EC_KEY_free(ctx->key);
    EC_ELGAMAL_DECRYPT_TABLE_free(ctx->decrypt_table);
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    EC_POINT_free(ctx->h);
    BN_free(ctx->pk_inv);
#endif
    OPENSSL_free(ctx);
}

/** Creates a new EC_ELGAMAL_MR_CTX object
 *  \param  key      EC_KEY to use
 *  \param  flag     flag of ctx
 *  \return newly created EC_ELGAMAL_MR_CTX object or NULL in case of an error
 */
EC_ELGAMAL_MR_CTX *EC_ELGAMAL_MR_CTX_new(STACK_OF(EC_KEY) *keys, const EC_POINT *h,
                                         int32_t flag)
{
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    size_t len;
    unsigned char *buf = NULL;
    BN_CTX *bn_ctx = NULL;
#endif
    int i;
    EC_KEY *key;
    EC_GROUP *group;
    EC_ELGAMAL_MR_CTX *ctx = NULL;

    if (keys == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (sk_EC_KEY_num(keys) == 0) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    key = sk_EC_KEY_value(keys, 0);
    group = key->group;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!(ctx->group = EC_GROUP_dup(group)))
        goto err;

    ctx->sk_key = sk_EC_KEY_dup(keys);
    if (ctx->sk_key == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < sk_EC_KEY_num(keys); i++) {
        key = sk_EC_KEY_value(keys, i);
        if (!ec_point_is_compat(key->pub_key, group))
            goto err;

        if (!EC_KEY_up_ref(key))
            goto err;
    }

    ctx->flag = flag;

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (flag == EC_ELGAMAL_FLAG_TWISTED) {
        bn_ctx = BN_CTX_new();
        if (bn_ctx == NULL) {
            ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        if (h != NULL) {
            if (!(ctx->h = EC_POINT_dup(h, ctx->group)))
                return 0;
        } else {
            ctx->h = EC_POINT_new(group);
            if (ctx->h == NULL) {
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            len = EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                     POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);
            if (len <= 0)
                goto err;

            buf = OPENSSL_zalloc(len);
            if (buf == NULL)
                goto err;

            if (!EC_POINT_point2oct(group, EC_GROUP_get0_generator(group),
                                    POINT_CONVERSION_COMPRESSED, buf, len, bn_ctx))
                goto err;

            if (!EC_POINT_from_string(group, ctx->h, buf, len))
                goto err;
        }

        if (key->priv_key) {
            ctx->pk_inv = BN_new();
            if (ctx->pk_inv == NULL) {
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!BN_mod_inverse(ctx->pk_inv, key->priv_key,
                                EC_GROUP_get0_order(group), bn_ctx))
                goto err;
        }

        OPENSSL_free(buf);
        BN_CTX_free(bn_ctx);
    }
#endif

    return ctx;
err:
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    OPENSSL_free(buf);
    BN_CTX_free(bn_ctx);
#endif
    EC_ELGAMAL_MR_CTX_free(ctx);
    return NULL;
}

/** Frees a EC_ELGAMAL_MR_CTX object
 *  \param  ctx  EC_ELGAMAL_MR_CTX object to be freed
 */
void EC_ELGAMAL_MR_CTX_free(EC_ELGAMAL_MR_CTX *ctx)
{
    if (ctx == NULL)
        return;

    EC_GROUP_free(ctx->group);
    sk_EC_KEY_pop_free(ctx->sk_key, EC_KEY_free);
    EC_ELGAMAL_DECRYPT_TABLE_free(ctx->decrypt_table);
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    EC_POINT_free(ctx->h);
    BN_free(ctx->pk_inv);
#endif
    OPENSSL_free(ctx);
}

/** Encrypts an Integer with additadive homomorphic EC-ElGamal
 *  \param  ctx        EC_ELGAMAL_CTX object.
 *  \param  r          EC_ELGAMAL_CIPHERTEXT object that stores the result of
 *                     the encryption
 *  \param  plaintext  The plaintext integer to be encrypted
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_encrypt(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r, int32_t plaintext)
{
    int ret = 0;
    BIGNUM *bn_plain = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub_key == NULL || r == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_plain = BN_new();
    if (bn_plain == NULL)
        return ret;

    BN_set_word(bn_plain, (BN_ULONG)(plaintext > 0 ? plaintext : -(int64_t)plaintext));
    BN_set_negative(bn_plain, plaintext < 0 ? 1 : 0);

    ret = EC_ELGAMAL_bn_encrypt(ctx, r, bn_plain, NULL);

    BN_free(bn_plain);
    return ret;
}

int EC_ELGAMAL_bn_encrypt(EC_ELGAMAL_CTX *ctx, EC_ELGAMAL_CIPHERTEXT *r,
                          const BIGNUM *plaintext, const BIGNUM *rand)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *random = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub_key == NULL
        || r == NULL || plaintext == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    BN_CTX_start(bn_ctx);
    random = BN_CTX_get(bn_ctx);
    if (random == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

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

    if (rand == NULL)
        BN_rand_range(random, EC_GROUP_get0_order(ctx->key->group));
    else
        random = (BIGNUM *)rand;

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (ctx->flag == EC_ELGAMAL_FLAG_TWISTED) {
        if (!EC_POINT_mul(ctx->key->group, r->C1, NULL, ctx->key->pub_key,
                          random, bn_ctx))
            goto err;

        if (!EC_POINT_mul(ctx->key->group, r->C2, random, ctx->h,
                          plaintext, bn_ctx))
            goto err;
    } else {
#endif
        if (!EC_POINT_mul(ctx->key->group, r->C1, random, NULL, NULL, bn_ctx))
            goto err;

        if (!EC_POINT_mul(ctx->key->group, r->C2, plaintext, ctx->key->pub_key,
                          random, bn_ctx))
            goto err;
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    }
#endif

    ret = 1;

err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    if (!ret) {
        EC_POINT_free(r->C1);
        EC_POINT_free(r->C2);
        r->C1 = NULL;
        r->C2 = NULL;
    }

    return ret;
}

/** Encryption with one plaintext for multiple recipients.
 *  \param  ctx        EC_ELGAMAL_CTX object.
 *  \param  r          EC_ELGAMAL_CIPHERTEXT_MR object that stores the result of
 *                     the encryption
 *  \param  plaintext  The plaintext BIGNUM object to be encrypted
 *  \return 1 on success and 0 otherwise
 */
int EC_ELGAMAL_MR_encrypt(EC_ELGAMAL_MR_CTX *ctx, EC_ELGAMAL_MR_CIPHERTEXT *r,
                          const BIGNUM *plaintext, BIGNUM *rand)
{
    int ret = 0, i;
    EC_KEY *key;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *random = NULL;
    EC_POINT *C1 = NULL;

    if (ctx == NULL || ctx->sk_key == NULL || r == NULL || plaintext == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    BN_CTX_start(bn_ctx);
    random = BN_CTX_get(bn_ctx);
    if (random == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (r->sk_C1 && sk_EC_POINT_num(r->sk_C1) != 0) {
        sk_EC_POINT_pop_free(r->sk_C1, EC_POINT_free);
        r->sk_C1 = NULL;
    }

    if (r->sk_C1 == NULL) {
        r->sk_C1 = sk_EC_POINT_new_null();
        if (r->sk_C1 == NULL)
            goto err;
    }

    if (r->C2 == NULL) {
        r->C2 = EC_POINT_new(ctx->group);
        if (r->C2 == NULL)
            goto err;
    }

    if (rand == NULL) {
        BN_rand_range(random, EC_GROUP_get0_order(ctx->group));
        rand = random;
    }

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (ctx->flag == EC_ELGAMAL_FLAG_TWISTED) {
        for (i = 0; i < sk_EC_KEY_num(ctx->sk_key); i++) {
            key = sk_EC_KEY_value(ctx->sk_key, i);

            C1 = EC_POINT_new(ctx->group);
            if (C1 == NULL)
                goto err;

            if (!EC_POINT_mul(ctx->group, C1, NULL, key->pub_key, rand, bn_ctx))
                goto err;

            if (sk_EC_POINT_push(r->sk_C1, C1) <= 0)
                goto err;

            C1 = NULL;
        }

        if (!EC_POINT_mul(ctx->group, r->C2, rand, ctx->h, plaintext, bn_ctx))
            goto err;
    } else {
#endif
        for (i = 0; i < sk_EC_KEY_num(ctx->sk_key); i++) {
            key = sk_EC_KEY_value(ctx->sk_key, i);

            C1 = EC_POINT_new(ctx->group);
            if (C1 == NULL)
                goto err;

            if (!EC_POINT_mul(ctx->group, C1, plaintext, key->pub_key, rand, bn_ctx))
                goto err;

            if (sk_EC_POINT_push(r->sk_C1, C1) <= 0)
                goto err;

            C1 = NULL;
        }

        if (!EC_POINT_mul(ctx->group, r->C2, rand, NULL, NULL, bn_ctx))
            goto err;
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    }
#endif

    ret = 1;

err:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);

    if (!ret) {
        EC_POINT_free(C1);
        EC_POINT_free(r->C2);
        sk_EC_POINT_pop_free(r->sk_C1, EC_POINT_free);
        r->sk_C1 = NULL;
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
int EC_ELGAMAL_decrypt(EC_ELGAMAL_CTX *ctx, int32_t *r,
                       const EC_ELGAMAL_CIPHERTEXT *ciphertext)
{
    int ret = 0;
    int32_t plaintext = 0;
    EC_POINT *M = NULL;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->priv_key == NULL || r == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    M = EC_POINT_new(ctx->key->group);
    if (M == NULL)
        goto err;

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    BN_CTX_start(bn_ctx);
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (ctx->flag == EC_ELGAMAL_FLAG_TWISTED) {
        if (!EC_POINT_mul(ctx->key->group, M, NULL, ciphertext->C1,
                          ctx->pk_inv, bn_ctx))
            goto err;
    } else {
#endif
        if (!EC_POINT_mul(ctx->key->group, M, NULL, ciphertext->C1,
                          ctx->key->priv_key, bn_ctx))
            goto err;
#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    }
#endif

    if (!EC_POINT_invert(ctx->key->group, M, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, M, ciphertext->C2, M, bn_ctx))
        goto err;

    if (ctx->decrypt_table != NULL) {
        if (!EC_ELGAMAL_dlog_bsgs(ctx, &plaintext, M))
            goto err;
    } else {
        if (!EC_ELGAMAL_dlog_brute(ctx, &plaintext, M))
            goto err;
    }

    *r = plaintext;

    ret = 1;

err:
    BN_CTX_end(bn_ctx);
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
                   const EC_ELGAMAL_CIPHERTEXT *c1,
                   const EC_ELGAMAL_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c1 == NULL || c2 == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

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
                   const EC_ELGAMAL_CIPHERTEXT *c1,
                   const EC_ELGAMAL_CIPHERTEXT *c2)
{
    int ret = 0;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *C1_inv = NULL, *C2_inv = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c1 == NULL || c2 == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if ((C1_inv = EC_POINT_dup(c2->C1, ctx->key->group)) == NULL)
        goto err;

    if ((C2_inv = EC_POINT_dup(c2->C2, ctx->key->group)) == NULL)
        goto err;

    if (!EC_POINT_invert(ctx->key->group, C1_inv, bn_ctx))
        goto err;

    if (!EC_POINT_invert(ctx->key->group, C2_inv, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C1, c1->C1, C1_inv, bn_ctx))
        goto err;

    if (!EC_POINT_add(ctx->key->group, r->C2, c1->C2, C2_inv, bn_ctx))
        goto err;

    ret = 1;

err:
    EC_POINT_free(C1_inv);
    EC_POINT_free(C2_inv);
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
                   const EC_ELGAMAL_CIPHERTEXT *c, int32_t m)
{
    int ret = 0;
    BIGNUM *bn_m;
    BN_CTX *bn_ctx = NULL;

    if (ctx == NULL || ctx->key == NULL || r == NULL || c == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    BN_CTX_start(bn_ctx);

    if (m == 0) {
        ret = EC_ELGAMAL_encrypt(ctx, r, 0);
        goto end;
    }

    bn_m = BN_CTX_get(bn_ctx);
    if (bn_m == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        goto end;
    }
    BN_set_word(bn_m, (BN_ULONG)(m > 0 ? m : -(int64_t)m));
    BN_set_negative(bn_m, m < 0 ? 1 : 0);

    if (!EC_POINT_mul(ctx->key->group, r->C1, NULL, c->C1, bn_m, bn_ctx))
        goto end;

    if (!EC_POINT_mul(ctx->key->group, r->C2, NULL, c->C2, bn_m, bn_ctx))
        goto end;

    ret = 1;

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}
