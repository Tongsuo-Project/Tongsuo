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
#include <openssl/sha.h>
#include <string.h>

#define HASH_TO_EC_POINT_TRY_COUNT  1000

/*
 * Functions for convert string to ec_point on the elliptic curve.
 * This implementation belongs to the ad-hoc method, but it is also the
 * recommended implementation in the mcl library, the google open source project
 * and the cryptography conference paper.
 *  \param  group   underlying EC_GROUP object
 *  \param  r       EC_POINT object for the result
 *  \param  str     string pointer
 *  \param  len     length of the string
 *  \return 1 on success and 0 if an error occurred
 */
int EC_POINT_from_string(const EC_GROUP *group, EC_POINT *r,
                         const unsigned char *str, size_t len)
{
    int ret = 0, i = 0;
    unsigned char hash_res[SHA256_DIGEST_LENGTH];
    unsigned char *p = (unsigned char *)str;
    BN_CTX *bn_ctx = NULL;
    BIGNUM *x;

    memset(hash_res, 0, sizeof(hash_res));

    if ((bn_ctx = BN_CTX_new_ex(group->libctx)) == NULL)
        goto end;

    BN_CTX_start(bn_ctx);
    if ((x = BN_CTX_get(bn_ctx)) == NULL)
        goto end;

    do {
        if (!SHA256(p, len, hash_res))
            goto end;

        BN_bin2bn(hash_res, SHA256_DIGEST_LENGTH, x);

        p  = &hash_res[0];
        len = sizeof(hash_res);

        if(EC_POINT_set_compressed_coordinates(group, r, x, 0, bn_ctx) == 1) {
            ret = 1;
            break;
        }

        ERR_clear_error();
    } while (i++ < HASH_TO_EC_POINT_TRY_COUNT);

end:
    BN_CTX_end(bn_ctx);
    BN_CTX_free(bn_ctx);
    return ret;
}

/** Creates a new EC_ELGAMAL object
 *  \param  key      EC_KEY to use
 *  \param  flag     flag of ctx
 *  \return newly created EC_ELGAMAL_CTX object or NULL in case of an error
 */
EC_ELGAMAL_CTX *EC_ELGAMAL_CTX_new(EC_KEY *key, int32_t flag)
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

        if (key->priv_key) {
            ctx->sk_inv = BN_new();
            if (ctx->sk_inv == NULL) {
                ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
                goto err;
            }

            if (!BN_mod_inverse(ctx->sk_inv, key->priv_key,
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
    return ctx;
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
    BN_free(ctx->sk_inv);
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
    BN_CTX *bn_ctx = NULL;
    BIGNUM *bn_plain = NULL, *rand = NULL;

    if (ctx == NULL || ctx->key == NULL || ctx->key->pub_key == NULL || r == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
    }

    bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) {
        ERR_raise(ERR_LIB_EC, ERR_R_MALLOC_FAILURE);
        return ret;
    }

    BN_CTX_start(bn_ctx);
    bn_plain = BN_CTX_get(bn_ctx);
    rand = BN_CTX_get(bn_ctx);
    if (rand == NULL) {
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

    BN_rand_range(rand, EC_GROUP_get0_order(ctx->key->group));

    BN_set_word(bn_plain, (BN_ULONG)(plaintext > 0 ? plaintext : -(int64_t)plaintext));
    BN_set_negative(bn_plain, plaintext < 0 ? 1 : 0);

#ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
    if (ctx->flag == EC_ELGAMAL_FLAG_TWISTED) {
        if (!EC_POINT_mul(ctx->key->group, r->C1, NULL, ctx->key->pub_key,
                          rand, bn_ctx))
            goto err;

        if (!EC_POINT_mul(ctx->key->group, r->C2, rand, ctx->h,
                          bn_plain, bn_ctx))
            goto err;
    } else {
#endif
        if (!EC_POINT_mul(ctx->key->group, r->C1, rand, NULL, NULL, bn_ctx))
            goto err;

        if (!EC_POINT_mul(ctx->key->group, r->C2, bn_plain, ctx->key->pub_key,
                          rand, bn_ctx))
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
                          ctx->sk_inv, bn_ctx))
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
