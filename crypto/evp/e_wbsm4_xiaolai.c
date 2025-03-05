/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_WBSM4_XIAOLAI
# include <openssl/rand.h>
# include "crypto/wbsm4.h"
# include "crypto/evp.h"
# include "crypto/modes.h"
# include "evp_local.h"

typedef struct {
    union {
        OSSL_UNION_ALIGN;
        wbsm4_xiaolai_key ks;
    } ks;
    block128_f block;
} EVP_WBSM4_XIAOLAI_KEY;

# define BLOCK_CIPHER_generic(nid,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER wbsm4_xiaolai_##mode = {                         \
        nid##_##nmode,blocksize,sizeof(wbsm4_xiaolai_key),ivlen,         \
        flags|EVP_CIPH_##MODE##_MODE,                                    \
        EVP_ORIG_GLOBAL,                                                 \
        wbsm4_xiaolai_init_key,                                          \
        wbsm4_xiaolai_##mode##_cipher,                                   \
        NULL,                                                            \
        sizeof(EVP_WBSM4_XIAOLAI_KEY),                                   \
        NULL,NULL,NULL,NULL                                              \
};                                                                       \
const EVP_CIPHER *EVP_wbsm4_xiaolai_##mode(void)                         \
{ return &wbsm4_xiaolai_##mode; }

#define DEFINE_BLOCK_CIPHERS(nid,flags)                        \
        BLOCK_CIPHER_generic(nid,16,16,cbc,cbc,CBC,            \
                            flags|EVP_CIPH_FLAG_DEFAULT_ASN1)  \
        BLOCK_CIPHER_generic(nid,16,0,ecb,ecb,ECB,             \
                             flags|EVP_CIPH_FLAG_DEFAULT_ASN1) \
        BLOCK_CIPHER_generic(nid,1,16,ofb128,ofb,OFB,          \
                             flags|EVP_CIPH_FLAG_DEFAULT_ASN1) \
        BLOCK_CIPHER_generic(nid,1,16,cfb128,cfb,CFB,          \
                             flags|EVP_CIPH_FLAG_DEFAULT_ASN1) \
        BLOCK_CIPHER_generic(nid,1,16,ctr,ctr,CTR,flags)

static int wbsm4_xiaolai_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    EVP_WBSM4_XIAOLAI_KEY *dat = EVP_C_DATA(EVP_WBSM4_XIAOLAI_KEY,ctx);

    if (!enc) {
        ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
        return 0;
    }

    dat->block = (block128_f)wbsm4_xiaolai_encrypt;
    wbsm4_xiaolai_set_key(key, &dat->ks.ks);
    
    return 1;
}

static int wbsm4_xiaolai_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_WBSM4_XIAOLAI_KEY *dat = EVP_C_DATA(EVP_WBSM4_XIAOLAI_KEY,ctx);

    CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv,
                            dat->block);

    return 1;
}

static int wbsm4_xiaolai_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_WBSM4_XIAOLAI_KEY *dat = EVP_C_DATA(EVP_WBSM4_XIAOLAI_KEY,ctx);
    int num = EVP_CIPHER_CTX_get_num(ctx);

    CRYPTO_cfb128_encrypt(in, out, len, &dat->ks,
                          ctx->iv, &num,
                          EVP_CIPHER_CTX_is_encrypting(ctx), dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int wbsm4_xiaolai_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_get_block_size(ctx);
    size_t i;
    EVP_WBSM4_XIAOLAI_KEY *dat = EVP_C_DATA(EVP_WBSM4_XIAOLAI_KEY,ctx);

    if (len < bl)
        return 1;

    for (i = 0, len -= bl; i <= len; i += bl)
        (*dat->block) (in + i, out + i, &dat->ks);

    return 1;
}

static int wbsm4_xiaolai_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_WBSM4_XIAOLAI_KEY *dat = EVP_C_DATA(EVP_WBSM4_XIAOLAI_KEY,ctx);
    int num = EVP_CIPHER_CTX_get_num(ctx);

    CRYPTO_ofb128_encrypt(in, out, len, &dat->ks,
                          ctx->iv, &num, dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int wbsm4_xiaolai_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int n = EVP_CIPHER_CTX_get_num(ctx);
    unsigned int num;
    EVP_WBSM4_XIAOLAI_KEY *dat = EVP_C_DATA(EVP_WBSM4_XIAOLAI_KEY,ctx);

    if (n < 0)
        return 0;
    num = (unsigned int)n;

    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks,
                        ctx->iv,
                        EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                        dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

DEFINE_BLOCK_CIPHERS(NID_wbsm4_xiaolai, 0)

# define BLOCK_CIPHER_custom(nid,blocksize,ivlen,mode,MODE,flags) \
static const EVP_CIPHER wbsm4_xiaolai_##mode = {                  \
        nid##_##mode,blocksize, sizeof(wbsm4_xiaolai_key), ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,                             \
        EVP_ORIG_GLOBAL,                                          \
        wbsm4_xiaolai_##mode##_init,                              \
        wbsm4_xiaolai_##mode##_cipher,                            \
        wbsm4_xiaolai_##mode##_cleanup,                           \
        sizeof(EVP_SM4_##MODE##_CTX),                             \
        NULL,NULL,wbsm4_xiaolai_##mode##_ctrl,NULL                \
};                                                                \
const EVP_CIPHER *EVP_wbsm4_xiaolai_##mode(void)                  \
{ return &wbsm4_xiaolai_##mode; }

typedef struct {
    wbsm4_xiaolai_key ks;       /* WBSM4 key schedule to use */
    int key_set;                /* Set if key initialized */
    int iv_set;                 /* Set if an iv is set */
    GCM128_CONTEXT gcm;
    unsigned char *iv;          /* Temporary IV store */
    int ivlen;                  /* IV length */
    int taglen;
    int iv_gen;                 /* It is OK to generate IVs */
    int tls_aad_len;            /* TLS AAD length */
    ctr128_f ctr;
} EVP_SM4_GCM_CTX;

typedef struct {
    wbsm4_xiaolai_key ks;       /* WBSM4 key schedule to use */
    int key_set;                /* Set if key initialized */
    int iv_set;                 /* Set if an iv is set */
    int tag_set;                /* Set if tag is valid */
    int len_set;                /* Set if message length set */
    int L, M;                   /* L and M parameters from RFC3610 */
    int tls_aad_len;            /* TLS AAD length */
    CCM128_CONTEXT ccm;
    ccm128_f str;
} EVP_SM4_CCM_CTX;

static int wbsm4_xiaolai_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg,
                                  void *ptr);
static int wbsm4_xiaolai_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int wbsm4_xiaolai_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len);
static int wbsm4_xiaolai_gcm_cleanup(EVP_CIPHER_CTX *c);

static int wbsm4_xiaolai_ccm_ctrl(EVP_CIPHER_CTX *c, int type, int arg,
                                  void *ptr);
static int wbsm4_xiaolai_ccm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int wbsm4_xiaolai_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len);
static int wbsm4_xiaolai_ccm_cleanup(EVP_CIPHER_CTX *c);

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(unsigned char *counter)
{
    int n = 8;
    unsigned char c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c)
            return;
    } while (n);
}

static int wbsm4_xiaolai_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg,
                                  void *ptr)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,c);

    switch (type) {
    case EVP_CTRL_INIT:
        gctx->key_set = 0;
        gctx->iv_set = 0;
        gctx->ivlen = EVP_CIPHER_iv_length(c->cipher);
        gctx->iv = c->iv;
        gctx->taglen = -1;
        gctx->iv_gen = 0;
        gctx->tls_aad_len = -1;
        return 1;

    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = gctx->ivlen;
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        if (arg <= 0)
            return 0;
        /* Allocate memory for IV if needed */
        if ((arg > EVP_MAX_IV_LENGTH) && (arg > gctx->ivlen)) {
            if (gctx->iv != c->iv)
                OPENSSL_free(gctx->iv);
            if ((gctx->iv = OPENSSL_malloc(arg)) == NULL)
                return 0;
        }
        gctx->ivlen = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if (arg <= 0 || arg > 16 || c->encrypt)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->taglen = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (arg <= 0 || arg > 16 || !c->encrypt || gctx->taglen < 0)
            return 0;
        memcpy(ptr, c->buf, arg);
        return 1;

    case EVP_CTRL_GCM_SET_IV_FIXED:
        /* Special case: -1 length restores whole IV */
        if (arg == -1) {
            memcpy(gctx->iv, ptr, gctx->ivlen);
            gctx->iv_gen = 1;
            return 1;
        }
        /*
         * Fixed field must be at least 4 bytes and invocation field at least
         * 8.
         */
        if ((arg < 4) || (gctx->ivlen - arg) < 8)
            return 0;
        if (arg)
            memcpy(gctx->iv, ptr, arg);
        if (c->encrypt && RAND_bytes(gctx->iv + arg, gctx->ivlen - arg) <= 0)
            return 0;
        gctx->iv_gen = 1;
        return 1;

    case EVP_CTRL_GCM_IV_GEN:
        if (gctx->iv_gen == 0 || gctx->key_set == 0)
            return 0;
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        if (arg <= 0 || arg > gctx->ivlen)
            arg = gctx->ivlen;
        memcpy(ptr, gctx->iv + gctx->ivlen - arg, arg);
        /*
         * Invocation field will be at least 8 bytes in size and so no need
         * to check wrap around or increment more than last 8 bytes.
         */
        ctr64_inc(gctx->iv + gctx->ivlen - 8);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_GCM_SET_IV_INV:
        if (gctx->iv_gen == 0 || gctx->key_set == 0 || c->encrypt)
            return 0;
        memcpy(gctx->iv + gctx->ivlen - arg, ptr, arg);
        CRYPTO_gcm128_setiv(&gctx->gcm, gctx->iv, gctx->ivlen);
        gctx->iv_set = 1;
        return 1;

    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(c->buf, ptr, arg);
        gctx->tls_aad_len = arg;
        {
            unsigned int len = c->buf[arg - 2] << 8 | c->buf[arg - 1];
            /* Correct length for explicit IV */
            if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!c->encrypt) {
                if (len < EVP_GCM_TLS_TAG_LEN)
                    return 0;
                len -= EVP_GCM_TLS_TAG_LEN;
            }
            c->buf[arg - 2] = len >> 8;
            c->buf[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return EVP_GCM_TLS_TAG_LEN;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_GCM_CTX *gctx_out = EVP_C_DATA(EVP_SM4_GCM_CTX,out);

            if (gctx->gcm.key) {
                if (gctx->gcm.key != &gctx->ks)
                    return 0;
                gctx_out->gcm.key = &gctx_out->ks;
            }
            if (gctx->iv == c->iv)
                gctx_out->iv = out->iv;
            else {
                if ((gctx_out->iv = OPENSSL_malloc(gctx->ivlen)) == NULL) {
                    return 0;
                }
                memcpy(gctx_out->iv, gctx->iv, gctx->ivlen);
            }
            return 1;
        }
    case EVP_CTRL_AEAD_SET_MAC_KEY:
        /* no-op */
        return 1;
    default:
        return -1;
    }
    return 1;
}

static int wbsm4_xiaolai_gcm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);

    if (iv == NULL && key == NULL)
        return 1;
    if (key) {
        do {
            wbsm4_xiaolai_set_key(key, &gctx->ks);
            CRYPTO_gcm128_init(&gctx->gcm, &gctx->ks,
                               (block128_f)wbsm4_xiaolai_encrypt);
            gctx->ctr = NULL;
        } while (0);

        /*
         * If we have an iv can set it directly, otherwise use saved IV.
         */
        if (iv == NULL && gctx->iv_set)
            iv = gctx->iv;
        if (iv) {
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
            gctx->iv_set = 1;
        }
        gctx->key_set = 1;
    } else {
        /* If key set use IV, otherwise copy */
        if (gctx->key_set)
            CRYPTO_gcm128_setiv(&gctx->gcm, iv, gctx->ivlen);
        else
            memcpy(gctx->iv, iv, gctx->ivlen);
        gctx->iv_set = 1;
        gctx->iv_gen = 0;
    }
    return 1;
}

/*
 * Handle TLS GCM packet format. This consists of the last portion of the IV
 * followed by the payload and finally the tag. On encrypt generate IV,
 * encrypt payload and write the tag. On verify retrieve IV, decrypt payload
 * and verify tag.
 */

static int wbsm4_xiaolai_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                              const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);
    int rv = -1;
    /* Encrypt/decrypt must be performed in place */
    if (out != in
        || len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
        return -1;
    /*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, ctx->encrypt ? EVP_CTRL_GCM_IV_GEN
                                              : EVP_CTRL_GCM_SET_IV_INV,
                            EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0)
        goto err;
    /* Use saved AAD */
    if (CRYPTO_gcm128_aad(&gctx->gcm, ctx->buf, gctx->tls_aad_len))
        goto err;
    /* Fix buffer and length to point to payload */
    in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
    len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    if (ctx->encrypt) {
        /* Encrypt payload */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_encrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        out += len;
        /* Finally write tag */
        CRYPTO_gcm128_tag(&gctx->gcm, out, EVP_GCM_TLS_TAG_LEN);
        rv = len + EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
    } else {
        /* Decrypt */
        if (gctx->ctr) {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm,
                                            in + bulk,
                                            out + bulk,
                                            len - bulk, gctx->ctr))
                goto err;
        } else {
            size_t bulk = 0;
            if (CRYPTO_gcm128_decrypt(&gctx->gcm,
                                      in + bulk, out + bulk, len - bulk))
                goto err;
        }
        /* Retrieve tag */
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, EVP_GCM_TLS_TAG_LEN);
        /* If tag mismatch wipe buffer */
        if (CRYPTO_memcmp(ctx->buf, in + len, EVP_GCM_TLS_TAG_LEN)) {
            OPENSSL_cleanse(out, len);
            goto err;
        }
        rv = len;
    }

 err:
    gctx->iv_set = 0;
    gctx->tls_aad_len = -1;
    return rv;
}

static int wbsm4_xiaolai_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX,ctx);

    /* If not set up, return error */
    if (!gctx->key_set)
        return -1;

    if (gctx->tls_aad_len >= 0)
        return wbsm4_xiaolai_gcm_tls_cipher(ctx, out, in, len);

    if (!gctx->iv_set)
        return -1;

    if (in != NULL) {
        if (out == NULL) {
            if (CRYPTO_gcm128_aad(&gctx->gcm, in, len))
                return -1;
        } else if (ctx->encrypt) {
            if (gctx->ctr != NULL) {
                if (CRYPTO_gcm128_encrypt_ctr32(&gctx->gcm, in, out, len,
                                                gctx->ctr))
                    return -1;
            } else {
                if (CRYPTO_gcm128_encrypt(&gctx->gcm, in, out, len))
                    return -1;
            }
        } else {
            if (gctx->ctr != NULL) {
                if (CRYPTO_gcm128_decrypt_ctr32(&gctx->gcm, in, out, len,
                                                gctx->ctr))
                    return -1;
            } else {
                if (CRYPTO_gcm128_decrypt(&gctx->gcm, in, out, len))
                    return -1;
            }
        }
        return len;
    } else {
        if (!ctx->encrypt) {
            if (gctx->taglen < 0)
                return -1;
            if (CRYPTO_gcm128_finish(&gctx->gcm, ctx->buf, gctx->taglen) != 0)
                return -1;
            gctx->iv_set = 0;
            return 0;
        }
        CRYPTO_gcm128_tag(&gctx->gcm, ctx->buf, 16);
        gctx->taglen = 16;
        /* Don't reuse the IV */
        gctx->iv_set = 0;
        return 0;
    }
}

static int wbsm4_xiaolai_gcm_cleanup(EVP_CIPHER_CTX *c)
{
    EVP_SM4_GCM_CTX *gctx = EVP_C_DATA(EVP_SM4_GCM_CTX, c);
    const unsigned char *iv;

    if (gctx == NULL)
        return 0;

    iv = EVP_CIPHER_CTX_iv(c);
    if (iv != gctx->iv)
        OPENSSL_free(gctx->iv);

    OPENSSL_cleanse(gctx, sizeof(*gctx));
    return 1;
}

static int wbsm4_xiaolai_ccm_ctrl(EVP_CIPHER_CTX *c, int type, int arg,
                                  void *ptr)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX,c);

    switch (type) {
    case EVP_CTRL_INIT:
        cctx->key_set = 0;
        cctx->iv_set = 0;
        cctx->L = 8;
        cctx->M = 12;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        cctx->tls_aad_len = -1;
        return 1;
    case EVP_CTRL_GET_IVLEN:
        *(int *)ptr = 15 - cctx->L;
        return 1;
    case EVP_CTRL_AEAD_TLS1_AAD:
        /* Save the AAD for later use */
        if (arg != EVP_AEAD_TLS1_AAD_LEN)
            return 0;
        memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        cctx->tls_aad_len = arg;
        {
            uint16_t len =
                EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8
                | EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];

            /* Correct length for explicit IV */
            if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
                return 0;
            len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;
            /* If decrypting correct for tag too */
            if (!EVP_CIPHER_CTX_encrypting(c)) {
                if (len < cctx->M)
                    return 0;
                len -= cctx->M;
            }
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
            EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
        }
        /* Extra padding: tag appended to record */
        return cctx->M;

    case EVP_CTRL_CCM_SET_IV_FIXED:
        /* Sanity check length */
        if (arg != EVP_CCM_TLS_FIXED_IV_LEN)
            return 0;
        /* Just copy to first part of IV */
        memcpy(EVP_CIPHER_CTX_iv_noconst(c), ptr, arg);
        return 1;

    case EVP_CTRL_AEAD_SET_IVLEN:
        arg = 15 - arg;
        /* fall thru */
    case EVP_CTRL_CCM_SET_L:
        if (arg < 2 || arg > 8)
            return 0;
        cctx->L = arg;
        return 1;

    case EVP_CTRL_AEAD_SET_TAG:
        if ((arg & 1) || arg < 4 || arg > 16)
            return 0;
        if (EVP_CIPHER_CTX_encrypting(c) && ptr)
            return 0;
        if (ptr) {
            cctx->tag_set = 1;
            memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
        }
        cctx->M = arg;
        return 1;

    case EVP_CTRL_AEAD_GET_TAG:
        if (!EVP_CIPHER_CTX_encrypting(c) || !cctx->tag_set)
            return 0;
        if (!CRYPTO_ccm128_tag(&cctx->ccm, ptr, (size_t)arg))
            return 0;
        cctx->tag_set = 0;
        cctx->iv_set = 0;
        cctx->len_set = 0;
        return 1;

    case EVP_CTRL_COPY:
        {
            EVP_CIPHER_CTX *out = ptr;
            EVP_SM4_CCM_CTX *cctx_out = EVP_C_DATA(EVP_SM4_CCM_CTX,out);

            if (cctx->ccm.key) {
                if (cctx->ccm.key != &cctx->ks)
                    return 0;
                cctx_out->ccm.key = &cctx_out->ks;
            }
            return 1;
        }

    default:
        return -1;

    }
}

static int wbsm4_xiaolai_ccm_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX,ctx);

    if (iv == NULL && key == NULL)
        return 1;
    if (key != NULL)
        do {
            wbsm4_xiaolai_set_key(key, &cctx->ks);
            CRYPTO_ccm128_init(&cctx->ccm, cctx->M, cctx->L,
                               &cctx->ks, (block128_f)wbsm4_xiaolai_encrypt);
            cctx->str = NULL;
            cctx->key_set = 1;
        } while (0);
    if (iv != NULL) {
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 15 - cctx->L);
        cctx->iv_set = 1;
    }
    return 1;
}

static int wbsm4_xiaolai_ccm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_CCM_CTX *cctx = EVP_C_DATA(EVP_SM4_CCM_CTX,ctx);
    CCM128_CONTEXT *ccm = &cctx->ccm;

    /* If not set up, return error */
    if (!cctx->key_set)
        return -1;

    /* EVP_*Final() doesn't return any data */
    if (in == NULL && out != NULL)
        return 0;

    if (!cctx->iv_set)
        return -1;

    if (out == NULL) {
        if (in == NULL) {
            if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx),
                                    15 - cctx->L, len))
                return -1;
            cctx->len_set = 1;
            return len;
        }
        /* If have AAD need message length */
        if (!cctx->len_set && len)
            return -1;
        CRYPTO_ccm128_aad(ccm, in, len);
        return len;
    }

    /* The tag must be set before actually decrypting data */
    if (!EVP_CIPHER_CTX_encrypting(ctx) && !cctx->tag_set)
        return -1;

    /* If not set length yet do it */
    if (!cctx->len_set) {
        if (CRYPTO_ccm128_setiv(ccm, EVP_CIPHER_CTX_iv_noconst(ctx),
                                15 - cctx->L, len))
            return -1;
        cctx->len_set = 1;
    }
    if (EVP_CIPHER_CTX_encrypting(ctx)) {
        if (cctx->str != NULL ?
            CRYPTO_ccm128_encrypt_ccm64(ccm, in, out, len,
                                        cctx->str) :
            CRYPTO_ccm128_encrypt(ccm, in, out, len))
            return -1;
        cctx->tag_set = 1;
        return len;
    } else {
        int rv = -1;

        if (cctx->str != NULL ? !CRYPTO_ccm128_decrypt_ccm64(ccm, in, out, len,
                                                     cctx->str) :
            !CRYPTO_ccm128_decrypt(ccm, in, out, len)) {
            unsigned char tag[16];
            if (CRYPTO_ccm128_tag(ccm, tag, cctx->M)) {
                if (!CRYPTO_memcmp(tag, EVP_CIPHER_CTX_buf_noconst(ctx),
                                   cctx->M))
                    rv = len;
            }
        }
        if (rv == -1)
            OPENSSL_cleanse(out, len);
        cctx->iv_set = 0;
        cctx->tag_set = 0;
        cctx->len_set = 0;
        return rv;
    }

}

static int wbsm4_xiaolai_ccm_cleanup(EVP_CIPHER_CTX *c)
{
    return 1;
}

#define CUSTOM_FLAGS    (EVP_CIPH_FLAG_DEFAULT_ASN1                         \
                         | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT   \
                         | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH)

BLOCK_CIPHER_custom(NID_wbsm4_xiaolai, 1, 12, gcm, GCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
BLOCK_CIPHER_custom(NID_wbsm4_xiaolai, 1, 12, ccm, CCM,
                    EVP_CIPH_FLAG_AEAD_CIPHER | CUSTOM_FLAGS)
#endif
