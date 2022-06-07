/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/* zuc_128_eea3 cipher implementation */

#include "cipher_zuc_eea3.h"

static int zuc_128_eea3_initkey(PROV_CIPHER_CTX *vctx, const uint8_t *key,
                                size_t keylen)
{
    PROV_ZUC_EEA3_CTX *ctx = (PROV_ZUC_EEA3_CTX *)vctx;
    ZUC_KEY *zk = &ctx->ks.ks;

    zk->k = key;

    return 1;
}

static int zuc_128_eea3_initiv(PROV_CIPHER_CTX *vctx)
{
    PROV_ZUC_EEA3_CTX *ctx = (PROV_ZUC_EEA3_CTX *)vctx;
    ZUC_KEY *zk = &ctx->ks.ks;
    uint32_t count;
    uint32_t bearer;
    uint32_t direction;
    unsigned char *iv = &vctx->oiv[0];

    /*
     * This is a lazy approach: we 'borrow' the 'iv' parameter
     * to use it as a place of transfer the EEA3 iv params -
     * count, bearer and direction.
     *
     * count is 32 bits, bearer is 5 bits and direction is 1
     * bit so we read the first 38 bits of iv. And the whole
     * iv is set to 5 bytes (40 bits).
     */

    /* IV is a 'must' */
    if (!vctx->iv_set)
        return 0;

    count = ((long)iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
    bearer = (iv[4] & 0xF8) >> 3;
    direction = (iv[4] & 0x4) >> 2;

    zk->iv[0] = (count >> 24) & 0xFF;
    zk->iv[1] = (count >> 16) & 0xFF;
    zk->iv[2] = (count >> 8) & 0xFF;
    zk->iv[3] = count & 0xFF;

    zk->iv[4] = ((bearer << 3) | ((direction & 1) << 2)) & 0xFC;
    zk->iv[5] = zk->iv[6] = zk->iv[7] = 0;

    zk->iv[8] = zk->iv[0];
    zk->iv[9] = zk->iv[1];
    zk->iv[10] = zk->iv[2];
    zk->iv[11] = zk->iv[3];
    zk->iv[12] = zk->iv[4];
    zk->iv[13] = zk->iv[5];
    zk->iv[14] = zk->iv[6];
    zk->iv[15] = zk->iv[7];

    ZUC_init(zk);

    return 1;
}

static int zuc_128_eea3_cipher(PROV_CIPHER_CTX *vctx, unsigned char *out,
                               const unsigned char *in, size_t inl)
{
    PROV_ZUC_EEA3_CTX *ctx = (PROV_ZUC_EEA3_CTX *)vctx;
    ZUC_KEY *zk = &ctx->ks.ks;
    unsigned int i, remain, num = vctx->num;

    remain = zk->keystream_len - num;
    if (remain < inl) {
        /* no adequate key, generate more */
        zk->L = ((inl - remain) * 8 + 31) / 32;

        if (!ZUC_generate_keystream(zk))
            return 0;
    }

    /*
     * EEA3 is based on 'bits', but we can only handle 'bytes'.
     *
     * So we choose to output a final whole byte, even if there are some
     * bits at the end of the input. Those trailing bits in the last byte
     * should be discarded by caller.
     */
    for (i = 0; i < inl; i++, num++)
        out[i] = in[i] ^ zk->keystream[num];

    /* num always points to next key byte to use */
    vctx->num = num;

    return 1;
}

static void zuc_128_eea3_cleanup(PROV_ZUC_EEA3_CTX *ctx)
{
    ZUC_destroy_keystream(&ctx->ks.ks);
}

static const PROV_CIPHER_HW_ZUC_EEA3 zuc_128_eea3_hw = {
    { zuc_128_eea3_initkey, zuc_128_eea3_cipher },
    zuc_128_eea3_initiv,
    zuc_128_eea3_cleanup
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_zuc_128_eea3(size_t keybits)
{
    return (PROV_CIPHER_HW *)&zuc_128_eea3_hw;
}

