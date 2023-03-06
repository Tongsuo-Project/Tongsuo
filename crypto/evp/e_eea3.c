/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include "internal/deprecated.h"

#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_ZUC

# include <openssl/evp.h>
# include <openssl/objects.h>

# include "crypto/zuc.h"
# include "crypto/evp.h"

typedef struct {
    ZUC_KEY zk;                 /* working key */
} EVP_EEA3_KEY;

# define data(ctx) ((EVP_EEA3_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int eea3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc);
static int eea3_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
static int eea3_cleanup(EVP_CIPHER_CTX *ctx);

static const EVP_CIPHER zuc_128_eea3_cipher = {
    NID_zuc_128_eea3,
    1,                      /* block_size */
    ZUC_KEY_SIZE,           /* key_len */
    ZUC_CTR_SIZE,           /* iv_len, 128-bit counter in the context */
    EVP_CIPH_VARIABLE_LENGTH,
    EVP_ORIG_GLOBAL,
    eea3_init_key,
    eea3_cipher,
    eea3_cleanup,
    sizeof(EVP_EEA3_KEY),
    NULL,
    NULL,
    NULL,
    NULL
};

const EVP_CIPHER *EVP_eea3(void)
{
    return &zuc_128_eea3_cipher;
}

static int eea3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                         const unsigned char *iv, int enc)
{
    EVP_EEA3_KEY *ek = data(ctx);
    ZUC_KEY *zk = &ek->zk;
    uint32_t count;
    uint32_t bearer;
    uint32_t direction;

    zk->k = key;

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
    if (iv == NULL)
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

    zk->keystream_len = 0;
    zk->inited = 0;

    ZUC_init(zk);

    return 1;
}

static int eea3_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       const unsigned char *in, size_t inl)
{
    EVP_EEA3_KEY *ek = data(ctx);
    ZUC_KEY *zk = &ek->zk;
    unsigned int i, k, n, num = EVP_CIPHER_CTX_num(ctx);

    if (num >= zk->keystream_len && !ZUC_generate_keystream(zk))
        return 0;

    n = zk->L * sizeof(uint32_t);

    /*
     * EEA3 is based on 'bits', but we can only handle 'bytes'.
     *
     * So we choose to output a final whole byte, even if there are some
     * bits at the end of the input. Those trailing bits in the last byte
     * should be discarded by caller.
     */
    for (i = 0; i < inl; i++) {
        k = num + i;
        if (k >= zk->keystream_len) {
            if (!ZUC_generate_keystream(zk))
                return 0;
        }

        out[i] = in[i] ^ zk->keystream[k % n];
    }

    num += inl;

    /* num always points to next key byte to use */
    EVP_CIPHER_CTX_set_num(ctx, num);

    return 1;
}

static int eea3_cleanup(EVP_CIPHER_CTX *ctx)
{
    EVP_EEA3_KEY *key = data(ctx);

    ZUC_destroy_keystream(&key->zk);

    return 1;
}
#endif
