/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>

#ifndef OPENSSL_NO_ZUC

# include "crypto/zuc.h"
# include "eia3_local.h"

static ossl_inline uint8_t GET_BIT(const unsigned char *data, uint32_t i)
{
	return (data[i / 8] & (1 << (7 - (i % 8)))) ? 1 : 0;
}

size_t EIA3_ctx_size(void)
{
    return sizeof(struct eia3_context);
}

int EIA3_Init(EIA3_CTX *ctx, const unsigned char key[EVP_ZUC_KEY_SIZE], const unsigned char iv[5])
{
    ZUC_KEY *zk = &ctx->zk;
    uint32_t count = 0;
    uint32_t bearer = 0;
    uint32_t direction = 0;

    memset(ctx, 0, sizeof(EIA3_CTX));

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
    if (iv != NULL) {
        count = ((long)iv[0] << 24) | (iv[1] << 16) | (iv[2] << 8) | iv[3];
        bearer = (iv[4] & 0xF8) >> 3;
        direction = (iv[4] & 0x4) >> 2;
    }

    zk->iv[0] = (count >> 24) & 0xFF;
    zk->iv[1] = (count >> 16) & 0xFF;
    zk->iv[2] = (count >> 8) & 0xFF;
    zk->iv[3] = count & 0xFF;

    zk->iv[4] = (bearer << 3) & 0xF8;
    zk->iv[5] = zk->iv[6] = zk->iv[7] = 0;

    zk->iv[8] = ((count >> 24) & 0xFF) ^ ((direction & 1) << 7);
    zk->iv[9] = (count >> 16) & 0xFF;
    zk->iv[10] = (count >> 8) & 0xFF;
    zk->iv[11] = count & 0xFF;

    zk->iv[12] = zk->iv[4];
    zk->iv[13] = zk->iv[5];
    zk->iv[14] = zk->iv[6] ^ ((direction & 1) << 7);
    zk->iv[15] = zk->iv[7];

    ZUC_init(zk);

    return 1;
}

int EIA3_Update(EIA3_CTX *ctx, const unsigned char *inp, size_t len)
{
    ZUC_KEY *zk = &ctx->zk;
    size_t i, length = len * 8;

    for (i = 0; i < length; i++) {
        if ((ctx->num + i/8 + 4) >= zk->keystream_len) {
            if (!ZUC_generate_keystream(zk))
                return 0;
        }

        if (GET_BIT(inp, i))
            ctx->T ^= ZUC_keystream_get_word(zk, i);
    }

    ctx->length += length;
    ctx->num += len;

    return 1;
}

void EIA3_Final(EIA3_CTX *ctx, unsigned char out[EIA3_DIGEST_SIZE])
{
    ZUC_KEY *zk = &ctx->zk;
    size_t L = (ctx->length + 64 + 31) / 32, last;
    uint32_t mac;

    if ((ctx->length / 8 + 4) >= zk->keystream_len) {
        if (!ZUC_generate_keystream(zk))
            return;
    }

    ctx->T ^= ZUC_keystream_get_word(zk, ctx->length);

    last = (L - 1) * 32;
    if ((last / 8 + 4) >= zk->keystream_len) {
        if (!ZUC_generate_keystream(zk))
            return;
    }

    mac = ctx->T ^ ZUC_keystream_get_word(zk, (L - 1) * 32);

    out[0] = (uint8_t)(mac >> 24) & 0xFF;
    out[1] = (uint8_t)(mac >> 16) & 0xFF;
    out[2] = (uint8_t)(mac >> 8) & 0xFF;
    out[3] = (uint8_t)mac & 0xFF;

    ZUC_destroy_keystream(&ctx->zk);
}
#endif
