/*
* Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
*/
#include "crypto/wbsm4.h"

void wbsm4_jin_stkey_gen(const uint8_t *key, wbsm4_jin_stkey_context *ctx)
{
    int i, j, x;
    Biject32 P[36];
    Biject32 P_inv[36];
    Biject32 Ea[32];
    Biject32 Ea_inv[32];
    Biject32 E[32];
    Biject32 E_inv[32];

    Biject32 Q[32][7];
    Biject32 Q_inv[32][7];

    uint32_t sm4_rk[32];
    if (ctx->mode == WBSM4_ENCRYPT_MODE)
    {
        wbsm4_setkey_enc(sm4_rk, key);
    }
    else
    {
        wbsm4_setkey_dec(sm4_rk, key);
    }
    InitRandom(((unsigned int)time(NULL)));

    for (i = 0; i < 36; i++) 
    {
        //non-linear P
        gen_Bijection32pair(&P[i], &P_inv[i]);
    }

    for (i = 0; i < 32; i++) 
    {
        //non-linear Ea
        gen_Bijection32pair(&Ea[i], &Ea_inv[i]);
        gen_BijectXor32_table(&P_inv[i + 1], &P_inv[i + 2], &Ea[i], ctx->P1[i]);

        // non-linear E
        gen_Bijection32pair(&E[i], &E_inv[i]);
        gen_BijectXor32_table(&Ea_inv[i], &P_inv[i + 3], &E[i], ctx->P2[i]);


        //non-linear Q
        for (j = 0; j < 7; j++) 
        {
            gen_Bijection32pair(&Q[i][j], &Q_inv[i][j]);
        }
        gen_BijectXor32_table(&P_inv[i], &Q_inv[i][0], &Q[i][4], ctx->Q1[i]);
        gen_BijectXor32_table(&Q_inv[i][4], &Q_inv[i][1], &Q[i][5], ctx->Q2[i]);
        gen_BijectXor32_table(&Q_inv[i][5], &Q_inv[i][2], &Q[i][6], ctx->Q3[i]);
        gen_BijectXor32_table(&Q_inv[i][6], &Q_inv[i][3], &P[i + 4], ctx->Q4[i]);
    }

    for (i = 0; i < 32; i++)
    {
        for (x = 0; x < 256; x++)
        {
            for (j = 0; j < 4; j++)
            {
                uint8_t high_result = E_inv[i].lut[j * 2][(x >> 4) & 0x0f];
                uint8_t low_result = E_inv[i].lut[j * 2 + 1][x & 0x0f];
                uint8_t temp_u8 = (high_result << 4) | low_result;
                temp_u8 = SM4_SBOX[temp_u8 ^ ((sm4_rk[i] >> (24 - j * 8)) & 0xff)];
                uint32_t temp_u32 = temp_u8 << (24 - j * 8);
                temp_u32 = MatMulNumM32(SM4_L_matrix, temp_u32);
                ctx->T[i][j][x] = BijectionU32(&Q[i][j], temp_u32);
            }
        }
    }

    //external encoding
    for (i = 0; i < 4; i++) 
    {
        for(x = 0; x < 16; x++)
        {
            for(j = 0; j < 8; j++)
            {
                ctx->SE[i].lut[j][x] = P[i].lut[j][x];
                ctx->FE[i].lut[j][x] = P_inv[35 - i].lut[j][x];
            }
        }
    }
}


void wbsm4_jin_stkey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_jin_stkey_context *ctx)
{
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt1, xt2, xt3, xt4;

    x0 = GET32(in);
    x1 = GET32(in + 4);
    x2 = GET32(in + 8);
    x3 = GET32(in + 12);

    x0 = BijectionU32(&ctx->SE[0], x0);
    x1 = BijectionU32(&ctx->SE[1], x1);
    x2 = BijectionU32(&ctx->SE[2], x2);
    x3 = BijectionU32(&ctx->SE[3], x3);

    for(i = 0; i < 32; i++)
    {
        xt1 = BijectXor32(ctx->P1[i], x1, x2);
        x4 = BijectXor32(ctx->P2[i], xt1, x3);

        xt1 = ctx->T[i][0][(x4 >> 24) & 0xff];
        xt2 = ctx->T[i][1][(x4 >> 16) & 0xff];
        xt3 = ctx->T[i][2][(x4 >> 8) & 0xff];
        xt4 = ctx->T[i][3][x4 & 0xff];
        
        xt1 = BijectXor32(ctx->Q1[i], x0, xt1);
        xt2 = BijectXor32(ctx->Q2[i], xt1, xt2);
        xt3 = BijectXor32(ctx->Q3[i], xt2, xt3);
        x4 = BijectXor32(ctx->Q4[i], xt3, xt4);

        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    x3 = BijectionU32(&ctx->FE[0], x3);
    x2 = BijectionU32(&ctx->FE[1], x2);
    x1 = BijectionU32(&ctx->FE[2], x1);
    x0 = BijectionU32(&ctx->FE[3], x0);

    PUT32(x3, out);
    PUT32(x2, out + 4);
    PUT32(x1, out + 8);
    PUT32(x0, out + 12);
}

void wbsm4_jin_stkey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_jin_stkey_context *ctx)
{
    wbsm4_jin_stkey_encrypt(in, out, ctx);
}
