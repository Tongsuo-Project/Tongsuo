/*
* Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
* Copyright 2024 Nexus-TYF. All Rights Reserved.
* Ported from Nexus-TYF/Xiao-Lai-White-box-SM4.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
*/
#include "crypto/wbsm4.h"

void wbsm4_xiao_dykey_gen(const uint8_t *key, wbsm4_xiao_dykey_context *ctx, wbsm4_xiao_dykey_ctxrk *ctxrk)
{
    int i, j, x, y;
    uint32_t temp_u32;
    uint8_t after_in1, after_in2, after_out;
    uint8_t high_result, low_result;
    Aff32 P[36];
    Aff32 P_inv[36];
    Aff8 Eij[32][4];
    Aff8 Eij_inv[32][4];
    Aff32 Ei_inv[32];
    Aff8 Eaij[32][4];
    Aff8 Eaij_inv[32][4];
    Aff8 Ekij[32][4];
    Aff8 Ekij_inv[32][4];
    Aff32 Q[32];
    Aff32 Q_inv[32];
    Biject32 R[32];
    Biject32 R_inv[32];

    M32 QL;

    uint32_t Q_constant[3] = {0};

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
        /* affine P */
        genaffinepairM32(&P[i], &P_inv[i]);
    }

    for (i = 0; i < 32; i++) 
    {
        /* affine E */
        for (j = 0; j < 4; j++) 
        {
            genaffinepairM8(&Eij[i][j], &Eij_inv[i][j]);
            genaffinepairM8(&Eaij[i][j], &Eaij_inv[i][j]);
            genaffinepairM8(&Ekij[i][j], &Ekij_inv[i][j]);
        }

        affinecomM8to32(Ekij_inv[i][0], Ekij_inv[i][1], Ekij_inv[i][2], Ekij_inv[i][3], &ctxrk->Ek[i]);

        /*  non-linear R and whitebox round key */
        gen_Bijection32pair(&R[i], &R_inv[i]);
        temp_u32 = affineU32(ctxrk->Ek[i], sm4_rk[i]);
        ctx->wbrk[i] = BijectionU32(&R[i], temp_u32);

        /*  combine 4 E8 to 1 E32 */
        affinecomM8to32(Eij_inv[i][0], Eij_inv[i][1], Eij_inv[i][2], Eij_inv[i][3], &Ei_inv[i]);

        /* affine M */
        affinemixM32(Ei_inv[i], P_inv[i + 1], &ctx->M[i][0]);
        affinemixM32(Ei_inv[i], P_inv[i + 2], &ctx->M[i][1]);
        affinemixM32(Ei_inv[i], P_inv[i + 3], &ctx->M[i][2]);

        /* affine Q */
        genaffinepairM32(&Q[i], &Q_inv[i]);

        /* affine C D, C for Xi0, D for T(Xi1+Xi2+Xi3+rk) */
        affinemixM32(P[i + 4], P_inv[i], &ctx->C[i]);
        affinemixM32(P[i + 4], Q_inv[i], &ctx->D[i]);
        temp_u32 = cus_random();
        ctx->C[i].Vec.V ^= temp_u32;
        ctx->D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;

        /* encoding for whitebox round key */
        ctxrk->R[i] = R[i];
    }
    
    for (i = 0; i < 32; i++)
    {
        /*  calculate xor table */
        for (j = 0; j < 4; j++)
        {
            for (x = 0; x < 256; x++)
            {
                for (y = 0; y < 256; y++)
                {
                    high_result = R_inv[i].lut[j * 2][(y >> 4) & 0x0f];
                    low_result = R_inv[i].lut[j * 2 + 1][y & 0x0f];
                    after_in1 = (high_result << 4) | low_result;
                    after_in1 = affineU8(Ekij[i][j], after_in1);

                    after_in2 = affineU8(Eij[i][j], x);
                    after_in1 ^= after_in2;
                    after_out = affineU8(Eaij_inv[i][j], after_in1);
                    ctx->Xor32Table[i][j][x][y] = after_out;
                }
            }
        }

        /* combine QL */
        MatMulMatM32(Q[i].Mat, SM4_L_matrix, &QL);

        for(j = 0; j < 3; j++)
        {
            Q_constant[j] = cus_random();
        }

        for (x = 0; x < 256; x++) 
        {
            for (j = 0; j < 4; j++) 
            {
                after_in1 = affineU8(Eaij[i][j], x);
                after_in1 = SM4_SBOX[after_in1];
                temp_u32 = after_in1 << (24 - j * 8);
                ctx->Table[i][j][x] = MatMulNumM32(QL, temp_u32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->Table[i][j][x] ^= Q_constant[j];
            }
            ctx->Table[i][3][x] ^=  Q[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }

    /* external encoding */
    for (i = 0; i < 4; i++) 
    {
        ctx->SE[i].Mat = P[i].Mat;
        ctx->SE[i].Vec = P[i].Vec;

        ctx->FE[i].Mat = P_inv[35 - i].Mat;
        ctx->FE[i].Vec = P_inv[35 - i].Vec;
    }

    ctxrk->mode = ctx->mode;    
}

void wbsm4_xiao_dykey_key2wbrk(uint8_t *key, wbsm4_xiao_dykey_ctxrk *ctxrk, uint32_t wbrk[32])
{
    int i;
    uint32_t tmp_rk;
    uint32_t sm4_rk[32];
    if (ctxrk->mode == WBSM4_ENCRYPT_MODE)
    {
        wbsm4_setkey_enc(sm4_rk, key);
    }
    else
    {
        wbsm4_setkey_dec(sm4_rk, key);
    }
    for (i = 0; i < 32; i++)
    {
        tmp_rk = affineU32(ctxrk->Ek[i], sm4_rk[i]);
        wbrk[i] = BijectionU32(&ctxrk->R[i], tmp_rk);
    }
}

void wbsm4_xiao_dykey_update_wbrk(wbsm4_xiao_dykey_context *ctx, uint32_t wbrk[32])
{
    int i;
    for (i = 0; i < 32; i++)
    {
        ctx->wbrk[i] = wbrk[i];
    }
}

void wbsm4_xiao_dykey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_dykey_context *ctx)
{
    int i, j;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;

    x0 = GET32(in);
    x1 = GET32(in + 4);
    x2 = GET32(in + 8);
    x3 = GET32(in + 12);

    x0 = affineU32(ctx->SE[0], x0);
    x1 = affineU32(ctx->SE[1], x1);
    x2 = affineU32(ctx->SE[2], x2);
    x3 = affineU32(ctx->SE[3], x3);

    for(i = 0; i < 32; i++)
    {
        xt1 = affineU32(ctx->M[i][0], x1);
        xt2 = affineU32(ctx->M[i][1], x2);
        xt3 = affineU32(ctx->M[i][2], x3);
        xt1 = xt1 ^ xt2 ^ xt3;
        x4 = 0;
        for (j = 0; j < 4; j++)
        {
            x4 |= (ctx->Xor32Table[i][j][(xt1 >> (24 - 8 * j) ) & 0xff][ctx->wbrk[i] >> (24 - 8 * j) & 0xff]) << (24 - 8 * j);
        }
        x4 = ctx->Table[i][0][(x4 >> 24) & 0xff] ^ ctx->Table[i][1][(x4 >> 16) & 0xff] ^ ctx->Table[i][2][(x4 >> 8) & 0xff] ^ ctx->Table[i][3][x4 & 0xff];
        xt0 = affineU32(ctx->C[i], x0);
        xt4 = affineU32(ctx->D[i], x4);
        x4 = xt0 ^ xt4;

        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    x0 = affineU32(ctx->FE[3], x0);
    x1 = affineU32(ctx->FE[2], x1);
    x2 = affineU32(ctx->FE[1], x2);
    x3 = affineU32(ctx->FE[0], x3);

    PUT32(x3, out);
    PUT32(x2, out + 4);
    PUT32(x1, out + 8);
    PUT32(x0, out + 12);
}

void wbsm4_xiao_dykey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_dykey_context *ctx)
{
    wbsm4_xiao_dykey_encrypt(in, out, ctx);
}
