#include <internal/endian.h>
#include "crypto/wbsm4.h"

void wbsm4_xiao_stkey_set_key(const uint8_t *key, wbsm4_xiao_stkey_context *ctx)
{
    DECLARE_IS_ENDIAN;

    *ctx = *(wbsm4_xiao_stkey_context *)key;
    if (IS_LITTLE_ENDIAN)
        return;

    uint8_t *p = (uint8_t *)ctx;
    uint8_t *end = p + sizeof(wbsm4_xiao_stkey_context);
    while (p < end) {
        uint8_t t;
        t = p[0];
        p[0] = p[3];
        p[3] = t;

        t = p[1];
        p[1] = p[2];
        p[2] = t;

        p += 4;
    }
}

void wbsm4_xiao_stkey_gen(const uint8_t *key, wbsm4_xiao_stkey_context *ctx)
{
    int i, j, x;
    Aff32 P[36];
    Aff32 P_inv[36];
    Aff8 Eij[32][4];
    Aff8 Eij_inv[32][4];
    Aff32 Ei_inv[32];
    Aff32 Q[32];
    Aff32 Q_inv[32];

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
        //affine P
        genaffinepairM32(&P[i], &P_inv[i]);
    }

    for (i = 0; i < 32; i++) 
    {
        //affine E
        for (j = 0; j < 4; j++) 
        {
            genaffinepairM8(&Eij[i][j], &Eij_inv[i][j]);
        }

        // combine 4 E8 to 1 E32
        affinecomM8to32(Eij_inv[i][0], Eij_inv[i][1], Eij_inv[i][2], Eij_inv[i][3], &Ei_inv[i]);

        //affine M
        affinemixM32(Ei_inv[i], P_inv[i + 1], &ctx->M[i][0]);
        affinemixM32(Ei_inv[i], P_inv[i + 2], &ctx->M[i][1]);
        affinemixM32(Ei_inv[i], P_inv[i + 3], &ctx->M[i][2]);

        //affine Q
        genaffinepairM32(&Q[i], &Q_inv[i]);

        //affine C D, C for Xi0, D for T(Xi1+Xi2+Xi3+rk)
        affinemixM32(P[i + 4], P_inv[i], &ctx->C[i]);
        affinemixM32(P[i + 4], Q_inv[i], &ctx->D[i]);
        uint32_t temp_u32 = cus_random();
        ctx->C[i].Vec.V ^= temp_u32;
        ctx->D[i].Vec.V ^= P[i + 4].Vec.V ^ temp_u32;
    }
    
    for (i = 0; i < 32; i++)
    {
        //combine QL
        M32 QL;
        MatMulMatM32(Q[i].Mat, SM4_L_matrix, &QL);

        uint32_t Q_constant[3] = {0};
        for(j = 0; j < 3; j++)
        {
            Q_constant[j] = cus_random();
        }

        for (x = 0; x < 256; x++) 
        {
            for (j = 0; j < 4; j++) 
            {
                uint8_t temp_u8 = affineU8(Eij[i][j], x);
                temp_u8 = SM4_SBOX[temp_u8 ^ ((sm4_rk[i] >> (24 - j * 8)) & 0xff)];
                uint32_t temp_32 = temp_u8 << (24 - j * 8);
                ctx->Table[i][j][x] = MatMulNumM32(QL, temp_32);
            }
            for(j = 0; j < 3; j++)
            {
                ctx->Table[i][j][x] ^= Q_constant[j];
            }
            ctx->Table[i][3][x] ^=  Q[i].Vec.V ^ Q_constant[0] ^ Q_constant[1] ^ Q_constant[2];
        }
    }

    //external encoding
    for (i = 0; i < 4; i++) 
    {
        ctx->SE[i].Mat = P[i].Mat;
        ctx->SE[i].Vec = P[i].Vec;

        ctx->FE[i].Mat = P_inv[35 - i].Mat;
        ctx->FE[i].Vec = P_inv[35 - i].Vec;
    }
}


void wbsm4_xiao_stkey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_stkey_context *ctx) {
    int i;
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
        x4 = xt1 ^ xt2 ^ xt3;
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

void wbsm4_xiao_stkey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_xiao_stkey_context *ctx) {
    wbsm4_xiao_stkey_encrypt(in, out, ctx);
}