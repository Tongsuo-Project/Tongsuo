#include "crypto/wbsm4.h"

void gen_Bijection4pair(uint8_t *table, uint8_t *inverse_table) {
    for (int i = 0; i < 16; i++) {
        table[i] = (uint8_t)i;
    }

    uint32_t tmp;
    // 打乱，生成双射表
    for (int i = 0; i < 16; i++) {
        tmp = cus_random();
        int r = (i + tmp % 16) % 16;
        uint8_t tmp = table[i];
        table[i] = table[r];
        table[r] = tmp;
    }

    // 生成双射的逆
    for (int i = 0; i < 16; i++) {
        inverse_table[table[i]] = (uint8_t)i;
    }
}

void gen_Bijection32pair(Biject32 *bij, Biject32 *bij_inv) {
    for (int i = 0; i < 8; i++) {
        gen_Bijection4pair(bij->lut[i], bij_inv->lut[i]);  // 生成正向和逆向双射表
    }
}

uint32_t BijectionU32(const Biject32* bij, uint32_t x) {
    uint32_t result = 0;
    uint8_t transformed;
    for (int i = 0; i < 8; i++) {
        transformed = bij->lut[i][(x >> (28 - i * 4)) & 0x0F];  // 通过查找表变换
        result |= transformed << (28 - i * 4);  // 拼接结果
    }
    return result;
}

// uint_8 lut[8][256] 第一维是8个4bit的输入，第二维是x和y结合的索引、其中x是高4位，y是低4位
void gen_BijectXor32_table(Biject32 *in1, Biject32 *in2, Biject32* out, uint8_t lut[8][256]) {
    int x, y, j;
    uint8_t after_in1, after_in2, after_out, idx;
    for (j = 0; j < 8; j++) {
        for (x = 0; x < 16; x++) {
            for (y = 0; y < 16; y++) {
                after_in1 = in1->lut[j][x & 0x0f];
                after_in2 = in2->lut[j][y & 0x0f];
                after_in1 ^= after_in2;
                after_out = out->lut[j][after_in1];
                idx = ((x & 0x0f) << 4) | (y & 0x0f);
                lut[j][idx] = after_out;
            }
        }
    }
}

// 对输入x和y查表
uint32_t BijectXor32(uint8_t lut[8][256], uint32_t x, uint32_t y) {
    int j;
    uint32_t result = 0;
    for (j = 0; j < 8; j++) {
        uint8_t idx = (((x >> (28 - 4 * j) ) & 0x0f) << 4) | ((y >> (28 - 4 * j)) & 0x0f);
        result |= (lut[j][idx] & 0x0f) << (28 - 4 * j);
    }
    return result;
}

void wbsm4_jin_stkey_gen(const uint8_t *key, wbsm4_jin_stkey_context *ctx) {
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
        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
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


void wbsm4_jin_stkey_encrypt(const unsigned char *in, unsigned char *out, wbsm4_jin_stkey_context *ctx) {
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

void wbsm4_jin_stkey_decrypt(const unsigned char *in, unsigned char *out, wbsm4_jin_stkey_context *ctx) {
    wbsm4_jin_stkey_encrypt(in, out, ctx);
}
