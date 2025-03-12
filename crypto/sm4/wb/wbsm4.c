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

#include <internal/endian.h>
#include "crypto/wbsm4.h"

const uint8_t SM4_SBOX[256]={
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

const M32 SM4_L_matrix = {
    .M[0] = 0xA0202080, 
    .M[1] = 0x50101040, 
    .M[2] = 0x28080820, 
    .M[3] = 0x14040410,
    .M[4] = 0xA020208, 
    .M[5] = 0x5010104, 
    .M[6] = 0x2808082, 
    .M[7] = 0x1404041, 
    .M[8] = 0x80A02020, 
    .M[9] = 0x40501010, 
    .M[10] = 0x20280808, 
    .M[11] = 0x10140404, 
    .M[12] = 0x80A0202, 
    .M[13] = 0x4050101, 
    .M[14] = 0x82028080, 
    .M[15] = 0x41014040, 
    .M[16] = 0x2080A020, 
    .M[17] = 0x10405010, 
    .M[18] = 0x8202808, 
    .M[19] = 0x4101404, 
    .M[20] = 0x2080A02, 
    .M[21] = 0x1040501, 
    .M[22] = 0x80820280, 
    .M[23] = 0x40410140, 
    .M[24] = 0x202080A0, 
    .M[25] = 0x10104050, 
    .M[26] = 0x8082028, 
    .M[27] = 0x4041014, 
    .M[28] = 0x202080A, 
    .M[29] = 0x1010405, 
    .M[30] = 0x80808202, 
    .M[31] = 0x40404101
};

static const uint32_t SM4_FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

static const uint32_t SM4_CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};
#define GET_ULONG_BE(n, b, i)                     \
{                                                 \
    (n) = ((uint32_t)(b)[(i)] << 24) |             \
          ((uint32_t)(b)[(i) + 1] << 16) |         \
          ((uint32_t)(b)[(i) + 2] << 8)  |         \
          ((uint32_t)(b)[(i) + 3]);                \
}

#define PUT_ULONG_BE(n, b, i)                     \
{                                                 \
    (b)[(i)]     = (unsigned char)((n) >> 24);     \
    (b)[(i) + 1] = (unsigned char)((n) >> 16);     \
    (b)[(i) + 2] = (unsigned char)((n) >> 8);      \
    (b)[(i) + 3] = (unsigned char)((n));           \
}
//循环左移
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static unsigned char wbsm4Sbox(unsigned char inch)
{
    return ((unsigned char *)SM4_SBOX)[inch];
}

//T
static uint32_t wbsm4CalciRK(uint32_t ka)
{
    uint32_t bb;
    unsigned char a[4], b[4];
    PUT_ULONG_BE(ka, a, 0);
    b[0] = wbsm4Sbox(a[0]);
    b[1] = wbsm4Sbox(a[1]);
    b[2] = wbsm4Sbox(a[2]);
    b[3] = wbsm4Sbox(a[3]);
    GET_ULONG_BE(bb, b, 0);
    return bb ^ ROTL(bb, 13) ^ ROTL(bb, 23);
}

//加密的轮密钥生成
void wbsm4_setkey_enc(uint32_t rk[32], const unsigned char key[16])
{
    uint32_t MK[4];
    uint32_t k[36];
    int i;
    
    GET_ULONG_BE(MK[0], key, 0);
    GET_ULONG_BE(MK[1], key, 4);
    GET_ULONG_BE(MK[2], key, 8);
    GET_ULONG_BE(MK[3], key, 12);
    
    k[0] = MK[0] ^ SM4_FK[0];
    k[1] = MK[1] ^ SM4_FK[1];
    k[2] = MK[2] ^ SM4_FK[2];
    k[3] = MK[3] ^ SM4_FK[3];
    
    for (i = 0; i < 32; i++) {
        k[i + 4] = k[i] ^ wbsm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i]);
        rk[i] = k[i + 4];
    }
}

//解密的轮密钥生成
void wbsm4_setkey_dec(uint32_t rk[32], const unsigned char key[16])
{
    int i;
    wbsm4_setkey_enc(rk, key);
    for (i = 0; i < 16; i++) {
        uint32_t tmp = rk[i];
        rk[i] = rk[31 - i];
        rk[31 - i] = tmp;
    }
}

void wbsm4_set_key(const uint8_t *key, void *ctx, size_t len_ctx)
{
    DECLARE_IS_ENDIAN;

    memcpy(ctx, key, len_ctx);
    if (IS_LITTLE_ENDIAN)
        return;

    uint8_t *p = (uint8_t *)ctx;
    uint8_t *end = p + sizeof(wbsm4_xiao_dykey_context);
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

void wbsm4_export_key(const void *ctx, uint8_t *key, size_t len_ctx)
{
    DECLARE_IS_ENDIAN;

    memcpy(key, ctx, len_ctx);
    if (IS_LITTLE_ENDIAN)
        return;

    uint8_t *p = (uint8_t *)key;
    uint8_t *end = p + len_ctx;
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
void gen_Bijection4pair(uint8_t *table, uint8_t *inverse_table)
{
    for (int i = 0; i < 16; i++) {
        table[i] = (uint8_t)i;
    }

    uint8_t buff_table_entry;
    for (int i = 0; i < 16; i++) {
        int r = (i + cus_random() % 16) % 16;
        buff_table_entry = table[i];
        table[i] = table[r];
        table[r] = buff_table_entry;
    }

    // 生成双射的逆
    for (int i = 0; i < 16; i++) {
        inverse_table[table[i]] = (uint8_t)i;
    }
}

void gen_Bijection32pair(Biject32 *bij, Biject32 *bij_inv)
{
    for (int i = 0; i < 8; i++)
    {
        gen_Bijection4pair(bij->lut[i], bij_inv->lut[i]);  // 生成正向和逆向双射表
    }
}

uint32_t BijectionU32(const Biject32* bij, uint32_t x)
{
    uint32_t result = 0;
    uint8_t transformed;
    for (int i = 0; i < 8; i++) {
        transformed = bij->lut[i][(x >> (28 - i * 4)) & 0x0F];  // lut
        result |= transformed << (28 - i * 4);
    }
    return result;
}

// uint_8 lut[8][256] 第一维是8个4bit的输入，第二维是x和y结合的索引、其中x是高4位，y是低4位
void gen_BijectXor32_table(Biject32 *in1, Biject32 *in2, Biject32* out, uint8_t lut[8][256])
{
    int x, y, j;
    uint8_t after_in1, after_in2, after_out, idx;
    for (j = 0; j < 8; j++)
    {
        for (x = 0; x < 16; x++)
        {
            for (y = 0; y < 16; y++)
            {
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
uint32_t BijectXor32(uint8_t lut[8][256], uint32_t x, uint32_t y)
{
    int j;
    uint32_t result = 0;
    for (j = 0; j < 8; j++)
    {
        uint8_t idx = (((x >> (28 - 4 * j) ) & 0x0f) << 4) | ((y >> (28 - 4 * j)) & 0x0f);
        result |= (lut[j][idx] & 0x0f) << (28 - 4 * j);
    }
    return result;
}
