/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include "crypto/nonlinearwbsm4.h"
#include <string.h> 
#include <openssl/crypto.h>
/*====sm4轮密钥生成==== */
# define SM4_KEY_SCHEDULE  32
typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;
static uint32_t load_u32_be1(const uint8_t *b, uint32_t n);
static uint32_t rotl1(uint32_t a, uint8_t n);
/*ossl_sm4_set_key1函数代码来源于sm4.c，用于sm4的轮密钥生成，防止sm4模块关闭无法使用白盒sm4模块*/
static int ossl_sm4_set_key1(const uint8_t *key, SM4_KEY *ks);
static const uint8_t SM4_S[256] = {
        0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
        0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
        0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
        0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
        0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
        0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
        0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
        0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
        0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
        0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
        0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
        0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
        0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
        0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
        0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
        0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
        0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
        0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
        0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
        0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
        0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
        0xD7, 0xCB, 0x39, 0x48
};
static uint32_t load_u32_be1(const uint8_t *b, uint32_t n)
{
    return ((uint32_t)(b[4 * n] & 0xFF) << 24) |
           ((uint32_t)(b[4 * n + 1] & 0xFF) << 16) |
           ((uint32_t)(b[4 * n + 2] & 0xFF) << 8) |
           (uint32_t)(b[4 * n + 3] & 0xFF);
}
static uint32_t rotl1(uint32_t a, uint8_t n)
{
    return (a << n) | (a >> (32 - n));
}
static int ossl_sm4_set_key1(const uint8_t *key, SM4_KEY *ks)
{
    /*
     * Family Key
     */
    static const uint32_t FK[4] =
            { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

    /*
     * Constant Key
     */
    static const uint32_t CK[32] = {
            0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
            0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
            0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
            0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
            0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
            0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
            0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t K[4];
    int i;

    K[0] = load_u32_be1(key, 0) ^ FK[0];
    K[1] = load_u32_be1(key, 1) ^ FK[1];
    K[2] = load_u32_be1(key, 2) ^ FK[2];
    K[3] = load_u32_be1(key, 3) ^ FK[3];

    for (i = 0; i != SM4_KEY_SCHEDULE; ++i) {
        uint32_t X = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];
        uint32_t t = 0;

        t |= ((uint32_t)(SM4_S[(uint8_t)(X >> 24)] & 0xFF) << 24);
        t |= ((uint32_t)(SM4_S[(uint8_t)(X >> 16)] & 0xFF) << 16);
        t |= ((uint32_t)(SM4_S[(uint8_t)(X >> 8)] & 0xFF) << 8);
        t |= (uint32_t)(SM4_S[(uint8_t)X] & 0xFF);

        t = t ^ rotl1(t, 13) ^ rotl1(t, 23);
        K[i % 4] ^= t;
        ks->rk[i] = K[i % 4];
    }
    return 1;
}

static uint8_t  SBOX[256] = {
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

#define GET32(pc)  (\
((uint32_t)(pc)[0] << 24) ^\
((uint32_t)(pc)[1] << 16) ^\
((uint32_t)(pc)[2] <<  8) ^\
((uint32_t)(pc)[3]))

#define PUT32(st, ct)\
(ct)[0] = (uint8_t)((st) >> 24);\
(ct)[1] = (uint8_t)((st) >> 16);\
(ct)[2] = (uint8_t)((st) >>  8);\
(ct)[3] = (uint8_t)(st)

static Nonlinear8 Pij[36][4];
static Nonlinear8 Pij_inv[36][4];

static Nonlinear32 Ei[32];
static Nonlinear32 Ei_inv[32];
static Nonlinear8 Eij[32][4];
static Nonlinear8 Eij_inv[32][4];
static Nonlinear32 Fi[32];
static Nonlinear32 Fi_inv[32];
static Nonlinear8 Fij[32][4];
static Nonlinear8 Fij_inv[32][4];

static Aff32 Gi[32];
static Aff32 Gi_inv[32];
static Aff8 Gij[32][4];
static Aff8 Gij_inv[32][4];
static Aff8 Aij_inv[32][4];
static Aff8 Aij[32][4];
static Aff32 Ai[32];
static Aff32 Ai_inv[32];

static Nonlinear32 Qi[32];
static Nonlinear8 Qij[32][4];
static Nonlinear8 Qij_inv[32][4];

static Aff32 Hi[32];
static Aff8 Hij[32][4];
static Aff8 Hij_inv[32][4];

static Nonlinear32 Wi[32];
static Nonlinear8 Wij[32][4];
static Nonlinear8 Wij_inv[32][4];

static Nonlinear32 Ci[32];
static Nonlinear8 Cij[32][4];
static Nonlinear8 Cij_inv[32][4];

static Nonlinear32 Di[32];
static Nonlinear8 Dij[32][4];
static Nonlinear8 Dij_inv[32][4];

static Aff8 Bij[32][4];
static Aff8 Bij_inv[32][4];
static Aff32 Bi[32];
static Aff32 Bi_inv[32];

static void wbsm4_gen_init(WB_SM4_Tables* tables);
static void wbsm4_gen_part1(WB_SM4_Tables* tables);
static void wbsm4_gen_part2(const SM4_KEY* sm4_key, WB_SM4_Tables* tables);
static void wbsm4_gen_part3(WB_SM4_Tables* tables);
static void wbsm4_gen_part4_1(WB_SM4_Tables* tables);
static void wbsm4_gen_part4_2(WB_SM4_Tables* tables);
static void wbsm4_gen_part4_3(WB_SM4_Tables* tables);
static void swap(uint8_t* a, uint8_t* b);
static void generate_S_box_and_inverse(uint8_t* mapping);
static void genNonlinearPair(Nonlinear8* nl, Nonlinear8* nl_inv);
static void nonlinearCom8to32(Nonlinear8 n1, Nonlinear8 n2, Nonlinear8 n3, Nonlinear8 n4, Nonlinear32* res);
static uint8_t nonlinearU8(Nonlinear8* n8, uint8_t arr);
static uint32_t nonlinearU32(const Nonlinear32* n32, uint32_t arr);

/*交换函数，用于打乱 S 盒 */
static void swap(uint8_t* a, uint8_t* b) {
    uint8_t temp = *a;
    *a = *b;
    *b = temp;
}
/* 生成 S 盒  */
static void generate_S_box_and_inverse(uint8_t* mapping) {
    int i, j; 
    static int initialized = 0; /* 声明必须放在代码块开头 */

    /* 初始化 S 盒为单位置换 */
    for (i = 0; i < 256; i++) {
        mapping[i] = i;
    }

    /* 使用 srand 初始化随机数生成器，仅初始化一次 */
    if (!initialized) {
        srand((unsigned int)time(NULL));
        initialized = 1;
    }

    for (i = 255; i > 0; i--) {
        j = rand() % (i + 1);
        swap(&mapping[i], &mapping[j]);
    }
}

 /*生成非线性双射对*/
 static void genNonlinearPair(Nonlinear8* nl, Nonlinear8* nl_inv) {
    int i;
    generate_S_box_and_inverse(nl->mapping);
    for (i = 0; i < 256; i++) {
        nl_inv->mapping[nl->mapping[i]] = i;
    }
}

static void nonlinearCom8to32(Nonlinear8 n1, Nonlinear8 n2, Nonlinear8 n3, Nonlinear8 n4, Nonlinear32* res) {
    int i;
    for (i = 0; i < 256; i++) {
        res->n8_1.mapping[i] = n1.mapping[i];
        res->n8_2.mapping[i] = n2.mapping[i];
        res->n8_3.mapping[i] = n3.mapping[i];
        res->n8_4.mapping[i] = n4.mapping[i];
    }
}
static uint8_t nonlinearU8(Nonlinear8* n8, uint8_t arr) {
    return n8->mapping[arr];
}
 /*非线性变换*/
 static uint32_t nonlinearU32(const Nonlinear32* n32, uint32_t arr) {
    uint8_t byte1, byte2, byte3, byte4; /* 提前声明所有变量 */
    uint8_t new_byte1, new_byte2, new_byte3, new_byte4;

    /* 将 32 位数 arr 拆分成 4 个 8 位部分 */
    byte1 = (arr >> 24) & 0xFF;  /* 获取最高字节 */
    byte2 = (arr >> 16) & 0xFF;  /* 获取第二字节 */
    byte3 = (arr >> 8) & 0xFF;   /* 获取第三字节 */
    byte4 = arr & 0xFF;          /* 获取最低字节 */

    /* 使用 Nonlinear32 中的映射计算每个字节的新值 */
    new_byte1 = n32->n8_1.mapping[byte1];  /* 使用 n8_1.mapping 进行 8 位映射 */
    new_byte2 = n32->n8_2.mapping[byte2];  /* 使用 n8_2.mapping 进行 8 位映射 */
    new_byte3 = n32->n8_3.mapping[byte3];  /* 使用 n8_3.mapping 进行 8 位映射 */
    new_byte4 = n32->n8_4.mapping[byte4];  /* 使用 n8_4.mapping 进行 8 位映射 */

    /* 重新拼接 4 个字节，形成一个新的 32 位数 */
    return ( (uint32_t)new_byte1 << 24 ) |
           ( (uint32_t)new_byte2 << 16 ) |
           ( (uint32_t)new_byte3 << 8 )  |
           (uint32_t)new_byte4;
}

static M32 L_matrix = {
    {
    0xA0202080,
    0x50101040,
    0x28080820,
     0x14040410,
    0xA020208,
    0x5010104,
    0x2808082,
    0x1404041,
    0x80A02020,
    0x40501010,
    0x20280808,
    0x10140404,
    0x80A0202,
    0x4050101,
    0x82028080,
    0x41014040,
    0x2080A020,
    0x10405010,
    0x8202808,
    0x4101404,
    0x2080A02,
    0x1040501,
    0x80820280,
    0x40410140,
    0x202080A0,
    0x10104050,
    0x8082028,
    0x4041014,
    0x202080A,
    0x1010405,
    0x80808202,
    0x40404101
    }
};

static void wbsm4_gen_init(WB_SM4_Tables* tables) {
    int i, j; 
    /* 生成36轮Pij和Pij_inv */
    for (i = 0; i < 36; i++) {
        for (j = 0; j < 4; j++) {
            genNonlinearPair(&Pij[i][j], &Pij_inv[i][j]);
        }
        nonlinearCom8to32(Pij_inv[i][0], Pij_inv[i][1], Pij_inv[i][2], Pij_inv[i][3], &tables->P_inv[i]);
        nonlinearCom8to32(Pij[i][0], Pij[i][1], Pij[i][2], Pij[i][3], &tables->P[i]);
    }

    for (i = 0; i < 32; i++) {
        for (j = 0; j < 4; j++) {
            /* 生成32个Ei，每个Ei由4个8×8的Eij组成 */
            genNonlinearPair(&Eij[i][j], &Eij_inv[i][j]);
            /* 生成32个Fi，每个Fi由4个8×8的Fij组成 */
            genNonlinearPair(&Fij[i][j], &Fij_inv[i][j]);
            /* 生成32个Gi，每个Gi由4个8×8的Gij组成 */
            genaffinepairM8(&Gij[i][j], &Gij_inv[i][j]);
            /* 生成32个Ai，每个Ai由4个8×8的Aij组成,且Ai的Vec为0 */
            Aij[i][j].Mat = Gij[i][j].Mat;
            Aij[i][j].Vec.V = 0;
            /* 生成32个Ai_inv，每个Ai_inv由4个8×8的Aij_inv组成,且Ai_inv的Vec为0 */
            Aij_inv[i][j].Mat = Gij_inv[i][j].Mat;
            Aij_inv[i][j].Vec.V = 0;
            /* 生成32个Qi，每个Qi由4个8×8的Qij组成 */
            genNonlinearPair(&Qij[i][j], &Qij_inv[i][j]);
            /* 生成32个Hi，每个Hi由4个8×8的Hij组成 */
            genaffinepairM8(&Hij[i][j], &Hij_inv[i][j]);
            /* 生成32个Bi_inv，每个Bi_inv由4个8×8的Bij_inv组成,且Bi_inv的Vec为0 */
            Bij_inv[i][j].Mat = Hij_inv[i][j].Mat;
            Bij_inv[i][j].Vec.V = 0;
            Bij[i][j].Mat = Hij[i][j].Mat;
            Bij[i][j].Vec.V = 0;
            /* 生成32个Wi，每个Wi由4个8×8的Wij组成 */
            genNonlinearPair(&Wij[i][j], &Wij_inv[i][j]);
            /* 生成32个Ci，每个Ci由4个8×8的Cij组成 */
            genNonlinearPair(&Cij[i][j], &Cij_inv[i][j]);
            /* 生成32个Di，每个Di由4个8×8的Dij组成 */
            genNonlinearPair(&Dij[i][j], &Dij_inv[i][j]);
        }
        /* 将4个8×8的Eij_inv复合成一个32×32的Ei_inv */
        nonlinearCom8to32(Eij_inv[i][0], Eij_inv[i][1], Eij_inv[i][2], Eij_inv[i][3], &Ei_inv[i]);
        /* 将4个8×8的Eij复合成一个32×32的Ei */
        nonlinearCom8to32(Eij[i][0], Eij[i][1], Eij[i][2], Eij[i][3], &Ei[i]);
        /* 将4个8×8的Fij_inv复合成一个32×32的Fi_inv */
        nonlinearCom8to32(Fij_inv[i][0], Fij_inv[i][1], Fij_inv[i][2], Fij_inv[i][3], &Fi_inv[i]);
        /* 将4个8×8的Fij复合成一个32×32的Fi */
        nonlinearCom8to32(Fij[i][0], Fij[i][1], Fij[i][2], Fij[i][3], &Fi[i]);
        affinecomM8to32(Gij_inv[i][0], Gij_inv[i][1], Gij_inv[i][2], Gij_inv[i][3], &Gi_inv[i]);
        affinecomM8to32(Gij[i][0], Gij[i][1], Gij[i][2], Gij[i][3], &Gi[i]);
        /* 将4个8×8的Qij复合成一个32×32的Qi */
        nonlinearCom8to32(Qij[i][0], Qij[i][1], Qij[i][2], Qij[i][3], &Qi[i]);
        /* 将4个8×8的Hij复合成一个32×32的Hi */
        affinecomM8to32(Hij[i][0], Hij[i][1], Hij[i][2], Hij[i][3], &Hi[i]);
        /* 将4个8×8的Wij复合成一个32×32的Wi */
        nonlinearCom8to32(Wij[i][0], Wij[i][1], Wij[i][2], Wij[i][3], &Wi[i]);
        /* 将4个8×8的Cij复合成一个32×32的Ci */
        nonlinearCom8to32(Cij[i][0], Cij[i][1], Cij[i][2], Cij[i][3], &Ci[i]);
        /* 将4个8×8的Dij复合成一个32×32的Di */
        nonlinearCom8to32(Dij[i][0], Dij[i][1], Dij[i][2], Dij[i][3], &Di[i]);
        /* 将4个8×8的Aij复合成一个32×32的Ai */
        affinecomM8to32(Aij[i][0], Aij[i][1], Aij[i][2], Aij[i][3], &Ai[i]);
        /* 将4个8×8的Aij_inv复合成一个32×32的Ai_inv */
        affinecomM8to32(Aij_inv[i][0], Aij_inv[i][1], Aij_inv[i][2], Aij_inv[i][3], &Ai_inv[i]);
        /* 将4个8×8的Bij复合成一个32×32的Bi */
        affinecomM8to32(Bij[i][0], Bij[i][1], Bij[i][2], Bij[i][3], &Bi[i]);
        /* 将4个8×8的Bij_inv复合成一个32×32的Bi_inv */
        affinecomM8to32(Bij_inv[i][0], Bij_inv[i][1], Bij_inv[i][2], Bij_inv[i][3], &Bi_inv[i]);
    }
}
static void wbsm4_gen_part4_3(WB_SM4_Tables* tables) {
    int i, x, j; 
    uint8_t x1, x2, temp; /* 提前声明局部变量 */

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 65536; x++) {
            for (j = 0; j < 4; j++) {
                x1 = (x >> 8) & 0xff; /* 高8位 */
                x2 = x & 0xff;       /* 低8位 */
                temp = nonlinearU8(&Cij_inv[i][j], x1) ^ nonlinearU8(&Dij_inv[i][j], x2);
                tables->part4_3_table[i][j][x] = nonlinearU8(&Pij[i + 4][j], temp);
            }
        }
    }

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 65536; x++) {
            for (j = 0; j < 4; j++) {
                x1 = (x >> 8) & 0xff; /* 高8位 */
                x2 = x & 0xff;       /* 低8位 */
                temp = nonlinearU8(&Cij_inv[i][j], x1) ^ nonlinearU8(&Dij_inv[i][j], x2);
                tables->part4_3_table_dec[i][j][x] = nonlinearU8(&Pij[i][j], temp);
            }
        }
    }
}
static void wbsm4_gen_part3(WB_SM4_Tables* tables) {
    int i, x, j; 
    uint8_t Pij_inv_val, CijComPij_inv_val, Qij_inv_val, Hij_invComQij_inv_val, Bij_invComHij_invComQij_inv_val, Hij_invComBij_val;

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
                Pij_inv_val = nonlinearU8(&Pij_inv[i][j], x);
                CijComPij_inv_val = nonlinearU8(&Cij[i][j], Pij_inv_val);
                tables->part3_table1[i][j][x] = CijComPij_inv_val;
            }
        }
    }

    /* 生成i+4表 part3_table1_dec[i][j][x] */
    for (i = 0; i < 32; i++) {
        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
                Pij_inv_val = nonlinearU8(&Pij_inv[i + 4][j], x);
                CijComPij_inv_val = nonlinearU8(&Cij[i][j], Pij_inv_val);
                tables->part3_table1_dec[i][j][x] = CijComPij_inv_val;
            }
        }
    }

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
                Qij_inv_val = nonlinearU8(&Qij_inv[i][j], x);
                Hij_invComQij_inv_val = affineU8(Hij_inv[i][j], Qij_inv_val);
                Bij_invComHij_invComQij_inv_val = affineU8(Bij_inv[i][j], Hij_invComQij_inv_val);
                Hij_invComBij_val = affineU8(Hij_inv[i][j], Bij_invComHij_invComQij_inv_val);
                tables->part3_table2[i][j][x] = nonlinearU8(&Dij[i][j], Hij_invComBij_val);
            }
        }
    }
}/* 共32轮，每轮有4张输入16bit，输出8bit的查找表 */
static void wbsm4_gen_part4_1(WB_SM4_Tables* tables) {
    int i, x, j; 
    uint8_t x1, x2, temp, Gij_val, Eij_invComGij_val;

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 65536; x++) {
            for (j = 0; j < 4; j++) {
                x1 = (x >> 8) & 0xff; /* 高8位 */
                x2 = x & 0xff;       /* 低8位 */
                temp = nonlinearU8(&Eij[i][j], x1) ^ nonlinearU8(&Fij[i][j], x2);
                Gij_val = affineU8(Gij[i][j], temp);
                Eij_invComGij_val = nonlinearU8(&Eij_inv[i][j], Gij_val);
                tables->part4_1_table[i][j][x] = Eij_invComGij_val;
            }
        }
    }
}/* 共32轮，每轮有4个输入8bit，输出8bit的查找表 */
static void wbsm4_gen_part1(WB_SM4_Tables* tables) {
    int i, x, j; 
    uint8_t Pij_inv_val_1, Eij_invComPij_inv_val, Pij_inv_val_2, Fij_invComPij_inv_val, Pij_inv_val_3, GijComPij_inv_val, Fij_invComGijComPij_inv_val;

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
                /* Eij_invComPij_inv为Eij_inv与Pij_inv的复合 */
                Pij_inv_val_1 = nonlinearU8(&Pij_inv[i + 1][j], x);
                Eij_invComPij_inv_val = nonlinearU8(&Eij_inv[i][j], Pij_inv_val_1);

                /* Fij_invComPij_inv为Fij_inv与Pij_inv的复合 */
                Pij_inv_val_2 = nonlinearU8(&Pij_inv[i + 2][j], x);
                Fij_invComPij_inv_val = nonlinearU8(&Fij_inv[i][j], Pij_inv_val_2);

                Pij_inv_val_3 = nonlinearU8(&Pij_inv[i + 3][j], x);
                GijComPij_inv_val = affineU8(Gij[i][j], Pij_inv_val_3);
                Fij_invComGijComPij_inv_val = nonlinearU8(&Fij_inv[i][j], GijComPij_inv_val);

                tables->part1_table1[i][j][x] = Eij_invComPij_inv_val;
                tables->part1_table2[i][j][x] = Fij_invComPij_inv_val;
                tables->part1_table3[i][j][x] = Fij_invComGijComPij_inv_val;
            }
        }
    }
}
static void wbsm4_gen_part4_2(WB_SM4_Tables* tables) {
    int i, x, j; 
    uint8_t x1, x2, temp, Hi_val, QiComHi_val; /* 提前声明局部变量 */

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 65536; x++) {
            for (j = 0; j < 4; j++) {
                x1 = (x >> 8) & 0xff; /* 高8位 */
                x2 = x & 0xff;        /* 低8位 */
                temp = nonlinearU8(&Qij_inv[i][j], x1) ^ nonlinearU8(&Wij_inv[i][j], x2);
                Hi_val = affineU8(Hij[i][j], temp);
                QiComHi_val = nonlinearU8(&Qij[i][j], Hi_val);
                tables->part4_2_table[i][j][x] = QiComHi_val;
            }
        }
    }
}

static void wbsm4_gen_part2(const SM4_KEY* sm4_key, WB_SM4_Tables* tables) {
    int i, x, j; 
    uint8_t Eij_val, Gij_invComEij_val, Aij_invComGij_invComEij_val; /* 提前声明局部变量 */
    uint32_t temp_32_0, temp_32_1, temp_32_2, temp_32_3, Hi_val_1, Hi_val_2, HiComHi_val;

    for (i = 0; i < 32; i++) {
        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
                Eij_val = nonlinearU8(&Eij[i][j], x);
                Gij_invComEij_val = affineU8(Gij_inv[i][j], Eij_val);
                Aij_invComGij_invComEij_val = affineU8(Aij_inv[i][j], Gij_invComEij_val);
                tables->part2_table_temp[i][j][x] = SBOX[Aij_invComGij_invComEij_val ^ ((sm4_key->rk[i] >> (24 - j * 8)) & 0xff)];
            }
        }

        for (x = 0; x < 256; x++) {
            /* 将 x 显式转换为 uint32_t 后再左移 */
            temp_32_0 = (uint32_t)x << 24;  
            tables->part2_table[i][0][x] = nonlinearU32(&Qi[i], temp_32_0);

            temp_32_1 = (uint32_t)x << 16;  
            tables->part2_table[i][1][x] = nonlinearU32(&Wi[i], temp_32_1);

            temp_32_2 = (uint32_t)x << 8;  
            Hi_val_1 = affineU32(Hi[i], temp_32_2);
            tables->part2_table[i][2][x] = nonlinearU32(&Wi[i], Hi_val_1);

            temp_32_3 = (uint32_t)x;   
            Hi_val_2 = affineU32(Hi[i], temp_32_3);
            HiComHi_val = affineU32(Hi[i], Hi_val_2);
            tables->part2_table[i][3][x] = nonlinearU32(&Wi[i], HiComHi_val);
        }
    }
}

void Nonlinearwbsm4_encrypt(const unsigned char IN[16], unsigned char OUT[16], const WB_SM4_Tables* tables) {
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;
    uint8_t xt0_1, xt0_2, xt0_3, xt0_4, xt1_1, xt1_2, xt1_3, xt1_4;
    uint8_t xt2_1, xt2_2, xt2_3, xt2_4, xt3_1, xt3_2, xt3_3, xt3_4;
    uint8_t xt4_1, xt4_2, xt4_3, xt4_4, x4_1, x4_2, x4_3, x4_4;
    uint32_t temp_part4_1, part2_temp;
    uint8_t part2_temp_1, part2_temp_2, part2_temp_3, part2_temp_4;
    uint32_t res_part2_1, res_part2_2, res_part2_3, res_part2_4;
    uint8_t res_part2_1_1, res_part2_1_2, res_part2_1_3, res_part2_1_4;
    uint8_t res_part2_2_1, res_part2_2_2, res_part2_2_3, res_part2_2_4;
    uint8_t res_part2_3_1, res_part2_3_2, res_part2_3_3, res_part2_3_4;
    uint8_t res_part2_4_1, res_part2_4_2, res_part2_4_3, res_part2_4_4;
    uint32_t temp_part4_2_1, temp_part4_2_2;
    uint32_t out0, out1, out2, out3;

    /* 输入外部编码 */
    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);

    x0 = nonlinearU32(&tables->P[0], x0);  /* P0 */
    x1 = nonlinearU32(&tables->P[1], x1);  /* P1 */
    x2 = nonlinearU32(&tables->P[2], x2);  /* P2 */
    x3 = nonlinearU32(&tables->P[3], x3);  /* P3 */

    /* 执行核心加密 */
    for (i = 0; i < 32; i++) {
        /* part1 */
        xt1 = ((uint32_t)tables->part1_table1[i][0][(x1 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part1_table1[i][1][(x1 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part1_table1[i][2][(x1 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part1_table1[i][3][x1 & 0xff];
        xt2 = ((uint32_t)tables->part1_table2[i][0][(x2 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part1_table2[i][1][(x2 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part1_table2[i][2][(x2 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part1_table2[i][3][x2 & 0xff];
        xt3 = ((uint32_t)tables->part1_table3[i][0][(x3 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part1_table3[i][1][(x3 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part1_table3[i][2][(x3 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part1_table3[i][3][x3 & 0xff];

        /* part4-1 */
        xt1_1 = (xt1 >> 24) & 0xff;
        xt1_2 = (xt1 >> 16) & 0xff;
        xt1_3 = (xt1 >> 8) & 0xff;
        xt1_4 = xt1 & 0xff;

        xt2_1 = (xt2 >> 24) & 0xff;
        xt2_2 = (xt2 >> 16) & 0xff;
        xt2_3 = (xt2 >> 8) & 0xff;
        xt2_4 = xt2 & 0xff;

        xt3_1 = (xt3 >> 24) & 0xff;
        xt3_2 = (xt3 >> 16) & 0xff;
        xt3_3 = (xt3 >> 8) & 0xff;
        xt3_4 = xt3 & 0xff;

        temp_part4_1 = ((uint32_t)tables->part4_1_table[i][0][(xt1_1 << 8) ^ xt2_1] << 24) ^
                       ((uint32_t)tables->part4_1_table[i][1][(xt1_2 << 8) ^ xt2_2] << 16) ^
                       ((uint32_t)tables->part4_1_table[i][2][(xt1_3 << 8) ^ xt2_3] << 8) ^
                       (uint32_t)tables->part4_1_table[i][3][(xt1_4 << 8) ^ xt2_4];
        x4 = ((uint32_t)tables->part4_1_table[i][0][(((temp_part4_1 >> 24) & 0xff) << 8) ^ xt3_1] << 24) ^
             ((uint32_t)tables->part4_1_table[i][1][(((temp_part4_1 >> 16) & 0xff) << 8) ^ xt3_2] << 16) ^
             ((uint32_t)tables->part4_1_table[i][2][(((temp_part4_1 >> 8) & 0xff) << 8) ^ xt3_3] << 8) ^
             (uint32_t)tables->part4_1_table[i][3][((temp_part4_1 & 0xff) << 8) ^ xt3_4];

        /* part2 */
        x4_1 = (x4 >> 24) & 0xff;
        x4_2 = (x4 >> 16) & 0xff;
        x4_3 = (x4 >> 8) & 0xff;
        x4_4 = x4 & 0xff;

        part2_temp = ((uint32_t)tables->part2_table_temp[i][0][x4_1] << 24) ^
                     ((uint32_t)tables->part2_table_temp[i][1][x4_2] << 16) ^
                     ((uint32_t)tables->part2_table_temp[i][2][x4_3] << 8) ^
                     (uint32_t)tables->part2_table_temp[i][3][x4_4];
        part2_temp = MatMulNumM32(L_matrix, part2_temp);

        part2_temp_1 = (part2_temp >> 24) & 0xff;
        part2_temp_2 = (part2_temp >> 16) & 0xff;
        part2_temp_3 = (part2_temp >> 8) & 0xff;
        part2_temp_4 = part2_temp & 0xff;

        res_part2_1 = tables->part2_table[i][0][part2_temp_1];
        res_part2_2 = tables->part2_table[i][1][part2_temp_2];
        res_part2_3 = tables->part2_table[i][2][part2_temp_3];
        res_part2_4 = tables->part2_table[i][3][part2_temp_4];

        res_part2_1_1 = (res_part2_1 >> 24) & 0xff;
        res_part2_1_2 = (res_part2_1 >> 16) & 0xff;
        res_part2_1_3 = (res_part2_1 >> 8) & 0xff;
        res_part2_1_4 = res_part2_1 & 0xff;

        res_part2_2_1 = (res_part2_2 >> 24) & 0xff;
        res_part2_2_2 = (res_part2_2 >> 16) & 0xff;
        res_part2_2_3 = (res_part2_2 >> 8) & 0xff;
        res_part2_2_4 = res_part2_2 & 0xff;

        res_part2_3_1 = (res_part2_3 >> 24) & 0xff;
        res_part2_3_2 = (res_part2_3 >> 16) & 0xff;
        res_part2_3_3 = (res_part2_3 >> 8) & 0xff;
        res_part2_3_4 = res_part2_3 & 0xff;

        res_part2_4_1 = (res_part2_4 >> 24) & 0xff;
        res_part2_4_2 = (res_part2_4 >> 16) & 0xff;
        res_part2_4_3 = (res_part2_4 >> 8) & 0xff;
        res_part2_4_4 = res_part2_4 & 0xff;

        temp_part4_2_1 = ((uint32_t)tables->part4_2_table[i][0][(res_part2_1_1 << 8) ^ res_part2_2_1] << 24) ^
                         ((uint32_t)tables->part4_2_table[i][1][(res_part2_1_2 << 8) ^ res_part2_2_2] << 16) ^
                         ((uint32_t)tables->part4_2_table[i][2][(res_part2_1_3 << 8) ^ res_part2_2_3] << 8) ^
                         (uint32_t)tables->part4_2_table[i][3][(res_part2_1_4 << 8) ^ res_part2_2_4];
        temp_part4_2_2 = ((uint32_t)tables->part4_2_table[i][0][(((temp_part4_2_1 >> 24) & 0xff) << 8) ^ res_part2_3_1] << 24) ^
                         ((uint32_t)tables->part4_2_table[i][1][(((temp_part4_2_1 >> 16) & 0xff) << 8) ^ res_part2_3_2] << 16) ^
                         ((uint32_t)tables->part4_2_table[i][2][(((temp_part4_2_1 >> 8) & 0xff) << 8) ^ res_part2_3_3] << 8) ^
                         (uint32_t)tables->part4_2_table[i][3][((temp_part4_2_1 & 0xff) << 8) ^ res_part2_3_4];
        x4 = ((uint32_t)tables->part4_2_table[i][0][(((temp_part4_2_2 >> 24) & 0xff) << 8) ^ res_part2_4_1] << 24) ^
             ((uint32_t)tables->part4_2_table[i][1][(((temp_part4_2_2 >> 16) & 0xff) << 8) ^ res_part2_4_2] << 16) ^
             ((uint32_t)tables->part4_2_table[i][2][(((temp_part4_2_2 >> 8) & 0xff) << 8) ^ res_part2_4_3] << 8) ^
             (uint32_t)tables->part4_2_table[i][3][((temp_part4_2_2 & 0xff) << 8) ^ res_part2_4_4];

        /* part3 */
        xt0 = ((uint32_t)tables->part3_table1[i][0][(x0 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part3_table1[i][1][(x0 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part3_table1[i][2][(x0 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part3_table1[i][3][x0 & 0xff];
        xt4 = ((uint32_t)tables->part3_table2[i][0][(x4 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part3_table2[i][1][(x4 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part3_table2[i][2][(x4 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part3_table2[i][3][x4 & 0xff];

        /* part4-3 */
        xt0_1 = (xt0 >> 24) & 0xff;
        xt0_2 = (xt0 >> 16) & 0xff;
        xt0_3 = (xt0 >> 8) & 0xff;
        xt0_4 = xt0 & 0xff;

        xt4_1 = (xt4 >> 24) & 0xff;
        xt4_2 = (xt4 >> 16) & 0xff;
        xt4_3 = (xt4 >> 8) & 0xff;
        xt4_4 = xt4 & 0xff;

        x4 = ((uint32_t)tables->part4_3_table[i][0][(xt0_1 << 8) ^ xt4_1] << 24) ^
             ((uint32_t)tables->part4_3_table[i][1][(xt0_2 << 8) ^ xt4_2] << 16) ^
             ((uint32_t)tables->part4_3_table[i][2][(xt0_3 << 8) ^ xt4_3] << 8) ^
             (uint32_t)tables->part4_3_table[i][3][(xt0_4 << 8) ^ xt4_4];

        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    /* 输出外部解码 */
    out0 = nonlinearU32(&tables->P_inv[35], x3);
    out1 = nonlinearU32(&tables->P_inv[34], x2);
    out2 = nonlinearU32(&tables->P_inv[33], x1);
    out3 = nonlinearU32(&tables->P_inv[32], x0);

    PUT32(out0, OUT);
    PUT32(out1, OUT + 4);
    PUT32(out2, OUT + 8);
    PUT32(out3, OUT + 12);
}
void Nonlinearwbsm4_decrypt(const unsigned char IN[16], unsigned char OUT[16], const WB_SM4_Tables* tables) {
    int i;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t xt0, xt1, xt2, xt3, xt4;
    uint8_t xt0_1, xt0_2, xt0_3, xt0_4, xt1_1, xt1_2, xt1_3, xt1_4;
    uint8_t xt2_1, xt2_2, xt2_3, xt2_4, xt3_1, xt3_2, xt3_3, xt3_4;
    uint8_t xt4_1, xt4_2, xt4_3, xt4_4, x4_1, x4_2, x4_3, x4_4;
    uint32_t temp_part4_1, part2_temp;
    uint8_t part2_temp_1, part2_temp_2, part2_temp_3, part2_temp_4;
    uint32_t res_part2_1, res_part2_2, res_part2_3, res_part2_4;
    uint8_t res_part2_1_1, res_part2_1_2, res_part2_1_3, res_part2_1_4;
    uint8_t res_part2_2_1, res_part2_2_2, res_part2_2_3, res_part2_2_4;
    uint8_t res_part2_3_1, res_part2_3_2, res_part2_3_3, res_part2_3_4;
    uint8_t res_part2_4_1, res_part2_4_2, res_part2_4_3, res_part2_4_4;
    uint32_t temp_part4_2_1, temp_part4_2_2;
    uint32_t out0, out1, out2, out3;

    /* 输入外部编码 */
    x0 = GET32(IN);
    x1 = GET32(IN + 4);
    x2 = GET32(IN + 8);
    x3 = GET32(IN + 12);

    x0 = nonlinearU32(&tables->P[35], x0);  /* P0 */
    x1 = nonlinearU32(&tables->P[34], x1);  /* P1 */
    x2 = nonlinearU32(&tables->P[33], x2);  /* P2 */
    x3 = nonlinearU32(&tables->P[32], x3);  /* P3 */

    /* 执行核心解密 */
    for (i = 31; i >= 0; i--) {
        /* part1 */
        xt1 = ((uint32_t)tables->part1_table3[i][0][(x1 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part1_table3[i][1][(x1 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part1_table3[i][2][(x1 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part1_table3[i][3][x1 & 0xff];
        xt2 = ((uint32_t)tables->part1_table2[i][0][(x2 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part1_table2[i][1][(x2 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part1_table2[i][2][(x2 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part1_table2[i][3][x2 & 0xff];
        xt3 = ((uint32_t)tables->part1_table1[i][0][(x3 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part1_table1[i][1][(x3 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part1_table1[i][2][(x3 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part1_table1[i][3][x3 & 0xff];

        /* part4-1 */
        xt1_1 = (xt1 >> 24) & 0xff;
        xt1_2 = (xt1 >> 16) & 0xff;
        xt1_3 = (xt1 >> 8) & 0xff;
        xt1_4 = xt1 & 0xff;

        xt2_1 = (xt2 >> 24) & 0xff;
        xt2_2 = (xt2 >> 16) & 0xff;
        xt2_3 = (xt2 >> 8) & 0xff;
        xt2_4 = xt2 & 0xff;

        xt3_1 = (xt3 >> 24) & 0xff;
        xt3_2 = (xt3 >> 16) & 0xff;
        xt3_3 = (xt3 >> 8) & 0xff;
        xt3_4 = xt3 & 0xff;

        temp_part4_1 = ((uint32_t)tables->part4_1_table[i][0][(xt3_1 << 8) ^ xt2_1] << 24) ^
                       ((uint32_t)tables->part4_1_table[i][1][(xt3_2 << 8) ^ xt2_2] << 16) ^
                       ((uint32_t)tables->part4_1_table[i][2][(xt3_3 << 8) ^ xt2_3] << 8) ^
                       (uint32_t)tables->part4_1_table[i][3][(xt3_4 << 8) ^ xt2_4];
        x4 = ((uint32_t)tables->part4_1_table[i][0][(((temp_part4_1 >> 24) & 0xff) << 8) ^ xt1_1] << 24) ^
             ((uint32_t)tables->part4_1_table[i][1][(((temp_part4_1 >> 16) & 0xff) << 8) ^ xt1_2] << 16) ^
             ((uint32_t)tables->part4_1_table[i][2][(((temp_part4_1 >> 8) & 0xff) << 8) ^ xt1_3] << 8) ^
             (uint32_t)tables->part4_1_table[i][3][((temp_part4_1 & 0xff) << 8) ^ xt1_4];

        /* part2 */
        x4_1 = (x4 >> 24) & 0xff;
        x4_2 = (x4 >> 16) & 0xff;
        x4_3 = (x4 >> 8) & 0xff;
        x4_4 = x4 & 0xff;

        part2_temp = ((uint32_t)tables->part2_table_temp[i][0][x4_1] << 24) ^
                     ((uint32_t)tables->part2_table_temp[i][1][x4_2] << 16) ^
                     ((uint32_t)tables->part2_table_temp[i][2][x4_3] << 8) ^
                     (uint32_t)tables->part2_table_temp[i][3][x4_4];
        part2_temp = MatMulNumM32(L_matrix, part2_temp);

        part2_temp_1 = (part2_temp >> 24) & 0xff;
        part2_temp_2 = (part2_temp >> 16) & 0xff;
        part2_temp_3 = (part2_temp >> 8) & 0xff;
        part2_temp_4 = part2_temp & 0xff;

        res_part2_1 = tables->part2_table[i][0][part2_temp_1];
        res_part2_2 = tables->part2_table[i][1][part2_temp_2];
        res_part2_3 = tables->part2_table[i][2][part2_temp_3];
        res_part2_4 = tables->part2_table[i][3][part2_temp_4];

        /* part4-2 */
        res_part2_1_1 = (res_part2_1 >> 24) & 0xff;
        res_part2_1_2 = (res_part2_1 >> 16) & 0xff;
        res_part2_1_3 = (res_part2_1 >> 8) & 0xff;
        res_part2_1_4 = res_part2_1 & 0xff;

        res_part2_2_1 = (res_part2_2 >> 24) & 0xff;
        res_part2_2_2 = (res_part2_2 >> 16) & 0xff;
        res_part2_2_3 = (res_part2_2 >> 8) & 0xff;
        res_part2_2_4 = res_part2_2 & 0xff;

        res_part2_3_1 = (res_part2_3 >> 24) & 0xff;
        res_part2_3_2 = (res_part2_3 >> 16) & 0xff;
        res_part2_3_3 = (res_part2_3 >> 8) & 0xff;
        res_part2_3_4 = res_part2_3 & 0xff;

        res_part2_4_1 = (res_part2_4 >> 24) & 0xff;
        res_part2_4_2 = (res_part2_4 >> 16) & 0xff;
        res_part2_4_3 = (res_part2_4 >> 8) & 0xff;
        res_part2_4_4 = res_part2_4 & 0xff;

        temp_part4_2_1 = ((uint32_t)tables->part4_2_table[i][0][(res_part2_1_1 << 8) ^ res_part2_2_1] << 24) ^
                         ((uint32_t)tables->part4_2_table[i][1][(res_part2_1_2 << 8) ^ res_part2_2_2] << 16) ^
                         ((uint32_t)tables->part4_2_table[i][2][(res_part2_1_3 << 8) ^ res_part2_2_3] << 8) ^
                         (uint32_t)tables->part4_2_table[i][3][(res_part2_1_4 << 8) ^ res_part2_2_4];
        temp_part4_2_2 = ((uint32_t)tables->part4_2_table[i][0][(((temp_part4_2_1 >> 24) & 0xff) << 8) ^ res_part2_3_1] << 24) ^
                         ((uint32_t)tables->part4_2_table[i][1][(((temp_part4_2_1 >> 16) & 0xff) << 8) ^ res_part2_3_2] << 16) ^
                         ((uint32_t)tables->part4_2_table[i][2][(((temp_part4_2_1 >> 8) & 0xff) << 8) ^ res_part2_3_3] << 8) ^
                         (uint32_t)tables->part4_2_table[i][3][((temp_part4_2_1 & 0xff) << 8) ^ res_part2_3_4];
        x4 = ((uint32_t)tables->part4_2_table[i][0][(((temp_part4_2_2 >> 24) & 0xff) << 8) ^ res_part2_4_1] << 24) ^
             ((uint32_t)tables->part4_2_table[i][1][(((temp_part4_2_2 >> 16) & 0xff) << 8) ^ res_part2_4_2] << 16) ^
             ((uint32_t)tables->part4_2_table[i][2][(((temp_part4_2_2 >> 8) & 0xff) << 8) ^ res_part2_4_3] << 8) ^
             (uint32_t)tables->part4_2_table[i][3][((temp_part4_2_2 & 0xff) << 8) ^ res_part2_4_4];

        /* part3 */
        xt0 = ((uint32_t)tables->part3_table1_dec[i][0][(x0 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part3_table1_dec[i][1][(x0 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part3_table1_dec[i][2][(x0 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part3_table1_dec[i][3][x0 & 0xff];
        xt4 = ((uint32_t)tables->part3_table2[i][0][(x4 >> 24) & 0xff] << 24) ^
              ((uint32_t)tables->part3_table2[i][1][(x4 >> 16) & 0xff] << 16) ^
              ((uint32_t)tables->part3_table2[i][2][(x4 >> 8) & 0xff] << 8) ^
              (uint32_t)tables->part3_table2[i][3][x4 & 0xff];

        /* part4-3 */
        xt0_1 = (xt0 >> 24) & 0xff;
        xt0_2 = (xt0 >> 16) & 0xff;
        xt0_3 = (xt0 >> 8) & 0xff;
        xt0_4 = xt0 & 0xff;

        xt4_1 = (xt4 >> 24) & 0xff;
        xt4_2 = (xt4 >> 16) & 0xff;
        xt4_3 = (xt4 >> 8) & 0xff;
        xt4_4 = xt4 & 0xff;

        x4 = ((uint32_t)tables->part4_3_table_dec[i][0][(xt0_1 << 8) ^ xt4_1] << 24) ^
             ((uint32_t)tables->part4_3_table_dec[i][1][(xt0_2 << 8) ^ xt4_2] << 16) ^
             ((uint32_t)tables->part4_3_table_dec[i][2][(xt0_3 << 8) ^ xt4_3] << 8) ^
             (uint32_t)tables->part4_3_table_dec[i][3][(xt0_4 << 8) ^ xt4_4];

        x0 = x1;
        x1 = x2;
        x2 = x3;
        x3 = x4;
    }

    /* 输出外部解码（解密方向） */
    out0 = nonlinearU32(&tables->P_inv[0], x3);
    out1 = nonlinearU32(&tables->P_inv[1], x2);
    out2 = nonlinearU32(&tables->P_inv[2], x1);
    out3 = nonlinearU32(&tables->P_inv[3], x0);

    PUT32(out0, OUT);
    PUT32(out1, OUT + 4);
    PUT32(out2, OUT + 8);
    PUT32(out3, OUT + 12);
}


void Nonlinearwbsm4_generate_tables(const uint8_t key[16], WB_SM4_Tables* tables) {
    SM4_KEY sm4_key;
    size_t total_size = 0;
    uint8_t* current = NULL; 
    ossl_sm4_set_key1(key, &sm4_key);
    total_size += 3 * 32 * sizeof(uint8_t[4][256]); 
    total_size += 32 * sizeof(uint32_t[4][256]) + 32 * sizeof(uint8_t[4][256]);
    total_size += 3 * 32 * sizeof(uint8_t[4][256]); 
    total_size += 4 * 32 * sizeof(uint8_t[4][65536]); 
    total_size += 36 * sizeof(Nonlinear32) * 2;
    /*一次性分配内存*/
    tables->memory_block = OPENSSL_malloc(total_size);
    if (!tables->memory_block) {
        memset(tables, 0, sizeof(WB_SM4_Tables));
        return; 
    }
    current = (uint8_t*)tables->memory_block;

    /* Part1 Tables*/
    tables->part1_table1 = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part1_table1);
    tables->part1_table2 = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part1_table2);
    tables->part1_table3 = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part1_table3);

    /* Part2 Tables*/
    tables->part2_table = (uint32_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part2_table);
    tables->part2_table_temp = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part2_table_temp);

    /* Part3 Tables*/
    tables->part3_table1 = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part3_table1);
    tables->part3_table1_dec = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part3_table1_dec);
    tables->part3_table2 = (uint8_t(*)[4][256])current;
    current += 32 * sizeof(*tables->part3_table2);

    /* Part4 Tables*/
    tables->part4_1_table = (uint8_t(*)[4][65536])current;
    current += 32 * sizeof(*tables->part4_1_table);
    tables->part4_2_table = (uint8_t(*)[4][65536])current;
    current += 32 * sizeof(*tables->part4_2_table);
    tables->part4_3_table = (uint8_t(*)[4][65536])current;
    current += 32 * sizeof(*tables->part4_3_table);
    tables->part4_3_table_dec = (uint8_t(*)[4][65536])current;
    current += 32 * sizeof(*tables->part4_3_table_dec);

    /*P盒  */
    tables->P = (Nonlinear32*)current;
    current += 36 * sizeof(*tables->P);
    tables->P_inv = (Nonlinear32*)current;
    current += 36 * sizeof(*tables->P_inv);
    wbsm4_gen_init(tables);
    wbsm4_gen_part1(tables);
    wbsm4_gen_part2(&sm4_key, tables);
    wbsm4_gen_part3(tables);
    wbsm4_gen_part4_1(tables);
    wbsm4_gen_part4_2(tables);
    wbsm4_gen_part4_3(tables);
}
void Nonlinearwbsm4_free_tables(WB_SM4_Tables* tables) {

    OPENSSL_free(tables->memory_block);
    memset(tables, 0, sizeof(WB_SM4_Tables));
}
