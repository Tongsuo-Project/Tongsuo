/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2024 Nexus-TYF. All Rights Reserved.
 * Ported from Nexus-TYF/Bai-Wu-White-box-SM4.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/e_os2.h>
#include <internal/endian.h>
#include "crypto/wbsm4.h"
#include "WBMatrix.h"

#define GET32(pc) (             \
    ((uint32_t)(pc)[0] << 24) ^ \
    ((uint32_t)(pc)[1] << 16) ^ \
    ((uint32_t)(pc)[2] << 8) ^  \
    ((uint32_t)(pc)[3]))

#define PUT32(st, ct)                \
    (ct)[0] = (uint8_t)((st) >> 24); \
    (ct)[1] = (uint8_t)((st) >> 16); \
    (ct)[2] = (uint8_t)((st) >> 8);  \
    (ct)[3] = (uint8_t)(st)

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

static M32 L_matrix = {
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

void wbsm4_baiwu_set_key(const uint8_t *key, wbsm4_baiwu_key *wbsm4_key)
{
    DECLARE_IS_ENDIAN;

    *wbsm4_key = *(wbsm4_baiwu_key *)key;
    if (IS_LITTLE_ENDIAN)
        return;

    uint8_t *p = (uint8_t *)wbsm4_key;
    uint8_t *end = p + sizeof(wbsm4_baiwu_key);
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

void wbsm4_baiwu_export_key(const wbsm4_baiwu_key *wbsm4_key, uint8_t *key)
{
    DECLARE_IS_ENDIAN;

    wbsm4_baiwu_key *out = (wbsm4_baiwu_key *)key;
    *out = *wbsm4_key;
    if (IS_LITTLE_ENDIAN)
        return;

    uint8_t *p = (uint8_t *)out;
    uint8_t *end = p + sizeof(wbsm4_baiwu_key);
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

void wbsm4_baiwu_gen(const uint8_t *sm4_key, wbsm4_baiwu_key *wbsm4_key)
{
    int i, j, r, x, y;
    uint8_t temp_u8_x, temp_u8_y, temp_u8;
    uint32_t temp_u32;
    uint32_t TD0_u32[6], TD1_u32[6], TD2_u32[3], TR_u32[4], Lc[36];
    uint32_t Ec0[32], Ec1[32];
    M32 L[36];
    M32 L_inv[36];
    M8 E[32][2][4];
    M8 E_inv[32][2][4];
    M32 Ei_inv[32][2];
    M32 M[32][2][3];
    M32 C[32];
    M32 LL;

    uint32_t SK[32];
    wbsm4_sm4_setkey(SK, sm4_key);

    for (r = 0; r < 36; r++) {
        genMatpairM32(&L[r], &L_inv[r]);
        Lc[r] = cus_random();
    }

    for (r = 0; r < 32; r++) {
        for (j = 0; j < 4; j++) {
            genMatpairM8(&E[r][0][j], &E_inv[r][0][j]);
            genMatpairM8(&E[r][1][j], &E_inv[r][1][j]);
        }

        MatrixcomM8to32(E_inv[r][0][0], E_inv[r][0][1], E_inv[r][0][2],
                        E_inv[r][0][3], &Ei_inv[r][0]);
        MatrixcomM8to32(E_inv[r][1][0], E_inv[r][1][1], E_inv[r][1][2],
                        E_inv[r][1][3], &Ei_inv[r][1]);

        MatMulMatM32(Ei_inv[r][0], L_inv[r + 1], &M[r][0][0]);
        MatMulMatM32(Ei_inv[r][0], L_inv[r + 2], &M[r][0][1]);
        MatMulMatM32(Ei_inv[r][0], L_inv[r + 3], &M[r][0][2]);

        MatMulMatM32(Ei_inv[r][1], L_inv[r + 1], &M[r][1][0]);
        MatMulMatM32(Ei_inv[r][1], L_inv[r + 2], &M[r][1][1]);
        MatMulMatM32(Ei_inv[r][1], L_inv[r + 3], &M[r][1][2]);

        MatMulMatM32(L[r + 4], L_inv[r], &C[r]);
    }

    for (r = 0; r < 32; r++)
    {
        MatMulMatM32(L[r + 4], L_matrix, &LL);

        for (i = 0; i < 6; i++) {
            TD0_u32[i] = cus_random();
            TD1_u32[i] = cus_random();
        }
        for (i = 0; i < 4; i++) {
            TR_u32[i] = cus_random();
        }
        for (i = 0; i < 3; i++) {
            TD2_u32[i] = cus_random();
        }
        Ec0[r] = TD0_u32[0] ^ TD0_u32[1] ^ TD0_u32[2] ^ TD0_u32[3] ^
                 TD0_u32[4] ^ TD0_u32[5];
        Ec1[r] = TD1_u32[0] ^ TD1_u32[1] ^ TD1_u32[2] ^ TD1_u32[3] ^
                 TD1_u32[4] ^ TD1_u32[5];

        for (x = 0; x < 256; x++) {
            for (j = 0; j < 4; j++) {
                temp_u8 = x ^ ((Lc[r] >> (24 - j * 8)) & 0xff);
                temp_u32 = temp_u8 << (24 - j * 8);
                wbsm4_key->TD[r][0][j][x] = MatMulNumM32(C[r], temp_u32);
            }
            for (j = 0; j < 3; j++) {
                wbsm4_key->TD[r][0][j][x] ^= TD2_u32[j];
            }
            wbsm4_key->TD[r][0][3][x] ^= Lc[r + 4] ^ TD2_u32[0] ^ TD2_u32[1] ^
                                         TD2_u32[2] ^ TR_u32[0] ^ TR_u32[1] ^
                                         TR_u32[2] ^ TR_u32[3];

            for (i = 1; i < 4; i++) {
                temp_u8 = x ^ ((Lc[r + i] >> 24) & 0xff);
                temp_u32 = temp_u8 << 24;
                wbsm4_key->TD[r][i][0][x] = MatMulNumM32(M[r][0][i - 1],
                                                         temp_u32);
                temp_u8 = x ^ ((Lc[r + i] >> 16) & 0xff);
                temp_u32 = temp_u8 << 16;
                wbsm4_key->TD[r][i][1][x] = MatMulNumM32(M[r][0][i - 1],
                                            temp_u32);

                temp_u8 = x ^ ((Lc[r + i] >> 8) & 0xff);
                temp_u32 = temp_u8 << 8;
                wbsm4_key->TD[r][i][2][x] = MatMulNumM32(M[r][1][i - 1],
                                                         temp_u32);
                temp_u8 = x ^ (Lc[r + i] & 0xff);
                temp_u32 = temp_u8;
                wbsm4_key->TD[r][i][3][x] = MatMulNumM32(M[r][1][i - 1],
                                                         temp_u32);
            }

            j = 0;
            for (i = 1; i < 4; i++) {
                wbsm4_key->TD[r][i][0][x] ^= TD0_u32[j++];
                wbsm4_key->TD[r][i][1][x] ^= TD0_u32[j++];
            }

            j = 0;
            for (i = 1; i < 4; i++) {
                wbsm4_key->TD[r][i][2][x] ^= TD1_u32[j++];
                wbsm4_key->TD[r][i][3][x] ^= TD1_u32[j++];
            }
        }

        for (x = 0; x < 256; x++) {
            for (y = 0; y < 256; y++) {
                for (j = 0; j < 4; j++) {
                    temp_u8_x = x ^ ((Ec0[r] >> (24 - j * 8)) & 0xff);
                    temp_u8_x = MatMulNumM8(E[r][0][j], temp_u8_x);

                    temp_u8_y = y ^ ((Ec1[r] >> (24 - j * 8)) & 0xff);
                    temp_u8_y = MatMulNumM8(E[r][1][j], temp_u8_y);
                    temp_u8 = SBOX[temp_u8_x ^ temp_u8_y ^
                              ((SK[r] >> (24 - j * 8)) & 0xff)];
                    temp_u32 = temp_u8 << (24 - j * 8);
                    wbsm4_key->TR[r][j][x][y] = MatMulNumM32(LL, temp_u32);
                    wbsm4_key->TR[r][j][x][y] ^= TR_u32[j];
                }
            }
        }
    }

    /* external encoding */
    for (i = 0; i < 4; i++) {
        wbsm4_key->SE[i].Mat = L[i];
        wbsm4_key->SE[i].Vec.V = Lc[i];

        wbsm4_key->FE[i].Mat = L_inv[35 - i];
        wbsm4_key->FE[i].Vec.V = MatMulNumM32(L_inv[35 - i], Lc[35 - i]);
    }
}

void wbsm4_baiwu_encrypt(const unsigned char IN[], unsigned char OUT[],
                         const wbsm4_baiwu_key *wbsm4_key)
{
    int r, i, j;
    uint32_t x[36];
    uint32_t s0, s1;

    x[0] = GET32(IN);
    x[1] = GET32(IN + 4);
    x[2] = GET32(IN + 8);
    x[3] = GET32(IN + 12);
    x[0] = affineU32(wbsm4_key->SE[0], x[0]);
    x[1] = affineU32(wbsm4_key->SE[1], x[1]);
    x[2] = affineU32(wbsm4_key->SE[2], x[2]);
    x[3] = affineU32(wbsm4_key->SE[3], x[3]);

    for (r = 0; r < 32; r++) {
        x[r + 4] = 0;
        s0 = 0;
        s1 = 0;

        for (i = 1; i < 4; i++) {
            s0 ^= wbsm4_key->TD[r][i][0][(x[r + i] >> 24) & 0xff];
            s0 ^= wbsm4_key->TD[r][i][1][(x[r + i] >> 16) & 0xff];
            s1 ^= wbsm4_key->TD[r][i][2][(x[r + i] >> 8) & 0xff];
            s1 ^= wbsm4_key->TD[r][i][3][x[r + i] & 0xff];
        }
        for (j = 0; j < 4; j++) {
            x[r + 4] ^= wbsm4_key->TR[r][j][(s0 >> (24 - j * 8)) &
                        0xff][(s1 >> (24 - j * 8)) & 0xff];
            x[r + 4] ^= wbsm4_key->TD[r][0][j][(x[r] >> (24 - j * 8)) & 0xff];
        }
    }

    x[35] = affineU32(wbsm4_key->FE[0], x[35]);
    x[34] = affineU32(wbsm4_key->FE[1], x[34]);
    x[33] = affineU32(wbsm4_key->FE[2], x[33]);
    x[32] = affineU32(wbsm4_key->FE[3], x[32]);
    PUT32(x[35], OUT);
    PUT32(x[34], OUT + 4);
    PUT32(x[33], OUT + 8);
    PUT32(x[32], OUT + 12);
}
