/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 * Copyright 2024 Nexus-TYF. All Rights Reserved.
 * Ported from Nexus-TYF/WBMatrix.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <inttypes.h>
#include "WBMatrix.h"

/* 8bit internal xor table */
static int xor [] = {
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0,
    1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0,
    1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0,
    1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0,
    1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0,
    1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1,
    0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0,
    1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0,
    1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1,
    0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1,
    0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0,
    1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0
};

/* 8bit Hamming weight table */
static int HW[] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2,
    3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2,
    3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4,
    5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2,
    3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3,
    4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4,
    5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3,
    4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2,
    3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4,
    5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4, 4, 5, 3,
    4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5,
    6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4,
    5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

static uint8_t idM4[4] = {0x08, 0x04, 0x02, 0x01};
static uint8_t idM8[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
static uint16_t idM16[16] = {0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400,
                             0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4,
                             0x2, 0x1};
static uint32_t idM32[32] = {0x80000000, 0x40000000, 0x20000000, 0x10000000,
                             0x8000000, 0x4000000, 0x2000000, 0x1000000,
                             0x800000, 0x400000, 0x200000, 0x100000, 0x80000,
                             0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x2000,
                             0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40,
                             0x20, 0x10, 0x8, 0x4, 0x2, 0x1};
static uint64_t idM64[64] = {0x8000000000000000, 0x4000000000000000,
                             0x2000000000000000, 0x1000000000000000,
                             0x800000000000000, 0x400000000000000,
                             0x200000000000000, 0x100000000000000,
                             0x80000000000000, 0x40000000000000,
                             0x20000000000000, 0x10000000000000,
                             0x8000000000000, 0x4000000000000, 0x2000000000000,
                             0x1000000000000, 0x800000000000, 0x400000000000,
                             0x200000000000, 0x100000000000, 0x80000000000,
                             0x40000000000, 0x20000000000, 0x10000000000,
                             0x8000000000, 0x4000000000, 0x2000000000,
                             0x1000000000, 0x800000000, 0x400000000,
                             0x200000000, 0x100000000, 0x80000000, 0x40000000,
                             0x20000000, 0x10000000, 0x8000000, 0x4000000,
                             0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000,
                             0x100000, 0x80000, 0x40000, 0x20000, 0x10000,
                             0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400,
                             0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4,
                             0x2, 0x1};

void initM4(M4 *Mat) /* initial Matrix 4*4 */
{
    int i;
    for (i = 0; i < 4; i++) {
        (*Mat).M[i] = 0;
    }
}
void initM8(M8 *Mat) /* initial Matrix 8*8 */
{
    int i;
    for (i = 0; i < 8; i++) {
        (*Mat).M[i] = 0;
    }
}
void initM16(M16 *Mat) /* initial Matrix 16*16 */
{
    int i;
    for (i = 0; i < 16; i++) {
        (*Mat).M[i] = 0;
    }
}
void initM32(M32 *Mat) /* initial Matrix 32*32 */
{
    int i;
    for (i = 0; i < 32; i++) {
        (*Mat).M[i] = 0;
    }
}
void initM64(M64 *Mat) /* initial Matrix 64*64 */
{
    int i;
    for (i = 0; i < 64; i++) {
        (*Mat).M[i] = 0;
    }
}
void initM128(M128 *Mat) /* initial Matrix 128*128 */
{
    int i;
    for (i = 0; i < 128; i++) {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = 0;
    }
}
void initM256(M256 *Mat) /* initial Matrix 256*256 */
{
    int i;
    for (i = 0; i < 256; i++) {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = 0;
        (*Mat).M[i][2] = 0;
        (*Mat).M[i][3] = 0;
    }
}
void initV4(V4 *Vec) /* initial Vector 4*1 */
{
    (*Vec).V = 0;
}
void initV8(V8 *Vec) /* initial Vector 8*1 */
{
    (*Vec).V = 0;
}
void initV16(V16 *Vec) /* initial Vector 16*1 */
{
    (*Vec).V = 0;
}
void initV32(V32 *Vec) /* initial Vector 32*1 */
{
    (*Vec).V = 0;
}
void initV64(V64 *Vec) /* initial Vector 64*1 */
{
    (*Vec).V = 0;
}
void initV128(V128 *Vec) /* initial Vector 128*1 */
{
    (*Vec).V[0] = 0;
    (*Vec).V[1] = 0;
}
void initV256(V256 *Vec) /* initial Vector 256*1 */
{
    (*Vec).V[0] = 0;
    (*Vec).V[1] = 0;
    (*Vec).V[2] = 0;
    (*Vec).V[3] = 0;
}
void randM4(M4 *Mat) /* randomize Matrix 4*4 */
{
    int i;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 4; i++) {
        (*Mat).M[i] = cus_random() & 0x0f;
    }
}
void randM8(M8 *Mat) /* randomize Matrix 8*8 */
{
    int i;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 8; i++) {
        (*Mat).M[i] = cus_random();
    }
}
void randM16(M16 *Mat) /* randomize Matrix 16*16 */
{
    int i;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 16; i++) {
        (*Mat).M[i] = cus_random();
    }
}
void randM32(M32 *Mat) /* randomize Matrix 32*32 */
{
    int i;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 32; i++) {
        (*Mat).M[i] = cus_random();
    }
}
void randM64(M64 *Mat) /* randomize Matrix 64*64 */
{
    int i;
    uint32_t *m;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 64; i++) {
        m = (uint32_t *)&((*Mat).M[i]);
        *(m + 1) = cus_random();
        *m = cus_random();
    }
}
void randM128(M128 *Mat) /* randomize Matrix 128*128 */
{
    int i;
    uint32_t *m;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 128; i++) {
        m = (uint32_t *)&((*Mat).M[i][0]);
        *(m + 1) = cus_random();
        *m = cus_random();
        m = (uint32_t *)&((*Mat).M[i][1]);
        *(m + 1) = cus_random();
        *m = cus_random();
    }
}
void randM256(M256 *Mat) /* randomize Matrix 256*256 */
{
    int i;
    uint32_t *m;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    for (i = 0; i < 256; i++) {
        m = (uint32_t *)&((*Mat).M[i][0]);
        *(m + 1) = cus_random();
        *m = cus_random();
        m = (uint32_t *)&((*Mat).M[i][1]);
        *(m + 1) = cus_random();
        *m = cus_random();
        m = (uint32_t *)&((*Mat).M[i][2]);
        *(m + 1) = cus_random();
        *m = cus_random();
        m = (uint32_t *)&((*Mat).M[i][3]);
        *(m + 1) = cus_random();
        *m = cus_random();
    }
}
void identityM4(M4 *Mat) /* identity matrix 4*4 */
{
    int i;
    for (i = 0; i < 4; i++) {
        (*Mat).M[i] = idM4[i];
    }
}
void identityM8(M8 *Mat) /* identity matrix 8*8 */
{
    int i;
    for (i = 0; i < 8; i++) {
        (*Mat).M[i] = idM8[i];
    }
}
void identityM16(M16 *Mat) /* identity matrix 16*16 */
{
    int i;
    for (i = 0; i < 16; i++) {
        (*Mat).M[i] = idM16[i];
    }
}
void identityM32(M32 *Mat) /* identity matrix 32*32 */
{
    int i;
    for (i = 0; i < 32; i++) {
        (*Mat).M[i] = idM32[i];
    }
}
void identityM64(M64 *Mat) /* identity matrix 64*64 */
{
    int i;
    for (i = 0; i < 64; i++) {
        (*Mat).M[i] = idM64[i];
    }
}
void identityM128(M128 *Mat) /* identity matrix 128*128 */
{
    int i;
    for (i = 0; i < 64; i++) {
        (*Mat).M[i][0] = idM64[i];
        (*Mat).M[i][1] = 0;
    }
    for (i = 64; i < 128; i++) {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = idM64[i - 64];
    }
}
void identityM256(M256 *Mat) /* identity matrix 256*256 */
{
    int i;
    for (i = 0; i < 64; i++) {
        (*Mat).M[i][0] = idM64[i];
        (*Mat).M[i][1] = 0;
        (*Mat).M[i][2] = 0;
        (*Mat).M[i][3] = 0;
    }
    for (i = 64; i < 128; i++) {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = idM64[i - 64];
        (*Mat).M[i][2] = 0;
        (*Mat).M[i][3] = 0;
    }
    for (i = 128; i < 192; i++) {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = 0;
        (*Mat).M[i][2] = idM64[i - 128];
        (*Mat).M[i][3] = 0;
    }
    for (i = 192; i < 256; i++) {
        (*Mat).M[i][0] = 0;
        (*Mat).M[i][1] = 0;
        (*Mat).M[i][2] = 0;
        (*Mat).M[i][3] = idM64[i - 192];
    }
}
void randV4(V4 *Vec) /* randomize Vector 4*1 */
{
    /* InitRandom((randseed++) ^ (unsigned int)time(NULL)); */
    (*Vec).V = cus_random() & 0x0f;
}
void randV8(V8 *Vec) /* randomize Vector 8*1 */
{
    /* InitRandom((randseed++) ^ (unsigned int)time(NULL)); */
    (*Vec).V = cus_random();
}
void randV16(V16 *Vec) /* randomize Vector 16*1 */
{
    /* InitRandom((randseed++) ^ (unsigned int)time(NULL)); */
    (*Vec).V = cus_random();
}
void randV32(V32 *Vec) /* randomize Vector 32*1 */
{
    /* InitRandom((randseed++) ^ (unsigned int)time(NULL)); */
    (*Vec).V = cus_random();
}
void randV64(V64 *Vec) /* randomize Vector 64*1 */
{
    uint32_t *v = (uint32_t *)&((*Vec).V);
    *(v + 1) = cus_random();
    *v = cus_random();
}
void randV128(V128 *Vec) /* randomize Vector 128*1 */
{
    uint32_t *v = (uint32_t *)&((*Vec).V[0]);
    /* InitRandom((randseed++) ^ (unsigned int)time(NULL)); */
    *(v + 1) = cus_random();
    *v = cus_random();
    v = (uint32_t *)&((*Vec).V[1]);
    *(v + 1) = cus_random();
    *v = cus_random();
}
void randV256(V256 *Vec) /* randomize Vector 256*1 */
{
    uint32_t *v = (uint32_t *)&((*Vec).V[0]);
    /* InitRandom((randseed++) ^ (unsigned int)time(NULL)); */
    *(v + 1) = cus_random();
    *v = cus_random();
    v = (uint32_t *)&((*Vec).V[1]);
    *(v + 1) = cus_random();
    *v = cus_random();
    v = (uint32_t *)&((*Vec).V[2]);
    *(v + 1) = cus_random();
    *v = cus_random();
    v = (uint32_t *)&((*Vec).V[3]);
    *(v + 1) = cus_random();
    *v = cus_random();
}
void printM4(M4 Mat) /* printf Matrix 4*4 */
{
    int i;
    for (i = 0; i < 4; i++) {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM8(M8 Mat) /* printf Matrix 8*8 */
{
    int i;
    for (i = 0; i < 8; i++) {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM16(M16 Mat) /* printf Matrix 16*16 */
{
    int i;
    for (i = 0; i < 16; i++) {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM32(M32 Mat) /* printf Matrix 32*32 */
{
    int i;
    for (i = 0; i < 32; i++) {
        printf("0x%x\n", Mat.M[i]);
    }
}
void printM64(M64 Mat) /* printf Matrix 64*64 */
{
    int i;
    for (i = 0; i < 64; i++) {
        printf("0x%" PRIx64 "\n", Mat.M[i]);
    }
}
void printM128(M128 Mat) /* printf Matrix 128*128 */
{
    int i;
    for (i = 0; i < 128; i++) {
        printf("0x%" PRIx64 " ", Mat.M[i][0]);
        printf("0x%" PRIx64 "\n", Mat.M[i][1]);
    }
}
void printM256(M256 Mat) /* printf Matrix 256*256 */
{
    int i;
    for (i = 0; i < 256; i++) {
        printf("0x%" PRIx64 " ", Mat.M[i][0]);
        printf("0x%" PRIx64 " ", Mat.M[i][1]);
        printf("0x%" PRIx64 " ", Mat.M[i][2]);
        printf("0x%" PRIx64 "\n", Mat.M[i][3]);
    }
}
void printV4(V4 Vec) /* printf Vector 4*1 */
{
    printf("0x%x\n", Vec.V);
}
void printV8(V8 Vec) /* printf Vector 8*1 */
{
    printf("0x%x\n", Vec.V);
}
void printV16(V16 Vec) /* printf Vector 16*1 */
{
    printf("0x%x\n", Vec.V);
}
void printV32(V32 Vec) /* printf Vector 32*1 */
{
    printf("0x%x\n", Vec.V);
}
void printV64(V64 Vec) /* printf Vector 64*1 */
{
    printf("0x%" PRIx64 "\n", Vec.V);
}
void printV128(V128 Vec) /* printf Vector 128*1 */
{
    printf("0x%" PRIx64 " ", Vec.V[0]);
    printf("0x%" PRIx64 "\n", Vec.V[1]);
}
void printV256(V256 Vec) /* printf Vector 256*1 */
{
    printf("0x%" PRIx64 " ", Vec.V[0]);
    printf("0x%" PRIx64 " ", Vec.V[1]);
    printf("0x%" PRIx64 " ", Vec.V[2]);
    printf("0x%" PRIx64 "\n", Vec.V[3]);
}
void copyM4(M4 Mat1, M4 *Mat2)
{
    int i;
    for (i = 0; i < 4; i++) {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM8(M8 Mat1, M8 *Mat2)
{
    int i;
    for (i = 0; i < 8; i++) {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM16(M16 Mat1, M16 *Mat2)
{
    int i;
    for (i = 0; i < 16; i++) {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM32(M32 Mat1, M32 *Mat2)
{
    int i;
    for (i = 0; i < 32; i++) {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM64(M64 Mat1, M64 *Mat2)
{
    int i;
    for (i = 0; i < 64; i++) {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
void copyM128(M128 Mat1, M128 *Mat2)
{
    int i;
    for (i = 0; i < 128; i++) {
        (*Mat2).M[i][0] = Mat1.M[i][0];
        (*Mat2).M[i][1] = Mat1.M[i][1];
    }
}
void copyM256(M256 Mat1, M256 *Mat2)
{
    int i;
    for (i = 0; i < 256; i++) {
        (*Mat2).M[i][0] = Mat1.M[i][0];
        (*Mat2).M[i][1] = Mat1.M[i][1];
        (*Mat2).M[i][2] = Mat1.M[i][2];
        (*Mat2).M[i][3] = Mat1.M[i][3];
    }
}
int isequalM4(M4 Mat1, M4 Mat2)
{
    int i;
    for (i = 0; i < 4; i++) {
        if (Mat1.M[i] != Mat2.M[i])
            return 0;
    }
    return 1;
}
int isequalM8(M8 Mat1, M8 Mat2)
{
    int i;
    for (i = 0; i < 8; i++) {
        if (Mat1.M[i] != Mat2.M[i])
            return 0;
    }
    return 1;
}
int isequalM16(M16 Mat1, M16 Mat2)
{
    int i;
    for (i = 0; i < 16; i++) {
        if (Mat1.M[i] != Mat2.M[i])
            return 0;
    }
    return 1;
}
int isequalM32(M32 Mat1, M32 Mat2)
{
    int i;
    for (i = 0; i < 32; i++) {
        if (Mat1.M[i] != Mat2.M[i])
            return 0;
    }
    return 1;
}
int isequalM64(M64 Mat1, M64 Mat2)
{
    int i;
    for (i = 0; i < 64; i++) {
        if (Mat1.M[i] != Mat2.M[i])
            return 0;
    }
    return 1;
}
int isequalM128(M128 Mat1, M128 Mat2)
{
    int i;
    for (i = 0; i < 128; i++) {
        if (Mat1.M[i][0] != Mat2.M[i][0])
            return 0;
        if (Mat1.M[i][1] != Mat2.M[i][1])
            return 0;
    }
    return 1;
}
int isequalM256(M256 Mat1, M256 Mat2)
{
    int i;
    for (i = 0; i < 256; i++) {
        if (Mat1.M[i][0] != Mat2.M[i][0])
            return 0;
        if (Mat1.M[i][1] != Mat2.M[i][1])
            return 0;
        if (Mat1.M[i][2] != Mat2.M[i][2])
            return 0;
        if (Mat1.M[i][3] != Mat2.M[i][3])
            return 0;
    }
    return 1;
}
int isequalV4(V4 Vec1, V4 Vec2)
{
    if (Vec1.V != Vec2.V)
        return 0;
    return 1;
}
int isequalV8(V8 Vec1, V8 Vec2)
{
    if (Vec1.V != Vec2.V)
        return 0;
    return 1;
}
int isequalV16(V16 Vec1, V16 Vec2)
{
    if (Vec1.V != Vec2.V)
        return 0;
    return 1;
}
int isequalV32(V32 Vec1, V32 Vec2)
{
    if (Vec1.V != Vec2.V)
        return 0;
    return 1;
}
int isequalV64(V64 Vec1, V64 Vec2)
{
    if (Vec1.V != Vec2.V)
        return 0;
    return 1;
}
int isequalV128(V128 Vec1, V128 Vec2)
{
    if (Vec1.V[0] != Vec2.V[0])
        return 0;
    if (Vec1.V[1] != Vec2.V[1])
        return 0;
    return 1;
}
int isequalV256(V256 Vec1, V256 Vec2)
{
    if (Vec1.V[0] != Vec2.V[0])
        return 0;
    if (Vec1.V[1] != Vec2.V[1])
        return 0;
    if (Vec1.V[1] != Vec2.V[1])
        return 0;
    if (Vec1.V[1] != Vec2.V[1])
        return 0;
    return 1;
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-3 */
int readbitM4(M4 Mat, int i, int j)
{
    if ((Mat.M[i] & idM4[j]) == idM4[j])
        return 1;
    else
        return 0;
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-7 */
int readbitM8(M8 Mat, int i, int j)
{
    if ((Mat.M[i] & idM8[j]) == idM8[j])
        return 1;
    else
        return 0;
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-15 */
int readbitM16(M16 Mat, int i, int j)
{
    if ((Mat.M[i] & idM16[j]) == idM16[j])
        return 1;
    else
        return 0;
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-31 */
int readbitM32(M32 Mat, int i, int j)
{
    if ((Mat.M[i] & idM32[j]) == idM32[j])
        return 1;
    else
        return 0;
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-63 */
int readbitM64(M64 Mat, int i, int j)
{
    if ((Mat.M[i] & idM64[j]) == idM64[j])
        return 1;
    else
        return 0;
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-127 */
int readbitM128(M128 Mat, int i, int j)
{
    if (j < 64) {
        if ((Mat.M[i][0] & idM64[j]) == idM64[j])
            return 1;
        else
            return 0;
    } else {
        if ((Mat.M[i][1] & idM64[j - 64]) == idM64[j - 64])
            return 1;
        else
            return 0;
    }
}
/* read one bit in a matrix, i in n rows, j in n columns, i,j: 0-255 */
int readbitM256(M256 Mat, int i, int j)
{
    if (j < 64) {
        if ((Mat.M[i][0] & idM64[j]) == idM64[j])
            return 1;
        else
            return 0;
    } else if (j < 128) {
        if ((Mat.M[i][1] & idM64[j - 64]) == idM64[j - 64])
            return 1;
        else
            return 0;
    } else if (j < 192) {
        if ((Mat.M[i][2] & idM64[j - 128]) == idM64[j - 128])
            return 1;
        else
            return 0;
    } else {
        if ((Mat.M[i][3] & idM64[j - 192]) == idM64[j - 192])
            return 1;
        else
            return 0;
    }
}
void flipbitM4(M4 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    (*Mat).M[i] ^= idM4[j];
}
void flipbitM8(M8 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    (*Mat).M[i] ^= idM8[j];
}
void flipbitM16(M16 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    (*Mat).M[i] ^= idM16[j];
}
void flipbitM32(M32 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    (*Mat).M[i] ^= idM32[j];
}
void flipbitM64(M64 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    (*Mat).M[i] ^= idM64[j];
}
void flipbitM128(M128 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    if (j < 64) {
        (*Mat).M[i][0] ^= idM64[j];
    } else {
        (*Mat).M[i][1] ^= idM64[j - 64];
    }
}
void flipbitM256(M256 *Mat, int i, int j) /* flip (i, j) bit in a matrix */
{
    if (j < 64) {
        (*Mat).M[i][0] ^= idM64[j];
    } else if (j < 128) {
        (*Mat).M[i][1] ^= idM64[j - 64];
    } else if (j < 192) {
        (*Mat).M[i][2] ^= idM64[j - 128];
    } else {
        (*Mat).M[i][3] ^= idM64[j - 192];
    }
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM4(M4 *Mat, int i, int j, int bit)
{
    if (readbitM4(*Mat, i, j) == bit)
        return;
    else
        flipbitM4(Mat, i, j);
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM8(M8 *Mat, int i, int j, int bit)
{
    if (readbitM8(*Mat, i, j) == bit)
        return;
    else
        flipbitM8(Mat, i, j);
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM16(M16 *Mat, int i, int j, int bit)
{
    if (readbitM16(*Mat, i, j) == bit)
        return;
    else
        flipbitM16(Mat, i, j);
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM32(M32 *Mat, int i, int j, int bit)
{
    if (readbitM32(*Mat, i, j) == bit)
        return;
    else
        flipbitM32(Mat, i, j);
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM64(M64 *Mat, int i, int j, int bit)
{
    if (readbitM64(*Mat, i, j) == bit)
        return;
    else
        flipbitM64(Mat, i, j);
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM128(M128 *Mat, int i, int j, int bit)
{
    if (readbitM128(*Mat, i, j) == bit)
        return;
    else
        flipbitM128(Mat, i, j);
}
/* set (i, j) bit in a matrix, bit = 0/1 */
void setbitM256(M256 *Mat, int i, int j, int bit)
{
    if (readbitM256(*Mat, i, j) == bit)
        return;
    else
        flipbitM256(Mat, i, j);
}
int isinvertM4(M4 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint8_t temp;
    int flag;
    for (i = 0; i < 4; i++) {
        if ((Mat.M[i] & idM4[i]) == idM4[i]) {
            for (j = i + 1; j < 4; j++) {
                if ((Mat.M[j] & idM4[i]) == idM4[i]) {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 4; j++) {
                if ((Mat.M[j] & idM4[i]) == idM4[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 4; k++) {
                if ((Mat.M[k] & idM4[i]) == idM4[i]) {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if (Mat.M[3] == idM4[3])
        return 1;
    else
        return 0;
}
int isinvertM8(M8 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint8_t temp;
    int flag;
    for (i = 0; i < 8; i++) {
        if ((Mat.M[i] & idM8[i]) == idM8[i]) {
            for (j = i + 1; j < 8; j++) {
                if ((Mat.M[j] & idM8[i]) == idM8[i]) {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 8; j++) {
                if ((Mat.M[j] & idM8[i]) == idM8[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 8; k++) {
                if ((Mat.M[k] & idM8[i]) == idM8[i]) {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if (Mat.M[7] == idM8[7])
        return 1;
    else
        return 0;
}
int isinvertM16(M16 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint16_t temp;
    int flag;
    for (i = 0; i < 16; i++) {
        if ((Mat.M[i] & idM16[i]) == idM16[i]) {
            for (j = i + 1; j < 16; j++) {
                if ((Mat.M[j] & idM16[i]) == idM16[i]) {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 16; j++) {
                if ((Mat.M[j] & idM16[i]) == idM16[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 16; k++) {
                if ((Mat.M[k] & idM16[i]) == idM16[i]) {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if (Mat.M[15] == idM16[15])
        return 1;
    else
        return 0;
}
int isinvertM32(M32 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint32_t temp;
    int flag;
    for (i = 0; i < 32; i++) {
        if ((Mat.M[i] & idM32[i]) == idM32[i]) {
            for (j = i + 1; j < 32; j++) {
                if ((Mat.M[j] & idM32[i]) == idM32[i]) {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 32; j++) {
                if ((Mat.M[j] & idM32[i]) == idM32[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 32; k++) {
                if ((Mat.M[k] & idM32[i]) == idM32[i]) {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if (Mat.M[31] == idM32[31])
        return 1;
    else
        return 0;
}
int isinvertM64(M64 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint64_t temp;
    int flag;
    for (i = 0; i < 64; i++) {
        if ((Mat.M[i] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 64; j++) {
                if ((Mat.M[j] & idM64[i]) == idM64[i]) {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 64; j++) {
                if ((Mat.M[j] & idM64[i]) == idM64[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 64; k++) {
                if ((Mat.M[k] & idM64[i]) == idM64[i]) {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if (Mat.M[63] == idM64[63])
        return 1;
    else
        return 0;
}
int isinvertM128(M128 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint64_t temp;
    int flag;
    for (i = 0; i < 64; i++) {
        if ((Mat.M[i][0] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    Mat.M[j][0] ^= Mat.M[i][0];
                    Mat.M[j][1] ^= Mat.M[i][1];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    temp = Mat.M[i][0];
                    Mat.M[i][0] = Mat.M[j][0];
                    Mat.M[j][0] = temp;

                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 128; k++) {
                if ((Mat.M[k][0] & idM64[i]) == idM64[i]) {
                    Mat.M[k][0] ^= Mat.M[i][0];
                    Mat.M[k][1] ^= Mat.M[i][1];
                }
            }
        }
    }
    for (i = 64; i < 128; i++) {
        if ((Mat.M[i][1] & idM64[i - 64]) == idM64[i - 64]) {
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[j][1] ^= Mat.M[i][1];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;
                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 128; k++) {
                if ((Mat.M[k][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[k][1] ^= Mat.M[i][1];
                }
            }
        }
    }
    if (Mat.M[127][1] == idM64[63])
        return 1;
    else
        return 0;
}
int isinvertM256(M256 Mat) /* Invertible Matrix? */
{
    int i, j, k;
    uint64_t temp;
    int flag;
    for (i = 0; i < 64; i++) {
        if ((Mat.M[i][0] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    Mat.M[j][0] ^= Mat.M[i][0];
                    Mat.M[j][1] ^= Mat.M[i][1];
                    Mat.M[j][2] ^= Mat.M[i][2];
                    Mat.M[j][3] ^= Mat.M[i][3];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    temp = Mat.M[i][0];
                    Mat.M[i][0] = Mat.M[j][0];
                    Mat.M[j][0] = temp;

                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;

                    temp = Mat.M[i][2];
                    Mat.M[i][2] = Mat.M[j][2];
                    Mat.M[j][2] = temp;

                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][0] & idM64[i]) == idM64[i]) {
                    Mat.M[k][0] ^= Mat.M[i][0];
                    Mat.M[k][1] ^= Mat.M[i][1];
                    Mat.M[k][2] ^= Mat.M[i][2];
                    Mat.M[k][3] ^= Mat.M[i][3];
                }
            }
        }
    }
    for (i = 64; i < 128; i++) {
        if ((Mat.M[i][1] & idM64[i - 64]) == idM64[i - 64]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[j][1] ^= Mat.M[i][1];
                    Mat.M[j][2] ^= Mat.M[i][2];
                    Mat.M[j][3] ^= Mat.M[i][3];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;

                    temp = Mat.M[i][2];
                    Mat.M[i][2] = Mat.M[j][2];
                    Mat.M[j][2] = temp;

                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[k][1] ^= Mat.M[i][1];
                    Mat.M[k][2] ^= Mat.M[i][2];
                    Mat.M[k][3] ^= Mat.M[i][3];
                }
            }
        }
    }
    for (i = 128; i < 192; i++) {
        if ((Mat.M[i][2] & idM64[i - 128]) == idM64[i - 128]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    Mat.M[j][2] ^= Mat.M[i][2];
                    Mat.M[j][3] ^= Mat.M[i][3];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    temp = Mat.M[i][2];
                    Mat.M[i][2] = Mat.M[j][2];
                    Mat.M[j][2] = temp;

                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][2] & idM64[i - 128]) == idM64[i - 128]) {
                    Mat.M[k][2] ^= Mat.M[i][2];
                    Mat.M[k][3] ^= Mat.M[i][3];
                }
            }
        }
    }
    for (i = 192; i < 256; i++) {
        if ((Mat.M[i][3] & idM64[i - 192]) == idM64[i - 192]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    Mat.M[j][3] ^= Mat.M[i][3];
                }
            }
        } else {
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    flag = 0;
                    break;
                }
            }
            if (flag)
                return 0;
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][3] & idM64[i - 192]) == idM64[i - 192]) {
                    Mat.M[k][3] ^= Mat.M[i][3];
                }
            }
        }
    }
    if (Mat.M[255][3] == idM64[63])
        return 1;
    else
        return 0;
}
void invsM4(M4 Mat, M4 *Mat_inv) /* compute the 4*4 inverse matrix */
{
    int i, j, k;
    uint8_t temp;
    identityM4(Mat_inv);
    for (i = 0; i < 4; i++) {
        if ((Mat.M[i] & idM4[i]) == idM4[i]) {
            for (j = i + 1; j < 4; j++) {
                if ((Mat.M[j] & idM4[i]) == idM4[i]) {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        } else {
            for (j = i + 1; j < 4; j++) {
                if ((Mat.M[j] & idM4[i]) == idM4[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 4; k++) {
                if ((Mat.M[k] & idM4[i]) == idM4[i]) {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for (i = 3; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j] & idM4[i]) == idM4[i]) {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM8(M8 Mat, M8 *Mat_inv) /* compute the 8*8 inverse matrix */
{
    int i, j, k;
    uint8_t temp;
    identityM8(Mat_inv);
    for (i = 0; i < 8; i++) {
        if ((Mat.M[i] & idM8[i]) == idM8[i]) {
            for (j = i + 1; j < 8; j++) {
                if ((Mat.M[j] & idM8[i]) == idM8[i]) {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        } else {
            for (j = i + 1; j < 8; j++) {
                if ((Mat.M[j] & idM8[i]) == idM8[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 8; k++) {
                if ((Mat.M[k] & idM8[i]) == idM8[i]) {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for (i = 7; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j] & idM8[i]) == idM8[i]) {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM16(M16 Mat, M16 *Mat_inv) /* compute the 16*16 inverse matrix */
{
    int i, j, k;
    uint16_t temp;
    identityM16(Mat_inv);
    for (i = 0; i < 16; i++) {
        if ((Mat.M[i] & idM16[i]) == idM16[i]) {
            for (j = i + 1; j < 16; j++) {
                if ((Mat.M[j] & idM16[i]) == idM16[i]) {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        } else {
            for (j = i + 1; j < 16; j++) {
                if ((Mat.M[j] & idM16[i]) == idM16[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 16; k++) {
                if ((Mat.M[k] & idM16[i]) == idM16[i]) {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for (i = 15; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j] & idM16[i]) == idM16[i]) {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM32(M32 Mat, M32 *Mat_inv) /* compute the 32*32 inverse matrix */
{
    int i, j, k;
    uint32_t temp;
    identityM32(Mat_inv);
    for (i = 0; i < 32; i++) {
        if ((Mat.M[i] & idM32[i]) == idM32[i]) {
            for (j = i + 1; j < 32; j++) {
                if ((Mat.M[j] & idM32[i]) == idM32[i]) {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        } else {
            for (j = i + 1; j < 32; j++) {
                if ((Mat.M[j] & idM32[i]) == idM32[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 32; k++) {
                if ((Mat.M[k] & idM32[i]) == idM32[i]) {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for (i = 31; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j] & idM32[i]) == idM32[i]) {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM64(M64 Mat, M64 *Mat_inv) /* compute the 64*64 inverse matrix */
{
    int i, j, k;
    uint64_t temp;
    identityM64(Mat_inv);
    for (i = 0; i < 64; i++) {
        if ((Mat.M[i] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 64; j++) {
                if ((Mat.M[j] & idM64[i]) == idM64[i]) {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        } else {
            for (j = i + 1; j < 64; j++) {
                if ((Mat.M[j] & idM64[i]) == idM64[i]) {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 64; k++) {
                if ((Mat.M[k] & idM64[i]) == idM64[i]) {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for (i = 63; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j] & idM64[i]) == idM64[i]) {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}
void invsM128(M128 Mat, M128 *Mat_inv) /* compute the 128*128 inverse matrix */
{
    int i, j, k;
    uint64_t temp;
    identityM128(Mat_inv);
    for (i = 0; i < 64; i++) {
        if ((Mat.M[i][0] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    Mat.M[j][0] ^= Mat.M[i][0];
                    Mat.M[j][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        } else {
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    temp = Mat.M[i][0];
                    Mat.M[i][0] = Mat.M[j][0];
                    Mat.M[j][0] = temp;

                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 128; k++) {
                if ((Mat.M[k][0] & idM64[i]) == idM64[i]) {
                    Mat.M[k][0] ^= Mat.M[i][0];
                    Mat.M[k][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
    }
    for (i = 64; i < 128; i++) {
        if ((Mat.M[i][1] & idM64[i - 64]) == idM64[i - 64]) {
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[j][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        } else {
            for (j = i + 1; j < 128; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 128; k++) {
                if ((Mat.M[k][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[k][1] ^= Mat.M[i][1];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
    }
    for (i = 127; i >= 64; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                Mat.M[j][1] ^= Mat.M[i][1];
                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
            }
        }
    }
    for (i = 63; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                Mat.M[j][0] ^= Mat.M[i][0];
                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
            }
        }
    }
}
void invsM256(M256 Mat, M256 *Mat_inv) /* compute the 256*256 inverse matrix */
{
    int i, j, k;
    uint64_t temp;
    identityM256(Mat_inv);
    for (i = 0; i < 64; i++) { /* diagonal = 1? */
        if ((Mat.M[i][0] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    Mat.M[j][0] ^= Mat.M[i][0];
                    Mat.M[j][1] ^= Mat.M[i][1];
                    Mat.M[j][2] ^= Mat.M[i][2];
                    Mat.M[j][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        } else { /* swap to find 1 */
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                    temp = Mat.M[i][0];
                    Mat.M[i][0] = Mat.M[j][0];
                    Mat.M[j][0] = temp;

                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;

                    temp = Mat.M[i][2];
                    Mat.M[i][2] = Mat.M[j][2];
                    Mat.M[j][2] = temp;

                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][0] & idM64[i]) == idM64[i]) {
                    Mat.M[k][0] ^= Mat.M[i][0];
                    Mat.M[k][1] ^= Mat.M[i][1];
                    Mat.M[k][2] ^= Mat.M[i][2];
                    Mat.M[k][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
    }
    for (i = 64; i < 128; i++) { /* diagonal = 1? */
        if ((Mat.M[i][1] & idM64[i - 64]) == idM64[i - 64]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[j][1] ^= Mat.M[i][1];
                    Mat.M[j][2] ^= Mat.M[i][2];
                    Mat.M[j][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        } else { /* swap to find 1 */
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    temp = Mat.M[i][1];
                    Mat.M[i][1] = Mat.M[j][1];
                    Mat.M[j][1] = temp;

                    temp = Mat.M[i][2];
                    Mat.M[i][2] = Mat.M[j][2];
                    Mat.M[j][2] = temp;

                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][1] & idM64[i - 64]) == idM64[i - 64]) {
                    Mat.M[k][1] ^= Mat.M[i][1];
                    Mat.M[k][2] ^= Mat.M[i][2];
                    Mat.M[k][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
    }
    for (i = 128; i < 192; i++) { /* diagonal = 1? */
        if ((Mat.M[i][2] & idM64[i - 128]) == idM64[i - 128]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    Mat.M[j][2] ^= Mat.M[i][2];
                    Mat.M[j][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        } else { /* swap to find 1 */
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    temp = Mat.M[i][2];
                    Mat.M[i][2] = Mat.M[j][2];
                    Mat.M[j][2] = temp;

                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][2] & idM64[i - 128]) == idM64[i - 128]) {
                    Mat.M[k][2] ^= Mat.M[i][2];
                    Mat.M[k][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
    }
    for (i = 192; i < 256; i++) { /* diagonal = 1? */
        if ((Mat.M[i][3] & idM64[i - 192]) == idM64[i - 192]) {
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    Mat.M[j][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        } else { /* swap to find 1 */
            for (j = i + 1; j < 256; j++) {
                if ((Mat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    temp = Mat.M[i][3];
                    Mat.M[i][3] = Mat.M[j][3];
                    Mat.M[j][3] = temp;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;
                    break;
                }
            }
            for (k = i + 1; k < 256; k++) {
                if ((Mat.M[k][3] & idM64[i - 192]) == idM64[i - 192]) {
                    Mat.M[k][3] ^= Mat.M[i][3];

                    (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
    }
    for (i = 255; i >= 192; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                Mat.M[j][3] ^= Mat.M[i][3];

                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
            }
        }
    }
    for (i = 191; i >= 128; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                Mat.M[j][2] ^= Mat.M[i][2];

                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
            }
        }
    }
    for (i = 127; i >= 64; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                Mat.M[j][1] ^= Mat.M[i][1];

                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
            }
        }
    }
    for (i = 63; i >= 0; i--) {
        for (j = i - 1; j >= 0; j--) {
            if ((Mat.M[j][0] & idM64[i]) == idM64[i]) {
                Mat.M[j][0] ^= Mat.M[i][0];

                (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
            }
        }
    }
}
uint8_t affineU4(Aff4 aff, uint8_t arr) /* 4bits affine transformation */
{
    V4 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM4(aff.Mat, mul_vec, &ans_vec); /* mul */
    return ans_vec.V ^ aff.Vec.V;            /* add */
}
uint8_t affineU8(Aff8 aff, uint8_t arr) /* 8bits affine transformation */
{
    V8 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM8(aff.Mat, mul_vec, &ans_vec); /* mul */
    return ans_vec.V ^ aff.Vec.V;            /* add */
}
uint16_t affineU16(Aff16 aff, uint16_t arr) /* 16bits affine transformation */
{
    V16 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM16(aff.Mat, mul_vec, &ans_vec); /* mul */
    return ans_vec.V ^ aff.Vec.V;             /* add */
}
uint32_t affineU32(Aff32 aff, uint32_t arr) /* 32bits affine transformation */
{
    V32 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM32(aff.Mat, mul_vec, &ans_vec); /* mul */
    return ans_vec.V ^ aff.Vec.V;             /* add */
}
uint64_t affineU64(Aff64 aff, uint64_t arr) /* 64bits affine transformation */
{
    V64 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM64(aff.Mat, mul_vec, &ans_vec); /* mul */
    return ans_vec.V ^ aff.Vec.V;             /* add */
}
/* 128bits affine transformation */
void affineU128(Aff128 aff, uint64_t arr[], uint64_t ans[])
{
    V128 mul_vec, ans_vec;
    mul_vec.V[0] = arr[0];
    mul_vec.V[1] = arr[1];
    MatMulVecM128(aff.Mat, mul_vec, &ans_vec); /* mul */
    ans[0] = ans_vec.V[0] ^ aff.Vec.V[0];      /* add */
    ans[1] = ans_vec.V[1] ^ aff.Vec.V[1];
}
int xorU4(uint8_t n) /* 4bits internal xor */
{
    if (xor[n])
        return 1;
    else
        return 0;
}
int xorU8(uint8_t n) /* uint8_t internal xor */
{
    if (xor[n])
        return 1;
    else
        return 0;
}
int xorU16(uint16_t n) /* uint16_t internal xor */
{
    uint8_t temp = 0;
    uint8_t *u = (uint8_t *)&n;
    temp = (*u) ^ (*(u + 1));
    if (xorU8(temp))
        return 1;
    else
        return 0;
}
int xorU32(uint32_t n) /* uint32_t internal xor */
{
    uint16_t temp = 0;
    uint16_t *u = (uint16_t *)&n;
    temp = (*u) ^ (*(u + 1));
    if (xorU16(temp))
        return 1;
    else
        return 0;
}
int xorU64(uint64_t n) /* uint64_t internal xor */
{
    uint32_t temp = 0;
    uint32_t *u = (uint32_t *)&n;
    temp = (*u) ^ (*(u + 1));
    if (xorU32(temp))
        return 1;
    else
        return 0;
}
int xorU128(uint64_t n[]) /* uint128_t internal xor */
{
    uint64_t temp = 0;
    temp = n[0] ^ n[1];
    if (xorU64(temp))
        return 1;
    else
        return 0;
}
int xorU256(uint64_t n[]) /* uint256_t internal xor */
{
    uint64_t temp = 0;
    temp = n[0] ^ n[1] ^ n[2] ^ n[3];
    if (xorU64(temp))
        return 1;
    else
        return 0;
}
int HWU4(uint8_t n) /* 4bits HW */
{
    return HW[n];
}
int HWU8(uint8_t n) /* uint8_t HW */
{
    return HW[n];
}
int HWU16(uint16_t n) /* uint16_t HW */
{
    uint8_t *u = (uint8_t *)&n;
    return HWU8(*u) + HWU8(*(u + 1));
}
int HWU32(uint32_t n) /* uint32_t HW */
{
    uint16_t *u = (uint16_t *)&n;
    return HWU16(*u) + HWU16(*(u + 1));
}
int HWU64(uint64_t n) /* uint64_t HW */
{
    uint32_t *u = (uint32_t *)&n;
    return HWU32(*u) + HWU32(*(u + 1));
}
int HWU128(uint64_t n[]) /* uint128_t HW */
{
    return HWU64(n[0]) + HWU64(n[1]);
}
void printU8(uint8_t n) /* printf uint8_t */
{
    printf("0x%x\n", n);
}
void printU16(uint16_t n) /* printf uint16_t */
{
    printf("0x%x\n", n);
}
void printU32(uint32_t n) /* printf uint32_t */
{
    printf("0x%x\n", n);
}
void printU64(uint64_t n) /* printf uint64_t */
{
    printf("0x%" PRIx64 "\n", n);
}
void printU128(uint64_t n[]) /* printf uint128_t */
{
    printf("0x%" PRIx64 " ", n[0]);
    printf("0x%" PRIx64 "\n", n[1]);
}
void printbitM4(M4 Mat) /* printf Matrix 4*4 in the form of bits */
{
    int i, j;
    uint8_t temp;
    for (i = 0; i < 4; i++) {
        temp = Mat.M[i];
        for (j = 0; j < 4; j++) {
            if (temp & 0x08)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM8(M8 Mat) /* printf Matrix 8*8 in the form of bits */
{
    int i, j;
    uint8_t temp;
    for (i = 0; i < 8; i++) {
        temp = Mat.M[i];
        for (j = 0; j < 8; j++) {
            if (temp & 0x80)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM16(M16 Mat) /* printf Matrix 16*16 in the form of bits */
{
    int i, j;
    uint16_t temp;
    for (i = 0; i < 16; i++) {
        temp = Mat.M[i];
        for (j = 0; j < 16; j++) {
            if (temp & 0x8000)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM32(M32 Mat) /* printf Matrix 32*32 in the form of bits */
{
    int i, j;
    uint32_t temp;
    for (i = 0; i < 32; i++) {
        temp = Mat.M[i];
        for (j = 0; j < 32; j++) {
            if (temp & 0x80000000)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM64(M64 Mat) /* printf Matrix 64*64 in the form of bits */
{
    int i, j;
    uint64_t temp;
    for (i = 0; i < 64; i++) {
        temp = Mat.M[i];
        for (j = 0; j < 64; j++) {
            if (temp & 0x8000000000000000)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void printbitM128(M128 Mat) /* printf Matrix 128*128 in the form of bits */
{
    int i, j;
    uint64_t temp;
    for (i = 0; i < 128; i++) {
        temp = Mat.M[i][0];
        for (j = 0; j < 64; j++) {
            if (temp & 0x8000000000000000)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        temp = Mat.M[i][1];
        for (j = 0; j < 64; j++) {
            if (temp & 0x8000000000000000)
                printf("%d ", 1);
            else
                printf("%d ", 0);
            temp = temp << 1;
        }
        printf("\n");
    }
    printf("\n");
}
void VecAddVecV4(V4 Vec1, V4 Vec2, V4 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV8(V8 Vec1, V8 Vec2, V8 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV16(V16 Vec1, V16 Vec2, V16 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV32(V32 Vec1, V32 Vec2, V32 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV64(V64 Vec1, V64 Vec2, V64 *Vec)
{
    (*Vec).V = Vec1.V ^ Vec2.V;
}
void VecAddVecV128(V128 Vec1, V128 Vec2, V128 *Vec)
{
    (*Vec).V[0] = Vec1.V[0] ^ Vec2.V[0];
    (*Vec).V[1] = Vec1.V[1] ^ Vec2.V[1];
}
void VecAddVecV256(V256 Vec1, V256 Vec2, V256 *Vec)
{
    (*Vec).V[0] = Vec1.V[0] ^ Vec2.V[0];
    (*Vec).V[1] = Vec1.V[1] ^ Vec2.V[1];
    (*Vec).V[2] = Vec1.V[2] ^ Vec2.V[2];
    (*Vec).V[3] = Vec1.V[3] ^ Vec2.V[3];
}
uint8_t MatMulNumM4(M4 Mat, uint8_t n) /* matrix * number -> number 4bits */
{
    int i;
    uint8_t temp = 0;
    for (i = 0; i < 4; i++) {
        if (xorU4(Mat.M[i] & n & 0x0f))
            temp ^= idM4[i];
    }
    return temp;
}
uint8_t MatMulNumM8(M8 Mat, uint8_t n) /* matrix * number -> number 8bits */
{
    int i;
    uint8_t temp = 0;
    for (i = 0; i < 8; i++) {
        if (xorU8(Mat.M[i] & n))
            temp ^= idM8[i];
    }
    return temp;
}
/* matrix * number -> number 16bits */
uint16_t MatMulNumM16(M16 Mat, uint16_t n)
{
    int i;
    uint16_t temp = 0;
    for (i = 0; i < 16; i++) {
        if (xorU16(Mat.M[i] & n))
            temp ^= idM16[i];
    }
    return temp;
}
/* matrix * number -> number 32bits */
uint32_t MatMulNumM32(M32 Mat, uint32_t n)
{
    int i;
    uint32_t temp = 0;
    for (i = 0; i < 32; i++) {
        if (xorU32(Mat.M[i] & n))
            temp ^= idM32[i];
    }
    return temp;
}
/* matrix * number -> number 64bits */
uint64_t MatMulNumM64(M64 Mat, uint64_t n)
{
    int i;
    uint64_t temp = 0;
    for (i = 0; i < 64; i++) {
        if (xorU64(Mat.M[i] & n))
            temp ^= idM64[i];
    }
    return temp;
}
void MatMulVecM4(M4 Mat, V4 Vec, V4 *ans) /* matrix * vector -> vector 4*1 */
{
    int i;
    initV4(ans);
    for (i = 0; i < 4; i++) {
        if (xorU4(Mat.M[i] & Vec.V & 0x0f))
            (*ans).V ^= idM4[i];
    }
}
void MatMulVecM8(M8 Mat, V8 Vec, V8 *ans) /* matrix * vector -> vector 8*1 */
{
    int i;
    initV8(ans);
    for (i = 0; i < 8; i++) {
        if (xorU8(Mat.M[i] & Vec.V))
            (*ans).V ^= idM8[i];
    }
}
/* matrix * vector -> vector 16*1 */
void MatMulVecM16(M16 Mat, V16 Vec, V16 *ans)
{
    int i;
    initV16(ans);
    for (i = 0; i < 16; i++) {
        if (xorU16(Mat.M[i] & Vec.V))
            (*ans).V ^= idM16[i];
    }
}
/* matrix * vector -> vector 32*1 */
void MatMulVecM32(M32 Mat, V32 Vec, V32 *ans)
{
    int i;
    initV32(ans);
    for (i = 0; i < 32; i++) {
        if (xorU32(Mat.M[i] & Vec.V))
            (*ans).V ^= idM32[i];
    }
}
/* matrix * vector -> vector 64*1 */
void MatMulVecM64(M64 Mat, V64 Vec, V64 *ans)
{
    int i;
    initV64(ans);
    for (i = 0; i < 64; i++) {
        if (xorU64(Mat.M[i] & Vec.V))
            (*ans).V ^= idM64[i];
    }
}
/* matrix * vector -> vector 128*1 */
void MatMulVecM128(M128 Mat, V128 Vec, V128 *ans)
{
    int i;
    initV128(ans);
    uint64_t temp[2];
    for (i = 0; i < 64; i++) {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        if (xorU128(temp))
            (*ans).V[0] ^= idM64[i];
    }
    for (i = 64; i < 128; i++) {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        if (xorU128(temp))
            (*ans).V[1] ^= idM64[i - 64];
    }
}
/* matrix * vector -> vector 256*1 */
void MatMulVecM256(M256 Mat, V256 Vec, V256 *ans)
{
    int i;
    initV256(ans);
    uint64_t temp[4];
    for (i = 0; i < 64; i++) {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        temp[2] = Mat.M[i][2] & Vec.V[2];
        temp[3] = Mat.M[i][3] & Vec.V[3];
        if (xorU256(temp))
            (*ans).V[0] ^= idM64[i];
    }
    for (i = 64; i < 128; i++) {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        temp[2] = Mat.M[i][2] & Vec.V[2];
        temp[3] = Mat.M[i][3] & Vec.V[3];
        if (xorU256(temp))
            (*ans).V[1] ^= idM64[i - 64];
    }
    for (i = 128; i < 192; i++) {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        temp[2] = Mat.M[i][2] & Vec.V[2];
        temp[3] = Mat.M[i][3] & Vec.V[3];
        if (xorU256(temp))
            (*ans).V[2] ^= idM64[i - 128];
    }
    for (i = 192; i < 256; i++) {
        temp[0] = Mat.M[i][0] & Vec.V[0];
        temp[1] = Mat.M[i][1] & Vec.V[1];
        temp[2] = Mat.M[i][2] & Vec.V[2];
        temp[3] = Mat.M[i][3] & Vec.V[3];
        if (xorU256(temp))
            (*ans).V[3] ^= idM64[i - 192];
    }
}
/* generate 4*4 invertible matrix and its inverse matrix */
void genMatpairM4(M4 *Mat, M4 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M4 tempMat;
    M4 resultMat;
    uint8_t temp;
    uint8_t trail[16][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM4(Mat);
    identityM4(Mat_inv);
    randM4(&tempMat);
    copyM4(tempMat, &resultMat);
    for (i = 0; i < 4; i++) { /* diagonal = 1? */
        if ((tempMat.M[i] & idM4[i]) == idM4[i]) {
            for (j = i + 1; j < 4; j++) {
                if ((tempMat.M[j] & idM4[i]) == idM4[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 4; j++) {
                if ((tempMat.M[j] & idM4[i]) == idM4[i]) {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 3) {
                    p = i + 1 + cus_random() % (3 - i); /* swap */
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for (t = i + 1; t < 4; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 4; k++) {
                    if ((tempMat.M[k] & idM4[i]) == idM4[i]) {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 3; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM4[t]) == idM4[t]) {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }
        }
    } else { /* invertible */
        for (i = 3; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM4[i]) == idM4[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM4(resultMat, Mat);
    }
}
/* generate 8*8 invertible matrix and its inverse matrix */
void genMatpairM8(M8 *Mat, M8 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M8 tempMat;
    M8 resultMat;
    uint8_t temp;
    uint8_t trail[64][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM8(Mat);
    identityM8(Mat_inv);
    randM8(&tempMat);
    copyM8(tempMat, &resultMat);
    for (i = 0; i < 8; i++) { /* diagonal = 1? */
        if ((tempMat.M[i] & idM8[i]) == idM8[i]) {
            for (j = i + 1; j < 8; j++) {
                if ((tempMat.M[j] & idM8[i]) == idM8[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 8; j++) {
                if ((tempMat.M[j] & idM8[i]) == idM8[i]) {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 7) {
                    p = i + 1 + cus_random() % (7 - i); /* swap */
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for (t = i + 1; t < 8; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 8; k++) {
                    if ((tempMat.M[k] & idM8[i]) == idM8[i]) {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 7; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM8[t]) == idM8[t]) {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }
        }
    } else { /* invertible */
        for (i = 7; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM8[i]) == idM8[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM8(resultMat, Mat);
    }
}
/* generate 16*16 invertible matrix and its inverse matrix */
void genMatpairM16(M16 *Mat, M16 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M16 tempMat;
    M16 resultMat;
    uint16_t temp;
    uint8_t trail[256][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM16(Mat);
    identityM16(Mat_inv);
    randM16(&tempMat);
    copyM16(tempMat, &resultMat);
    for (i = 0; i < 16; i++) { /* diagonal = 1? */
        if ((tempMat.M[i] & idM16[i]) == idM16[i]) {
            for (j = i + 1; j < 16; j++) {
                if ((tempMat.M[j] & idM16[i]) == idM16[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 16; j++) {
                if ((tempMat.M[j] & idM16[i]) == idM16[i]) {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 15) {
                    p = i + 1 + cus_random() % (15 - i); /* swap */
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for (t = i + 1; t < 16; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 16; k++) {
                    if ((tempMat.M[k] & idM16[i]) == idM16[i]) {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 15; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM16[t]) == idM16[t]) {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }
        }
    } else { /* invertible */
        for (i = 15; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM16[i]) == idM16[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM16(resultMat, Mat);
    }
}
/* generate 32*32 invertible matrix and its inverse matrix */
void genMatpairM32(M32 *Mat, M32 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M32 tempMat;
    M32 resultMat;
    uint32_t temp;
    uint8_t trail[1024][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM32(Mat);
    identityM32(Mat_inv);
    randM32(&tempMat);
    copyM32(tempMat, &resultMat);
    for (i = 0; i < 32; i++) { /* diagonal = 1? */
        if ((tempMat.M[i] & idM32[i]) == idM32[i]) {
            for (j = i + 1; j < 32; j++) {
                if ((tempMat.M[j] & idM32[i]) == idM32[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 32; j++) {
                if ((tempMat.M[j] & idM32[i]) == idM32[i]) {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 31) {
                    p = i + 1 + cus_random() % (31 - i); /* swap */
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for (t = i + 1; t < 32; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 32; k++) {
                    if ((tempMat.M[k] & idM32[i]) == idM32[i]) {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 31; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM32[t]) == idM32[t]) {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }
        }
    } else { /* invertible */
        for (i = 31; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM32[i]) == idM32[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM32(resultMat, Mat);
    }
}
/* generate 64*64 invertible matrix and its inverse matrix */
void genMatpairM64(M64 *Mat, M64 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M64 tempMat;
    M64 resultMat;
    uint64_t temp;
    uint8_t trail[4096][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM64(Mat);
    identityM64(Mat_inv);
    randM64(&tempMat);
    copyM64(tempMat, &resultMat);
    for (i = 0; i < 64; i++) { /* diagonal = 1? */
        if ((tempMat.M[i] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 64; j++) {
                if ((tempMat.M[j] & idM64[i]) == idM64[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 64; j++) {
                if ((tempMat.M[j] & idM64[i]) == idM64[i]) {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 63) {
                    p = i + 1 + cus_random() % (63 - i); /* swap */
                    temp = tempMat.M[p];
                    tempMat.M[p] = tempMat.M[i];
                    tempMat.M[i] = temp;
                    temp = (*Mat_inv).M[p];
                    (*Mat_inv).M[p] = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = temp;
                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;
                    for (t = i + 1; t < 64; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 64; k++) {
                    if ((tempMat.M[k] & idM64[i]) == idM64[i]) {
                        tempMat.M[k] ^= tempMat.M[i];

                        (*Mat_inv).M[k] ^= (*Mat_inv).M[i];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 63; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM64[t]) == idM64[t]) {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }
        }
    } else { /* invertible */
        for (i = 63; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j] & idM64[i]) == idM64[i]) {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM64(resultMat, Mat);
    }
}
/* generate 128*128 invertible matrix and its inverse matrix */
void genMatpairM128(M128 *Mat, M128 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M128 tempMat;
    M128 resultMat;
    uint64_t temp;
    uint8_t trail[16384][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM128(Mat);
    identityM128(Mat_inv);
    randM128(&tempMat);
    copyM128(tempMat, &resultMat);
    for (i = 0; i < 64; i++) { /* diagonal = 1? */
        if ((tempMat.M[i][0] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 128; j++) {
                if ((tempMat.M[j][0] & idM64[i]) == idM64[i]) {
                    tempMat.M[j][0] ^= tempMat.M[i][0];
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 128; j++) {
                if ((tempMat.M[j][0] & idM64[i]) == idM64[i]) {
                    temp = tempMat.M[i][0];
                    tempMat.M[i][0] = tempMat.M[j][0];
                    tempMat.M[j][0] = temp;

                    temp = tempMat.M[i][1];
                    tempMat.M[i][1] = tempMat.M[j][1];
                    tempMat.M[j][1] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                p = i + 1 + cus_random() % (127 - i); /* swap */

                temp = tempMat.M[p][0];
                tempMat.M[p][0] = tempMat.M[i][0];
                tempMat.M[i][0] = temp;

                temp = tempMat.M[p][1];
                tempMat.M[p][1] = tempMat.M[i][1];
                tempMat.M[i][1] = temp;

                temp = (*Mat_inv).M[p][0];
                (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                (*Mat_inv).M[i][0] = temp;

                temp = (*Mat_inv).M[p][1];
                (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                (*Mat_inv).M[i][1] = temp;

                trail[times][0] = 0;
                trail[times][1] = p;
                trail[times][2] = i;
                times++;

                for (t = i + 1; t < 128; t++) {
                    if (cus_random() % 2) {
                        tempMat.M[t][0] ^= tempMat.M[i][0];
                        tempMat.M[t][1] ^= tempMat.M[i][1];

                        (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                        trail[times][0] = 1;
                        trail[times][1] = t;
                        trail[times][2] = i;
                        times++;
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 128; k++) {
                    if ((tempMat.M[k][0] & idM64[i]) == idM64[i]) {
                        tempMat.M[k][0] ^= tempMat.M[i][0];
                        tempMat.M[k][1] ^= tempMat.M[i][1];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    for (i = 64; i < 128; i++) { /* diagonal = 1? */
        if ((tempMat.M[i][1] & idM64[i - 64]) == idM64[i - 64]) {
            for (j = i + 1; j < 128; j++) {
                if ((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 128; j++) {
                if ((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    temp = tempMat.M[i][1];
                    tempMat.M[i][1] = tempMat.M[j][1];
                    tempMat.M[j][1] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 127) {
                    p = i + 1 + cus_random() % (127 - i); /* swap */

                    temp = tempMat.M[p][1];
                    tempMat.M[p][1] = tempMat.M[i][1];
                    tempMat.M[i][1] = temp;

                    temp = (*Mat_inv).M[p][0];
                    (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = temp;

                    temp = (*Mat_inv).M[p][1];
                    (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;

                    for (t = i + 1; t < 128; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t][1] ^= tempMat.M[i][1];

                            (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                            (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 128; k++) {
                    if ((tempMat.M[k][1] & idM64[i - 64]) == idM64[i - 64]) {
                        tempMat.M[k][1] ^= tempMat.M[i][1];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 127; t >= 64; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j][1] & idM64[t - 64]) == idM64[t - 64]) {
                    tempMat.M[j][1] ^= tempMat.M[t][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        for (t = 63; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j][0] & idM64[t]) == idM64[t]) {
                    tempMat.M[j][0] ^= tempMat.M[t][0];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]][0] ^= (*Mat).M[trail[j][2]][0];
                (*Mat).M[trail[j][1]][1] ^= (*Mat).M[trail[j][2]][1];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]][0];
                (*Mat).M[trail[j][1]][0] = (*Mat).M[trail[j][2]][0];
                (*Mat).M[trail[j][2]][0] = temp;

                temp = (*Mat).M[trail[j][1]][1];
                (*Mat).M[trail[j][1]][1] = (*Mat).M[trail[j][2]][1];
                (*Mat).M[trail[j][2]][1] = temp;
            }
        }
    } else { /* invertible */
        for (i = 127; i >= 64; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
        for (i = 63; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j][0] & idM64[i]) == idM64[i]) {
                    tempMat.M[j][0] ^= tempMat.M[i][0];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                }
            }
        }
        copyM128(resultMat, Mat);
    }
}
/* generate 256*256 invertible matrix and its inverse matrix */
void genMatpairM256(M256 *Mat, M256 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M256 tempMat;
    M256 resultMat;
    uint64_t temp;
    uint8_t trail[65536][3]; /* generate trail */
    int flag = 0;
    int times = 0;
    int invertible = 1;
    /* InitRandom((randseed++) ^ ((unsigned int)time(NULL))); */
    identityM256(Mat);
    identityM256(Mat_inv);
    randM256(&tempMat);
    copyM256(tempMat, &resultMat);
    for (i = 0; i < 64; i++) { /* diagonal = 1? */
        if ((tempMat.M[i][0] & idM64[i]) == idM64[i]) {
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][0] & idM64[i]) == idM64[i]) {
                    tempMat.M[j][0] ^= tempMat.M[i][0];
                    tempMat.M[j][1] ^= tempMat.M[i][1];
                    tempMat.M[j][2] ^= tempMat.M[i][2];
                    tempMat.M[j][3] ^= tempMat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][0] & idM64[i]) == idM64[i]) {
                    temp = tempMat.M[i][0];
                    tempMat.M[i][0] = tempMat.M[j][0];
                    tempMat.M[j][0] = temp;

                    temp = tempMat.M[i][1];
                    tempMat.M[i][1] = tempMat.M[j][1];
                    tempMat.M[j][1] = temp;

                    temp = tempMat.M[i][2];
                    tempMat.M[i][2] = tempMat.M[j][2];
                    tempMat.M[j][2] = temp;

                    temp = tempMat.M[i][3];
                    tempMat.M[i][3] = tempMat.M[j][3];
                    tempMat.M[j][3] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                p = i + 1 + cus_random() % (255 - i); /* swap */

                temp = tempMat.M[p][0];
                tempMat.M[p][0] = tempMat.M[i][0];
                tempMat.M[i][0] = temp;

                temp = tempMat.M[p][1];
                tempMat.M[p][1] = tempMat.M[i][1];
                tempMat.M[i][1] = temp;

                temp = tempMat.M[p][2];
                tempMat.M[p][2] = tempMat.M[i][2];
                tempMat.M[i][2] = temp;

                temp = tempMat.M[p][3];
                tempMat.M[p][3] = tempMat.M[i][3];
                tempMat.M[i][3] = temp;

                temp = (*Mat_inv).M[p][0];
                (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                (*Mat_inv).M[i][0] = temp;

                temp = (*Mat_inv).M[p][1];
                (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                (*Mat_inv).M[i][1] = temp;

                temp = (*Mat_inv).M[p][2];
                (*Mat_inv).M[p][2] = (*Mat_inv).M[i][2];
                (*Mat_inv).M[i][2] = temp;

                temp = (*Mat_inv).M[p][3];
                (*Mat_inv).M[p][3] = (*Mat_inv).M[i][3];
                (*Mat_inv).M[i][3] = temp;

                trail[times][0] = 0;
                trail[times][1] = p;
                trail[times][2] = i;
                times++;

                for (t = i + 1; t < 256; t++) {
                    if (cus_random() % 2) {
                        tempMat.M[t][0] ^= tempMat.M[i][0];
                        tempMat.M[t][1] ^= tempMat.M[i][1];
                        tempMat.M[t][2] ^= tempMat.M[i][2];
                        tempMat.M[t][3] ^= tempMat.M[i][3];

                        (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                        (*Mat_inv).M[t][2] ^= (*Mat_inv).M[i][2];
                        (*Mat_inv).M[t][3] ^= (*Mat_inv).M[i][3];
                        trail[times][0] = 1;
                        trail[times][1] = t;
                        trail[times][2] = i;
                        times++;
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 256; k++) {
                    if ((tempMat.M[k][0] & idM64[i]) == idM64[i]) {
                        tempMat.M[k][0] ^= tempMat.M[i][0];
                        tempMat.M[k][1] ^= tempMat.M[i][1];
                        tempMat.M[k][2] ^= tempMat.M[i][2];
                        tempMat.M[k][3] ^= tempMat.M[i][3];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                        (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                        (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    for (i = 64; i < 128; i++) { /* diagonal = 1? */
        if ((tempMat.M[i][1] & idM64[i - 64]) == idM64[i - 64]) {
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    tempMat.M[j][1] ^= tempMat.M[i][1];
                    tempMat.M[j][2] ^= tempMat.M[i][2];
                    tempMat.M[j][3] ^= tempMat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    temp = tempMat.M[i][1];
                    tempMat.M[i][1] = tempMat.M[j][1];
                    tempMat.M[j][1] = temp;

                    temp = tempMat.M[i][2];
                    tempMat.M[i][2] = tempMat.M[j][2];
                    tempMat.M[j][2] = temp;

                    temp = tempMat.M[i][3];
                    tempMat.M[i][3] = tempMat.M[j][3];
                    tempMat.M[j][3] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                /* if(i < 127) */ {
                    p = i + 1 + cus_random() % (255 - i); /* swap */

                    temp = tempMat.M[p][1];
                    tempMat.M[p][1] = tempMat.M[i][1];
                    tempMat.M[i][1] = temp;

                    temp = tempMat.M[p][2];
                    tempMat.M[p][2] = tempMat.M[i][2];
                    tempMat.M[i][2] = temp;

                    temp = tempMat.M[p][3];
                    tempMat.M[p][3] = tempMat.M[i][3];
                    tempMat.M[i][3] = temp;

                    temp = (*Mat_inv).M[p][0];
                    (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = temp;

                    temp = (*Mat_inv).M[p][1];
                    (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = temp;

                    temp = (*Mat_inv).M[p][2];
                    (*Mat_inv).M[p][2] = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = temp;

                    temp = (*Mat_inv).M[p][3];
                    (*Mat_inv).M[p][3] = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;

                    for (t = i + 1; t < 256; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t][1] ^= tempMat.M[i][1];
                            tempMat.M[t][2] ^= tempMat.M[i][2];
                            tempMat.M[t][3] ^= tempMat.M[i][3];

                            (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                            (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                            (*Mat_inv).M[t][2] ^= (*Mat_inv).M[i][2];
                            (*Mat_inv).M[t][3] ^= (*Mat_inv).M[i][3];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 256; k++) {
                    if ((tempMat.M[k][1] & idM64[i - 64]) == idM64[i - 64]) {
                        tempMat.M[k][1] ^= tempMat.M[i][1];
                        tempMat.M[k][2] ^= tempMat.M[i][2];
                        tempMat.M[k][3] ^= tempMat.M[i][3];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                        (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                        (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    for (i = 128; i < 192; i++) { /* diagonal = 1? */
        if ((tempMat.M[i][2] & idM64[i - 128]) == idM64[i - 128]) {
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    tempMat.M[j][2] ^= tempMat.M[i][2];
                    tempMat.M[j][3] ^= tempMat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    temp = tempMat.M[i][2];
                    tempMat.M[i][2] = tempMat.M[j][2];
                    tempMat.M[j][2] = temp;

                    temp = tempMat.M[i][3];
                    tempMat.M[i][3] = tempMat.M[j][3];
                    tempMat.M[j][3] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                /* if(i < 127) */ {
                    p = i + 1 + cus_random() % (255 - i); /* swap */

                    temp = tempMat.M[p][2];
                    tempMat.M[p][2] = tempMat.M[i][2];
                    tempMat.M[i][2] = temp;

                    temp = tempMat.M[p][3];
                    tempMat.M[p][3] = tempMat.M[i][3];
                    tempMat.M[i][3] = temp;

                    temp = (*Mat_inv).M[p][0];
                    (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = temp;

                    temp = (*Mat_inv).M[p][1];
                    (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = temp;

                    temp = (*Mat_inv).M[p][2];
                    (*Mat_inv).M[p][2] = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = temp;

                    temp = (*Mat_inv).M[p][3];
                    (*Mat_inv).M[p][3] = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;

                    for (t = i + 1; t < 256; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t][2] ^= tempMat.M[i][2];
                            tempMat.M[t][3] ^= tempMat.M[i][3];

                            (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                            (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                            (*Mat_inv).M[t][2] ^= (*Mat_inv).M[i][2];
                            (*Mat_inv).M[t][3] ^= (*Mat_inv).M[i][3];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 256; k++) {
                    if ((tempMat.M[k][2] & idM64[i - 128]) == idM64[i - 128]) {
                        tempMat.M[k][2] ^= tempMat.M[i][2];
                        tempMat.M[k][3] ^= tempMat.M[i][3];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                        (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                        (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    for (i = 192; i < 256; i++) { /* diagonal = 1? */
        if ((tempMat.M[i][3] & idM64[i - 192]) == idM64[i - 192]) {
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    tempMat.M[j][3] ^= tempMat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        } else { /* swap to find 1 */
            flag = 1;
            for (j = i + 1; j < 256; j++) {
                if ((tempMat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    temp = tempMat.M[i][3];
                    tempMat.M[i][3] = tempMat.M[j][3];
                    tempMat.M[j][3] = temp;

                    flag = 0;

                    temp = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = (*Mat_inv).M[j][0];
                    (*Mat_inv).M[j][0] = temp;

                    temp = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = (*Mat_inv).M[j][1];
                    (*Mat_inv).M[j][1] = temp;

                    temp = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = (*Mat_inv).M[j][2];
                    (*Mat_inv).M[j][2] = temp;

                    temp = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = (*Mat_inv).M[j][3];
                    (*Mat_inv).M[j][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                    break;
                }
            }
            if (flag) { /* can not find 1 which means not invertible */
                invertible = 0;
                if (i < 255) {
                    p = i + 1 + cus_random() % (255 - i); /* swap */

                    temp = tempMat.M[p][3];
                    tempMat.M[p][3] = tempMat.M[i][3];
                    tempMat.M[i][3] = temp;

                    temp = (*Mat_inv).M[p][0];
                    (*Mat_inv).M[p][0] = (*Mat_inv).M[i][0];
                    (*Mat_inv).M[i][0] = temp;

                    temp = (*Mat_inv).M[p][1];
                    (*Mat_inv).M[p][1] = (*Mat_inv).M[i][1];
                    (*Mat_inv).M[i][1] = temp;

                    temp = (*Mat_inv).M[p][2];
                    (*Mat_inv).M[p][2] = (*Mat_inv).M[i][2];
                    (*Mat_inv).M[i][2] = temp;

                    temp = (*Mat_inv).M[p][3];
                    (*Mat_inv).M[p][3] = (*Mat_inv).M[i][3];
                    (*Mat_inv).M[i][3] = temp;

                    trail[times][0] = 0;
                    trail[times][1] = p;
                    trail[times][2] = i;
                    times++;

                    for (t = i + 1; t < 256; t++) {
                        if (cus_random() % 2) {
                            tempMat.M[t][3] ^= tempMat.M[i][3];

                            (*Mat_inv).M[t][0] ^= (*Mat_inv).M[i][0];
                            (*Mat_inv).M[t][1] ^= (*Mat_inv).M[i][1];
                            (*Mat_inv).M[t][2] ^= (*Mat_inv).M[i][2];
                            (*Mat_inv).M[t][3] ^= (*Mat_inv).M[i][3];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            } else { /* can still contiune */
                for (k = i + 1; k < 256; k++) {
                    if ((tempMat.M[k][3] & idM64[i - 192]) == idM64[i - 192]) {
                        tempMat.M[k][3] ^= tempMat.M[i][3];

                        (*Mat_inv).M[k][0] ^= (*Mat_inv).M[i][0];
                        (*Mat_inv).M[k][1] ^= (*Mat_inv).M[i][1];
                        (*Mat_inv).M[k][2] ^= (*Mat_inv).M[i][2];
                        (*Mat_inv).M[k][3] ^= (*Mat_inv).M[i][3];

                        trail[times][0] = 1;
                        trail[times][1] = k;
                        trail[times][2] = i;
                        times++;
                    }
                }
            }
        }
    }
    if (!invertible) { /* not invertible */
        for (t = 255; t >= 192; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j][3] & idM64[t - 192]) == idM64[t - 192]) {
                    tempMat.M[j][3] ^= tempMat.M[t][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[t][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[t][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        for (t = 191; t >= 128; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j][2] & idM64[t - 128]) == idM64[t - 128]) {
                    tempMat.M[j][2] ^= tempMat.M[t][2];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[t][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[t][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        for (t = 127; t >= 64; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j][1] & idM64[t - 64]) == idM64[t - 64]) {
                    tempMat.M[j][1] ^= tempMat.M[t][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[t][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[t][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }
        for (t = 63; t >= 0; t--) {
            for (j = t - 1; j >= 0; j--) {
                if ((tempMat.M[j][0] & idM64[t]) == idM64[t]) {
                    tempMat.M[j][0] ^= tempMat.M[t][0];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[t][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[t][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[t][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[t][3];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--) { /* generate inverse matrix */
            if (trail[j][0]) { /* add */
                (*Mat).M[trail[j][1]][0] ^= (*Mat).M[trail[j][2]][0];
                (*Mat).M[trail[j][1]][1] ^= (*Mat).M[trail[j][2]][1];
                (*Mat).M[trail[j][1]][2] ^= (*Mat).M[trail[j][2]][2];
                (*Mat).M[trail[j][1]][3] ^= (*Mat).M[trail[j][2]][3];
            } else { /* swap */
                temp = (*Mat).M[trail[j][1]][0];
                (*Mat).M[trail[j][1]][0] = (*Mat).M[trail[j][2]][0];
                (*Mat).M[trail[j][2]][0] = temp;

                temp = (*Mat).M[trail[j][1]][1];
                (*Mat).M[trail[j][1]][1] = (*Mat).M[trail[j][2]][1];
                (*Mat).M[trail[j][2]][1] = temp;

                temp = (*Mat).M[trail[j][1]][2];
                (*Mat).M[trail[j][1]][2] = (*Mat).M[trail[j][2]][2];
                (*Mat).M[trail[j][2]][2] = temp;

                temp = (*Mat).M[trail[j][1]][3];
                (*Mat).M[trail[j][1]][3] = (*Mat).M[trail[j][2]][3];
                (*Mat).M[trail[j][2]][3] = temp;
            }
        }
    } else { /* invertible */
        for (i = 255; i >= 192; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j][3] & idM64[i - 192]) == idM64[i - 192]) {
                    tempMat.M[j][3] ^= tempMat.M[i][3];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
        for (i = 191; i >= 128; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j][2] & idM64[i - 128]) == idM64[i - 128]) {
                    tempMat.M[j][2] ^= tempMat.M[i][2];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
        for (i = 127; i >= 64; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j][1] & idM64[i - 64]) == idM64[i - 64]) {
                    tempMat.M[j][1] ^= tempMat.M[i][1];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
        for (i = 63; i >= 0; i--) {
            for (j = i - 1; j >= 0; j--) {
                if ((tempMat.M[j][0] & idM64[i]) == idM64[i]) {
                    tempMat.M[j][0] ^= tempMat.M[i][0];

                    (*Mat_inv).M[j][0] ^= (*Mat_inv).M[i][0];
                    (*Mat_inv).M[j][1] ^= (*Mat_inv).M[i][1];
                    (*Mat_inv).M[j][2] ^= (*Mat_inv).M[i][2];
                    (*Mat_inv).M[j][3] ^= (*Mat_inv).M[i][3];
                }
            }
        }
        copyM256(resultMat, Mat);
    }
}
void genaffinepairM4(Aff4 *aff, Aff4 *aff_inv) /* generate a pair of affine */
{
    genMatpairM4(&(aff->Mat), &(aff_inv->Mat));
    randV4(&(aff->Vec));
    MatMulVecM4((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
void genaffinepairM8(Aff8 *aff, Aff8 *aff_inv) /* generate a pair of affine */
{
    genMatpairM8(&(aff->Mat), &(aff_inv->Mat));
    randV8(&(aff->Vec));
    MatMulVecM8((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
/* generate a pair of affine */
void genaffinepairM16(Aff16 *aff, Aff16 *aff_inv)
{
    genMatpairM16(&(aff->Mat), &(aff_inv->Mat));
    randV16(&(aff->Vec));
    MatMulVecM16((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
/* generate a pair of affine */
void genaffinepairM32(Aff32 *aff, Aff32 *aff_inv)
{
    genMatpairM32(&(aff->Mat), &(aff_inv->Mat));
    randV32(&(aff->Vec));
    MatMulVecM32((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
/* generate a pair of affine */
void genaffinepairM64(Aff64 *aff, Aff64 *aff_inv)
{
    genMatpairM64(&(aff->Mat), &(aff_inv->Mat));
    randV64(&(aff->Vec));
    MatMulVecM64((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
/* generate a pair of affine */
void genaffinepairM128(Aff128 *aff, Aff128 *aff_inv)
{
    genMatpairM128(&(aff->Mat), &(aff_inv->Mat));
    randV128(&(aff->Vec));
    MatMulVecM128((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}
/* diagonal matrix concatenation, four 8*8 -> 32*32 */
void MatrixcomM8to32(M8 m1, M8 m2, M8 m3, M8 m4, M32 *mat)
{
    int i;
    int j = 0;
    uint8_t *m;
    initM32(mat);
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 3) = m1.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 2) = m2.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 1) = m3.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *m = m4.M[i];
        j++;
    }
}
/* 4 vectors concatenation */
void VectorcomV8to32(V8 v1, V8 v2, V8 v3, V8 v4, V32 *vec)
{
    uint8_t *v;
    v = (uint8_t *)&(*vec).V;
    *(v + 3) = v1.V;
    *(v + 2) = v2.V;
    *(v + 1) = v3.V;
    *v = v4.V;
}
/* diagonal affine concatenation, four 8*8 -> 32*32 */
void affinecomM8to32(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32 *aff)
{
    MatrixcomM8to32(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV8to32(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
/* diagonal matrix concatenation, four 16*16 -> 64*64 */
void MatrixcomM16to64(M16 m1, M16 m2, M16 m3, M16 m4, M64 *mat)
{
    int i;
    int j = 0;
    uint16_t *m;
    initM64(mat);
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j];
        *(m + 3) = m1.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j];
        *(m + 2) = m2.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j];
        *(m + 1) = m3.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j];
        *m = m4.M[i];
        j++;
    }
}
/* 4 vectors concatenation */
void VectorcomV16to64(V16 v1, V16 v2, V16 v3, V16 v4, V64 *vec)
{
    uint16_t *v;
    v = (uint16_t *)&(*vec).V;
    *(v + 3) = v1.V;
    *(v + 2) = v2.V;
    *(v + 1) = v3.V;
    *v = v4.V;
}
/* diagonal affine concatenation,four 16*16 -> 64*64 */
void affinecomM16to64(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4,
                      Aff64 *aff)
{
    MatrixcomM16to64(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV16to64(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
/* diagonal matrix concatenation,four 8*8 -> 64*64 */
void MatrixcomM8to64(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8,
                     M64 *mat)
{
    int i;
    int j = 0;
    uint8_t *m;
    initM64(mat);
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 7) = m1.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 6) = m2.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 5) = m3.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 4) = m4.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 3) = m5.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 2) = m6.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *(m + 1) = m7.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j];
        *m = m8.M[i];
        j++;
    }
}
/* 8 vectors concatenation */
void VectorcomV8to64(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8,
                     V64 *vec)
{
    uint8_t *v;
    v = (uint8_t *)&(*vec).V;
    *(v + 7) = v1.V;
    *(v + 6) = v2.V;
    *(v + 5) = v3.V;
    *(v + 4) = v4.V;
    *(v + 3) = v5.V;
    *(v + 2) = v6.V;
    *(v + 1) = v7.V;
    *v = v8.V;
}
/* diagonal affine concatenation, four 8*8 -> 64*64 */
void affinecomM8to64(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5,
                     Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff64 *aff)
{
    MatrixcomM8to64(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, aff5.Mat, aff6.Mat,
                    aff7.Mat, aff8.Mat, &(aff->Mat));
    VectorcomV8to64(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, aff5.Vec, aff6.Vec,
                    aff7.Vec, aff8.Vec, &(aff->Vec));
}
/* diagonal matrix concatenation, four 32*32 -> 128*128 */
void MatrixcomM32to128(M32 m1, M32 m2, M32 m3, M32 m4, M128 *mat)
{
    int i;
    int j = 0;
    uint32_t *m;
    initM128(mat);
    for (i = 0; i < 32; i++) {
        m = (uint32_t *)&(*mat).M[j][0];
        *(m + 1) = m1.M[i];
        j++;
    }
    for (i = 0; i < 32; i++) {
        m = (uint32_t *)&(*mat).M[j][0];
        *m = m2.M[i];
        j++;
    }
    for (i = 0; i < 32; i++) {
        m = (uint32_t *)&(*mat).M[j][1];
        *(m + 1) = m3.M[i];
        j++;
    }
    for (i = 0; i < 32; i++) {
        m = (uint32_t *)&(*mat).M[j][1];
        *m = m4.M[i];
        j++;
    }
}
/* 4 vectors concatenation */
void VectorcomV32to128(V32 v1, V32 v2, V32 v3, V32 v4, V128 *vec)
{
    uint32_t *v;
    v = (uint32_t *)&(*vec).V[0];
    *(v + 1) = v1.V;
    *v = v2.V;
    v = (uint32_t *)&(*vec).V[1];
    *(v + 1) = v3.V;
    *v = v4.V;
}
/* diagonal affine concatenation, four 32*32 -> 128*128 */
void affinecomM32to128(Aff32 aff1, Aff32 aff2, Aff32 aff3, Aff32 aff4,
                       Aff128 *aff)
{
    MatrixcomM32to128(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV32to128(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
/* diagonal matrix concatenation, 16 8*8 -> 128*128 */
void MatrixcomM8to128(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8,
                      M8 m9, M8 m10, M8 m11, M8 m12, M8 m13, M8 m14, M8 m15,
                      M8 m16, M128 *mat)
{
    int i;
    int j = 0;
    uint8_t *m;
    initM128(mat);
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 7) = m1.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 6) = m2.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 5) = m3.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 4) = m4.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 3) = m5.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 2) = m6.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *(m + 1) = m7.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][0];
        *m = m8.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 7) = m9.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 6) = m10.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 5) = m11.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 4) = m12.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 3) = m13.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 2) = m14.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *(m + 1) = m15.M[i];
        j++;
    }
    for (i = 0; i < 8; i++) {
        m = (uint8_t *)&(*mat).M[j][1];
        *m = m16.M[i];
        j++;
    }
}
/* 16 vectors concatenation */
void VectorcomV8to128(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8,
                      V8 v9, V8 v10, V8 v11, V8 v12, V8 v13, V8 v14, V8 v15,
                      V8 v16, V128 *vec)
{
    uint8_t *v;
    v = (uint8_t *)&(*vec).V[0];
    *(v + 7) = v1.V;
    *(v + 6) = v2.V;
    *(v + 5) = v3.V;
    *(v + 4) = v4.V;
    *(v + 3) = v5.V;
    *(v + 2) = v6.V;
    *(v + 1) = v7.V;
    *v = v8.V;
    v = (uint8_t *)&(*vec).V[1];
    *(v + 7) = v9.V;
    *(v + 6) = v10.V;
    *(v + 5) = v11.V;
    *(v + 4) = v12.V;
    *(v + 3) = v13.V;
    *(v + 2) = v14.V;
    *(v + 1) = v15.V;
    *v = v16.V;
}
/* diagonal affine concatenation, 16 8*8 -> 128*128 */
void affinecomM8to128(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5,
                      Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff8 aff9, Aff8 aff10,
                      Aff8 aff11, Aff8 aff12, Aff8 aff13, Aff8 aff14,
                      Aff8 aff15, Aff8 aff16, Aff128 *aff)
{
    MatrixcomM8to128(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, aff5.Mat, aff6.Mat,
                     aff7.Mat, aff8.Mat, aff9.Mat, aff10.Mat, aff11.Mat,
                     aff12.Mat, aff13.Mat, aff14.Mat, aff15.Mat, aff16.Mat,
                     &(aff->Mat));
    VectorcomV8to128(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, aff5.Vec, aff6.Vec,
                     aff7.Vec, aff8.Vec, aff9.Vec, aff10.Vec, aff11.Vec,
                     aff12.Vec, aff13.Vec, aff14.Vec, aff15.Vec, aff16.Vec,
                     &(aff->Vec));
}
/* diagonal matrix concatenation, 8 16*16 -> 128*128 */
void MatrixcomM16to128(M16 m1, M16 m2, M16 m3, M16 m4, M16 m5, M16 m6, M16 m7,
                       M16 m8, M128 *mat)
{
    int i;
    int j = 0;
    uint16_t *m;
    initM128(mat);
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][0];
        *(m + 3) = m1.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][0];
        *(m + 2) = m2.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][0];
        *(m + 1) = m3.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][0];
        *m = m4.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][1];
        *(m + 3) = m5.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][1];
        *(m + 2) = m6.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][1];
        *(m + 1) = m7.M[i];
        j++;
    }
    for (i = 0; i < 16; i++) {
        m = (uint16_t *)&(*mat).M[j][1];
        *m = m8.M[i];
        j++;
    }
}
/* 8 vectors concatenation */
void VectorcomV16to128(V16 v1, V16 v2, V16 v3, V16 v4, V16 v5, V16 v6, V16 v7,
                       V16 v8, V128 *vec)
{
    uint16_t *v;
    v = (uint16_t *)&(*vec).V[0];
    *(v + 3) = v1.V;
    *(v + 2) = v2.V;
    *(v + 1) = v3.V;
    *v = v4.V;
    v = (uint16_t *)&(*vec).V[1];
    *(v + 3) = v5.V;
    *(v + 2) = v6.V;
    *(v + 1) = v7.V;
    *v = v8.V;
}
/* diagonal affine concatenation, 8 16*16 -> 128*128 */
void affinecomM16to128(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4,
                       Aff16 aff5, Aff16 aff6, Aff16 aff7, Aff16 aff8,
                       Aff128 *aff)
{
    MatrixcomM16to128(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, aff5.Mat,
                      aff6.Mat, aff7.Mat, aff8.Mat, &(aff->Mat));
    VectorcomV16to128(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, aff5.Vec,
                      aff6.Vec, aff7.Vec, aff8.Vec, &(aff->Vec));
}
void MattransM4(M4 Mat, M4 *Mat_trans) /* matrix tansposition M4 */
{
    int i, j;
    uint8_t mask[2], k, k2, l, temp;
    mask[0] = 0x5;
    mask[1] = 0x3;
    for (j = 0; j < 2; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 2; i++) {
            l = (k2 * i) % 3;
            temp = ((Mat.M[l] & ~mask[j]) ^ ((Mat.M[l + k] & ~mask[j]) >> k))
                   & 0x0f;
            Mat.M[l + k] = ((Mat.M[l + k] & mask[j]) ^
                            ((Mat.M[l] & mask[j]) << k)) & 0x0f;
            Mat.M[l] = temp;
        }
    }
    copyM4(Mat, Mat_trans);
}
void MattransM8(M8 Mat, M8 *Mat_trans) /* matrix tansposition M8 */
{
    int i, j;
    uint8_t mask[3], k, k2, l, temp;
    mask[0] = 0x55;
    mask[1] = 0x33;
    mask[2] = 0x0f;
    for (j = 0; j < 3; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 4; i++) {
            l = (k2 * i) % 7;
            temp = (Mat.M[l] & ~mask[j]) ^ ((Mat.M[l + k] & ~mask[j]) >> k);
            Mat.M[l + k] = (Mat.M[l + k] & mask[j]) ^
                           ((Mat.M[l] & mask[j]) << k);
            Mat.M[l] = temp;
        }
    }
    copyM8(Mat, Mat_trans);
}
void MattransM16(M16 Mat, M16 *Mat_trans) /* matrix tansposition M16 */
{
    int i, j;
    uint16_t mask[4], k, k2, l, temp;
    mask[0] = 0x5555;
    mask[1] = 0x3333;
    mask[2] = 0x0f0f;
    mask[3] = 0x00ff;
    for (j = 0; j < 4; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 8; i++) {
            l = (k2 * i) % 15;
            temp = (Mat.M[l] & ~mask[j]) ^ ((Mat.M[l + k] & ~mask[j]) >> k);
            Mat.M[l + k] = (Mat.M[l + k] & mask[j]) ^
                           ((Mat.M[l] & mask[j]) << k);
            Mat.M[l] = temp;
        }
    }
    copyM16(Mat, Mat_trans);
}
void MattransM32(M32 Mat, M32 *Mat_trans) /* matrix tansposition M32 */
{
    int i, j;
    uint32_t mask[5], k, k2, l, temp;
    mask[0] = 0x55555555;
    mask[1] = 0x33333333;
    mask[2] = 0x0f0f0f0f;
    mask[3] = 0x00ff00ff;
    mask[4] = 0x0000ffff;
    for (j = 0; j < 5; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 16; i++) {
            l = (k2 * i) % 31;
            temp = (Mat.M[l] & ~mask[j]) ^ ((Mat.M[l + k] & ~mask[j]) >> k);
            Mat.M[l + k] = (Mat.M[l + k] & mask[j]) ^
                           ((Mat.M[l] & mask[j]) << k);
            Mat.M[l] = temp;
        }
    }
    copyM32(Mat, Mat_trans);
}
void MattransM64(M64 Mat, M64 *Mat_trans) /* matrix tansposition M64 */
{
    int i, j;
    uint64_t mask[6], k, k2, l, temp;
    mask[0] = 0x5555555555555555;
    mask[1] = 0x3333333333333333;
    mask[2] = 0x0f0f0f0f0f0f0f0f;
    mask[3] = 0x00ff00ff00ff00ff;
    mask[4] = 0x0000ffff0000ffff;
    mask[5] = 0x00000000ffffffff;
    for (j = 0; j < 6; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 32; i++) {
            l = (k2 * i) % 63;
            temp = (Mat.M[l] & ~mask[j]) ^ ((Mat.M[l + k] & ~mask[j]) >> k);
            Mat.M[l + k] = (Mat.M[l + k] & mask[j]) ^
                           ((Mat.M[l] & mask[j]) << k);
            Mat.M[l] = temp;
        }
    }
    copyM64(Mat, Mat_trans);
}
void MattransM128(M128 Mat, M128 *Mat_trans) /* matrix tansposition M128 */
{
    int i, j;
    uint64_t mask[6], k, k2, l, temp;
    mask[0] = 0x5555555555555555;
    mask[1] = 0x3333333333333333;
    mask[2] = 0x0f0f0f0f0f0f0f0f;
    mask[3] = 0x00ff00ff00ff00ff;
    mask[4] = 0x0000ffff0000ffff;
    mask[5] = 0x00000000ffffffff;
    for (j = 0; j < 6; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 64; i++) {
            l = (k2 * i) % 127;
            temp = (Mat.M[l][0] & ~mask[j]) ^
                   ((Mat.M[l + k][0] & ~mask[j]) >> k);
            Mat.M[l + k][0] = (Mat.M[l + k][0] & mask[j]) ^
                              ((Mat.M[l][0] & mask[j]) << k);
            Mat.M[l][0] = temp;

            temp = (Mat.M[l][1] & ~mask[j]) ^
                   ((Mat.M[l + k][1] & ~mask[j]) >> k);
            Mat.M[l + k][1] = (Mat.M[l + k][1] & mask[j]) ^
                              ((Mat.M[l][1] & mask[j]) << k);
            Mat.M[l][1] = temp;
        }
    }
    for (i = 0; i < 64; i++) {
        temp = Mat.M[i + 64][0];
        Mat.M[i + 64][0] = Mat.M[i][1];
        Mat.M[i][1] = temp;
    }
    copyM128(Mat, Mat_trans);
}
void MattransM256(M256 Mat, M256 *Mat_trans) /* matrix tansposition M128 */
{
    int i, j;
    uint64_t mask[6], k, k2, l, temp;
    mask[0] = 0x5555555555555555;
    mask[1] = 0x3333333333333333;
    mask[2] = 0x0f0f0f0f0f0f0f0f;
    mask[3] = 0x00ff00ff00ff00ff;
    mask[4] = 0x0000ffff0000ffff;
    mask[5] = 0x00000000ffffffff;
    for (j = 0; j < 6; j++) {
        k = 1 << j;
        k2 = k * 2;
        for (i = 0; i < 128; i++) {
            l = (k2 * i) % 255;
            temp = (Mat.M[l][0] & ~mask[j]) ^
                   ((Mat.M[l + k][0] & ~mask[j]) >> k);
            Mat.M[l + k][0] = (Mat.M[l + k][0] & mask[j]) ^
                              ((Mat.M[l][0] & mask[j]) << k);
            Mat.M[l][0] = temp;

            temp = (Mat.M[l][1] & ~mask[j]) ^
                   ((Mat.M[l + k][1] & ~mask[j]) >> k);
            Mat.M[l + k][1] = (Mat.M[l + k][1] & mask[j]) ^
                              ((Mat.M[l][1] & mask[j]) << k);
            Mat.M[l][1] = temp;

            temp = (Mat.M[l][2] & ~mask[j]) ^
                   ((Mat.M[l + k][2] & ~mask[j]) >> k);
            Mat.M[l + k][2] = (Mat.M[l + k][2] & mask[j]) ^
                              ((Mat.M[l][2] & mask[j]) << k);
            Mat.M[l][2] = temp;

            temp = (Mat.M[l][3] & ~mask[j]) ^
                   ((Mat.M[l + k][3] & ~mask[j]) >> k);
            Mat.M[l + k][3] = (Mat.M[l + k][3] & mask[j]) ^
                              ((Mat.M[l][3] & mask[j]) << k);
            Mat.M[l][3] = temp;
        }
    }
    for (i = 0; i < 64; i++) {
        temp = Mat.M[i + 64][0];
        Mat.M[i + 64][0] = Mat.M[i][1];
        Mat.M[i][1] = temp;

        temp = Mat.M[i + 64][2];
        Mat.M[i + 64][2] = Mat.M[i][3];
        Mat.M[i][3] = temp;

        temp = Mat.M[i + 192][0];
        Mat.M[i + 192][0] = Mat.M[i + 128][1];
        Mat.M[i + 128][1] = temp;

        temp = Mat.M[i + 192][2];
        Mat.M[i + 192][2] = Mat.M[i + 128][3];
        Mat.M[i + 128][3] = temp;
    }
    for (i = 0; i < 128; i++) {
        temp = Mat.M[i + 128][0];
        Mat.M[i + 128][0] = Mat.M[i][2];
        Mat.M[i][2] = temp;

        temp = Mat.M[i + 128][1];
        Mat.M[i + 128][1] = Mat.M[i][3];
        Mat.M[i][3] = temp;
    }
    copyM256(Mat, Mat_trans);
}
void MatAddMatM4(M4 Mat1, M4 Mat2, M4 *Mat)
{
    int i;
    for (i = 0; i < 4; i++) {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM8(M8 Mat1, M8 Mat2, M8 *Mat)
{
    int i;
    for (i = 0; i < 8; i++) {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM16(M16 Mat1, M16 Mat2, M16 *Mat)
{
    int i;
    for (i = 0; i < 16; i++) {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM32(M32 Mat1, M32 Mat2, M32 *Mat)
{
    int i;
    for (i = 0; i < 32; i++) {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM64(M64 Mat1, M64 Mat2, M64 *Mat)
{
    int i;
    for (i = 0; i < 64; i++) {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}
void MatAddMatM128(M128 Mat1, M128 Mat2, M128 *Mat)
{
    int i;
    for (i = 0; i < 128; i++) {
        (*Mat).M[i][0] = Mat1.M[i][0] ^ Mat2.M[i][0];
        (*Mat).M[i][1] = Mat1.M[i][1] ^ Mat2.M[i][1];
    }
}
void MatAddMatM256(M256 Mat1, M256 Mat2, M256 *Mat)
{
    for (int i = 0; i < 256; i++) {
        (*Mat).M[i][0] = Mat1.M[i][0] ^ Mat2.M[i][0];
        (*Mat).M[i][1] = Mat1.M[i][1] ^ Mat2.M[i][1];
        (*Mat).M[i][2] = Mat1.M[i][2] ^ Mat2.M[i][2];
        (*Mat).M[i][3] = Mat1.M[i][3] ^ Mat2.M[i][3];
    }
}
/* matrix multiplication 4*4 mul 4*4 -> 4*4 */
void MatMulMatM4(M4 Mat1, M4 Mat2, M4 *Mat)
{
    int i, j;
    M4 Mat2_trans;
    initM4(Mat);
    MattransM4(Mat2, &Mat2_trans);
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            if (xorU4(Mat1.M[i] & Mat2_trans.M[j] & 0x0f))
                (*Mat).M[i] ^= idM4[j];
        }
    }
}
/* matrix multiplication 8*8 mul 8*8 -> 8*8 */
void MatMulMatM8(M8 Mat1, M8 Mat2, M8 *Mat)
{
    int i, j;
    M8 Mat2_trans;
    initM8(Mat);
    MattransM8(Mat2, &Mat2_trans);
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (xorU8(Mat1.M[i] & Mat2_trans.M[j]))
                (*Mat).M[i] ^= idM8[j];
        }
    }
}
/* matrix multiplication 16*16 mul 16*16 -> 16*16 */
void MatMulMatM16(M16 Mat1, M16 Mat2, M16 *Mat)
{
    int i, j;
    M16 Mat2_trans;
    initM16(Mat);
    MattransM16(Mat2, &Mat2_trans);
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            if (xorU16(Mat1.M[i] & Mat2_trans.M[j]))
                (*Mat).M[i] ^= idM16[j];
        }
    }
}
/* matrix multiplication 32*32 mul 32*32 -> 32*32 */
void MatMulMatM32(M32 Mat1, M32 Mat2, M32 *Mat)
{
    int i, j;
    M32 Mat2_trans;
    initM32(Mat);
    MattransM32(Mat2, &Mat2_trans);
    for (i = 0; i < 32; i++) {
        for (j = 0; j < 32; j++) {
            if (xorU32(Mat1.M[i] & Mat2_trans.M[j]))
                (*Mat).M[i] ^= idM32[j];
        }
    }
}
/* matrix multiplication 64*64 mul 64*64 -> 64*64 */
void MatMulMatM64(M64 Mat1, M64 Mat2, M64 *Mat)
{
    int i, j;
    M64 Mat2_trans;
    initM64(Mat);
    MattransM64(Mat2, &Mat2_trans);
    for (i = 0; i < 64; i++) {
        for (j = 0; j < 64; j++) {
            if (xorU64(Mat1.M[i] & Mat2_trans.M[j]))
                (*Mat).M[i] ^= idM64[j];
        }
    }
}
/* matrix multiplication 128*128 mul 128*128 -> 128*128 */
void MatMulMatM128(M128 Mat1, M128 Mat2, M128 *Mat)
{
    int i, j;
    M128 Mat2_trans;
    uint64_t temp[2];
    initM128(Mat);
    MattransM128(Mat2, &Mat2_trans);
    for (i = 0; i < 128; i++) {
        for (j = 0; j < 64; j++) {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            if (xorU128(temp))
                (*Mat).M[i][0] ^= idM64[j];
        }
        for (j = 64; j < 128; j++) {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            if (xorU128(temp))
                (*Mat).M[i][1] ^= idM64[j - 64];
        }
    }
}
/* matrix multiplication 256*256 mul 256*256 -> 256*256 */
void MatMulMatM256(M256 Mat1, M256 Mat2, M256 *Mat)
{
    int i, j;
    M256 Mat2_trans;
    uint64_t temp[4];
    initM256(Mat);
    MattransM256(Mat2, &Mat2_trans);
    for (i = 0; i < 256; i++) {
        for (j = 0; j < 64; j++) {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            temp[2] = Mat1.M[i][2] & Mat2_trans.M[j][2];
            temp[3] = Mat1.M[i][3] & Mat2_trans.M[j][3];
            if (xorU256(temp))
                (*Mat).M[i][0] ^= idM64[j];
        }
        for (j = 64; j < 128; j++) {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            temp[2] = Mat1.M[i][2] & Mat2_trans.M[j][2];
            temp[3] = Mat1.M[i][3] & Mat2_trans.M[j][3];
            if (xorU256(temp))
                (*Mat).M[i][1] ^= idM64[j - 64];
        }
        for (j = 128; j < 192; j++) {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            temp[2] = Mat1.M[i][2] & Mat2_trans.M[j][2];
            temp[3] = Mat1.M[i][3] & Mat2_trans.M[j][3];
            if (xorU256(temp))
                (*Mat).M[i][2] ^= idM64[j - 128];
        }
        for (j = 192; j < 256; j++) {
            temp[0] = Mat1.M[i][0] & Mat2_trans.M[j][0];
            temp[1] = Mat1.M[i][1] & Mat2_trans.M[j][1];
            temp[2] = Mat1.M[i][2] & Mat2_trans.M[j][2];
            temp[3] = Mat1.M[i][3] & Mat2_trans.M[j][3];
            if (xorU256(temp))
                (*Mat).M[i][3] ^= idM64[j - 192];
        }
    }
}
/* mixed transformation of (previous affine inversion) and this round affine */
void affinemixM4(Aff4 aff, Aff4 preaff_inv, Aff4 *mixaff) 
{
    MatMulMatM4(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM4(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
/* mixed transformation of (previous affine inversion) and this round affine */
void affinemixM8(Aff8 aff, Aff8 preaff_inv, Aff8 *mixaff)
{
    MatMulMatM8(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM8(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
/* mixed transformation of (previous affine inversion) and this round affine */
void affinemixM16(Aff16 aff, Aff16 preaff_inv, Aff16 *mixaff)
{
    MatMulMatM16(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM16(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
/* mixed transformation of (previous affine inversion) and this round affine */
void affinemixM32(Aff32 aff, Aff32 preaff_inv, Aff32 *mixaff)
{
    MatMulMatM32(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM32(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
/* mixed transformation of (previous affine inversion) and this round affine */
void affinemixM64(Aff64 aff, Aff64 preaff_inv, Aff64 *mixaff)
{
    MatMulMatM64(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM64(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V ^= aff.Vec.V;
}
/* mixed transformation of (previous affine inversion) and this round affine */
void affinemixM128(Aff128 aff, Aff128 preaff_inv, Aff128 *mixaff)
{
    MatMulMatM128(aff.Mat, preaff_inv.Mat, &(mixaff->Mat));
    MatMulVecM128(aff.Mat, preaff_inv.Vec, &(mixaff->Vec));
    (*mixaff).Vec.V[0] ^= aff.Vec.V[0];
    (*mixaff).Vec.V[1] ^= aff.Vec.V[1];
}
