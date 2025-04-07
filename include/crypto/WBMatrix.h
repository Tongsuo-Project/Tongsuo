/*
* Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
* Copyright 2024 Nexus-TYF. All Rights Reserved.
* Ported from Nexus-TYF/WBMatrix.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
*/
#ifndef _HWBMATRIX_H_
#define _HWBMATRIX_H_
/***
 * Last Update: 2020/08/24
 * Version: 3.2.0
***/
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* 4bits */
typedef struct M4
{
    uint8_t M[4];
}M4;

typedef struct V4
{
    uint8_t V;
}V4;

typedef struct Aff4
{
    M4 Mat;
    V4 Vec;
}Aff4;

/* 8bits */
typedef struct M8
{
    uint8_t M[8];
}M8;

typedef struct V8
{
    uint8_t V;
}V8;

typedef struct Aff8
{
    M8 Mat;
    V8 Vec;
}Aff8;
/* 16bits */
typedef struct M16
{
    uint16_t M[16];
}M16;

typedef struct V16
{
    uint16_t V;
}V16;

typedef struct Aff16
{
    M16 Mat;
    V16 Vec;
}Aff16;
/* 32bits */
typedef struct M32
{
    uint32_t M[32];
}M32;

typedef struct V32
{
    uint32_t V;
}V32;

typedef struct Aff32
{
    M32 Mat;
    V32 Vec;
}Aff32;
/* 64bits */
typedef struct M64
{
    uint64_t M[64];
}M64;

typedef struct V64
{
    uint64_t V;
}V64;

typedef struct Aff64
{
    M64 Mat;
    V64 Vec;
}Aff64;
/* 128bits */
typedef struct M128
{
    uint64_t M[128][2];
}M128;

typedef struct V128
{
    uint64_t V[2];
}V128;

typedef struct Aff128
{
    M128 Mat;
    V128 Vec;
}Aff128;

void wb_xiao_dy_InitRandom(unsigned int seedBase);
unsigned int wb_xiao_dy_cus_random(void);


/* Set random seed */
void wb_xiao_dy_SetRandSeed(unsigned int seed);

/*
* 4bit Matrix operation
*/

void wb_xiao_dy_initM4(M4 *Mat);
void wb_xiao_dy_randM4(M4 *Mat);
void wb_xiao_dy_identityM4(M4 *Mat);
void wb_xiao_dy_printM4(M4 Mat);
void wb_xiao_dy_printbitM4(M4 Mat);
void wb_xiao_dy_copyM4(M4 Mat1, M4 *Mat2);
int wb_xiao_dy_isequalM4(M4 Mat1, M4 Mat2);
int wb_xiao_dy_isinvertM4(M4 Mat);
void wb_xiao_dy_invsM4(M4 Mat, M4 *Mat_inv);
int wb_xiao_dy_readbitM4(M4 Mat, int i, int j);
void wb_xiao_dy_flipbitM4(M4 *Mat, int i, int j);
void wb_xiao_dy_setbitM4(M4 *Mat, int i, int j, int bit);

void wb_xiao_dy_initV4(V4 *Vec);
void wb_xiao_dy_randV4(V4 *Vec);
void wb_xiao_dy_printV4(V4 Vec);
int wb_xiao_dy_isequalV4(V4 Vec1, V4 Vec2);
void wb_xiao_dy_VecAddVecV4(V4 Vec1, V4 Vec2, V4 *Vec);

uint8_t wb_xiao_dy_affineU4(Aff4 aff, uint8_t arr);
int wb_xiao_dy_xorU4(uint8_t n);
int wb_xiao_dy_HWU4(uint8_t n);

void wb_xiao_dy_MatMulVecM4(M4 Mat,V4 Vec, V4 *ans);
uint8_t wb_xiao_dy_MatMulNumM4(M4 Mat, uint8_t n);
void wb_xiao_dy_MatMulMatM4(M4 Mat1, M4 Mat2, M4 *Mat);
void wb_xiao_dy_MatAddMatM4(M4 Mat1, M4 Mat2, M4 *Mat);
void wb_xiao_dy_MattransM4(M4 Mat, M4 *Mat_trans);

void wb_xiao_dy_genMatpairM4(M4 *Mat, M4 *Mat_inv);
void wb_xiao_dy_genaffinepairM4(Aff4 *aff, Aff4 *aff_inv);
void wb_xiao_dy_affinemixM4(Aff4 aff, Aff4 preaff_inv, Aff4 *mixaff);

/*
* 8bit Matrix operation
*/

void wb_xiao_dy_initM8(M8 *Mat);
void wb_xiao_dy_randM8(M8 *Mat);
void wb_xiao_dy_identityM8(M8 *Mat);
void wb_xiao_dy_printM8(M8 Mat);
void wb_xiao_dy_printbitM8(M8 Mat);
void wb_xiao_dy_copyM8(M8 Mat1, M8 *Mat2);
int wb_xiao_dy_isequalM8(M8 Mat1, M8 Mat2);
int wb_xiao_dy_isinvertM8(M8 Mat);
void wb_xiao_dy_invsM8(M8 Mat, M8 *Mat_inv);
int wb_xiao_dy_readbitM8(M8 Mat, int i, int j);
void wb_xiao_dy_flipbitM8(M8 *Mat, int i, int j);
void wb_xiao_dy_setbitM8(M8 *Mat, int i, int j, int bit);

void wb_xiao_dy_initV8(V8 *Vec);
void wb_xiao_dy_randV8(V8 *Vec);
void wb_xiao_dy_printV8(V8 Vec);
int wb_xiao_dy_isequalV8(V8 Vec1, V8 Vec2);
void wb_xiao_dy_VecAddVecV8(V8 Vec1, V8 Vec2, V8 *Vec);

uint8_t wb_xiao_dy_affineU8(Aff8 aff, uint8_t arr);
int wb_xiao_dy_xorU8(uint8_t n);
int wb_xiao_dy_HWU8(uint8_t n);
void wb_xiao_dy_printU8(uint8_t n);

void wb_xiao_dy_MatMulVecM8(M8 Mat,V8 Vec, V8 *ans);
uint8_t wb_xiao_dy_MatMulNumM8(M8 Mat, uint8_t n);
void wb_xiao_dy_MatMulMatM8(M8 Mat1, M8 Mat2, M8 *Mat);
void wb_xiao_dy_MatAddMatM8(M8 Mat1, M8 Mat2, M8 *Mat);
void wb_xiao_dy_MattransM8(M8 Mat, M8 *Mat_trans);

void wb_xiao_dy_genMatpairM8(M8 *Mat, M8 *Mat_inv);
void wb_xiao_dy_genaffinepairM8(Aff8 *aff, Aff8 *aff_inv);
void wb_xiao_dy_affinemixM8(Aff8 aff, Aff8 preaff_inv, Aff8 *mixaff);

/*
* 16bit Matrix operation
*/

void wb_xiao_dy_initM16(M16 *Mat);
void wb_xiao_dy_randM16(M16 *Mat);
void wb_xiao_dy_identityM16(M16 *Mat);
void wb_xiao_dy_printM16(M16 Mat);
void wb_xiao_dy_printbitM16(M16 Mat);
void wb_xiao_dy_copyM16(M16 Mat1, M16 *Mat2);
int wb_xiao_dy_isequalM16(M16 Mat1, M16 Mat2);
int wb_xiao_dy_isinvertM16(M16 Mat);
void wb_xiao_dy_invsM16(M16 Mat, M16 *Mat_inv);
int wb_xiao_dy_readbitM16(M16 Mat, int i, int j);
void wb_xiao_dy_flipbitM16(M16 *Mat, int i, int j);
void wb_xiao_dy_setbitM16(M16 *Mat, int i, int j, int bit);

void wb_xiao_dy_initV16(V16 *Vec);
void wb_xiao_dy_randV16(V16 *Vec);
void wb_xiao_dy_printV16(V16 Vec);
int wb_xiao_dy_isequalV16(V16 Vec1, V16 Vec2);
void wb_xiao_dy_VecAddVecV16(V16 Vec1, V16 Vec2, V16 *Vec);

uint16_t wb_xiao_dy_affineU16(Aff16 aff, uint16_t arr);
int wb_xiao_dy_xorU16(uint16_t n);
int wb_xiao_dy_HWU16(uint16_t n);
void wb_xiao_dy_printU16(uint16_t n);
void wb_xiao_dy_MatAddMatM16(M16 Mat1, M16 Mat2, M16 *Mat);
void wb_xiao_dy_MatMulVecM16(M16 Mat, V16 Vec, V16 *ans);
uint16_t wb_xiao_dy_MatMulNumM16(M16 Mat, uint16_t n);
void wb_xiao_dy_MatMulMatM16(M16 Mat1, M16 Mat2, M16 *Mat);
void wb_xiao_dy_MattransM16(M16 Mat, M16 *Mat_trans);

void wb_xiao_dy_genMatpairM16(M16 *Mat, M16 *Mat_inv);
void wb_xiao_dy_genaffinepairM16(Aff16 *aff, Aff16 *aff_inv);
void wb_xiao_dy_affinemixM16(Aff16 aff, Aff16 preaff_inv, Aff16 *mixaff);

/*
* 32bit Matrix operation
*/

void wb_xiao_dy_initM32(M32 *Mat);
void wb_xiao_dy_randM32(M32 *Mat);
void wb_xiao_dy_identityM32(M32 *Mat);
void wb_xiao_dy_printM32(M32 Mat);
void wb_xiao_dy_printbitM32(M32 Mat);
void wb_xiao_dy_copyM32(M32 Mat1, M32 *Mat2);
int wb_xiao_dy_isequalM32(M32 Mat1, M32 Mat2);
int wb_xiao_dy_isinvertM32(M32 Mat);
void wb_xiao_dy_invsM32(M32 Mat, M32 *Mat_inv);
int wb_xiao_dy_readbitM32(M32 Mat, int i, int j);
void wb_xiao_dy_flipbitM32(M32 *Mat, int i, int j);
void wb_xiao_dy_setbitM32(M32 *Mat, int i, int j, int bit);

void wb_xiao_dy_initV32(V32 *Vec);
void wb_xiao_dy_randV32(V32 *Vec);
void wb_xiao_dy_printV32(V32 Vec);
int wb_xiao_dy_isequalV32(V32 Vec1, V32 Vec2);
void wb_xiao_dy_VecAddVecV32(V32 Vec1, V32 Vec2, V32 *Vec);

uint32_t wb_xiao_dy_affineU32(Aff32 aff, uint32_t arr);
int wb_xiao_dy_xorU32(uint32_t n);
int wb_xiao_dy_HWU32(uint32_t n);
void wb_xiao_dy_printU32(uint32_t n);

void wb_xiao_dy_MatMulVecM32(M32 Mat, V32 Vec, V32 *ans);
uint32_t wb_xiao_dy_MatMulNumM32(M32 Mat, uint32_t n);
void wb_xiao_dy_MatMulMatM32(M32 Mat1, M32 Mat2, M32 *Mat);
void wb_xiao_dy_MatAddMatM32(M32 Mat1, M32 Mat2, M32 *Mat);
void wb_xiao_dy_MattransM32(M32 Mat, M32 *Mat_trans);

void wb_xiao_dy_genMatpairM32(M32 *Mat, M32 *Mat_inv);
void wb_xiao_dy_genaffinepairM32(Aff32 *aff, Aff32 *aff_inv);
void wb_xiao_dy_affinemixM32(Aff32 aff, Aff32 preaff_inv, Aff32 *mixaff);
void wb_xiao_dy_MatrixcomM8to32(M8 m1, M8 m2, M8 m3, M8 m4, M32 *mat);
void wb_xiao_dy_VectorcomV8to32(V8 v1, V8 v2, V8 v3, V8 v4, V32 *vec);
void wb_xiao_dy_affinecomM8to32(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32 *aff);

/*
* 64bit Matrix operation
*/

void wb_xiao_dy_initM64(M64 *Mat);
void wb_xiao_dy_randM64(M64 *Mat);
void wb_xiao_dy_identityM64(M64 *Mat);
void wb_xiao_dy_printM64(M64 Mat);
void wb_xiao_dy_printbitM64(M64 Mat);
void wb_xiao_dy_copyM64(M64 Mat1, M64 *Mat2);
int wb_xiao_dy_isequalM64(M64 Mat1, M64 Mat2);
int wb_xiao_dy_isinvertM64(M64 Mat);
void wb_xiao_dy_invsM64(M64 Mat, M64 *Mat_inv);
int wb_xiao_dy_readbitM64(M64 Mat, int i, int j);
void wb_xiao_dy_flipbitM64(M64 *Mat, int i, int j);
void wb_xiao_dy_setbitM64(M64 *Mat, int i, int j, int bit);

void wb_xiao_dy_initV64(V64 *Vec);
void wb_xiao_dy_randV64(V64 *Vec);
void wb_xiao_dy_printV64(V64 Vec);
int wb_xiao_dy_isequalV64(V64 Vec1, V64 Vec2);
void wb_xiao_dy_VecAddVecV64(V64 Vec1, V64 Vec2, V64 *Vec);

uint64_t wb_xiao_dy_affineU64(Aff64 aff, uint64_t arr);
int wb_xiao_dy_xorU64(uint64_t n);
int wb_xiao_dy_HWU64(uint64_t n);
void wb_xiao_dy_printU64(uint64_t n);

void wb_xiao_dy_MatMulVecM64(M64 Mat, V64 Vec, V64 *ans);
uint64_t wb_xiao_dy_MatMulNumM64(M64 Mat, uint64_t n);
void wb_xiao_dy_MatMulMatM64(M64 Mat1, M64 Mat2, M64 *Mat);
void wb_xiao_dy_MattransM64(M64 Mat, M64 *Mat_trans);

void wb_xiao_dy_MatAddMatM64(M64 Mat1, M64 Mat2, M64 *Mat);
void wb_xiao_dy_genMatpairM64(M64 *Mat, M64 *Mat_inv);
void wb_xiao_dy_genaffinepairM64(Aff64 *aff, Aff64 *aff_inv);
void wb_xiao_dy_affinemixM64(Aff64 aff, Aff64 preaff_inv, Aff64 *mixaff);

void wb_xiao_dy_MatrixcomM16to64(M16 m1, M16 m2, M16 m3, M16 m4, M64 *mat);
void wb_xiao_dy_VectorcomV16to64(V16 v1, V16 v2, V16 v3, V16 v4, V64 *vec);
void wb_xiao_dy_affinecomM16to64(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4, Aff64 *aff);
void wb_xiao_dy_MatrixcomM8to64(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8, M64 *mat);
void wb_xiao_dy_VectorcomV8to64(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8, V64 *vec);
void wb_xiao_dy_affinecomM8to64(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5, Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff64 *aff);

/*
* 128bit Matrix operation
*/

void wb_xiao_dy_initM128(M128 *Mat);
void wb_xiao_dy_randM128(M128 *Mat);
void wb_xiao_dy_identityM128(M128 *Mat);
void wb_xiao_dy_printM128(M128 Mat);
void wb_xiao_dy_printbitM128(M128 Mat);
void wb_xiao_dy_copyM128(M128 Mat1, M128 *Mat2);
int wb_xiao_dy_isequalM128(M128 Mat1, M128 Mat2);
int wb_xiao_dy_isinvertM128(M128 Mat);
void wb_xiao_dy_invsM128(M128 Mat, M128 *Mat_inv);
int wb_xiao_dy_readbitM128(M128 Mat, int i, int j);
void wb_xiao_dy_flipbitM128(M128 *Mat, int i, int j);
void wb_xiao_dy_setbitM128(M128 *Mat, int i, int j, int bit);

void wb_xiao_dy_initV128(V128 *Vec);
void wb_xiao_dy_randV128(V128 *Vec);
void wb_xiao_dy_printV128(V128 Vec);

void wb_xiao_dy_affineU128(Aff128 aff, uint64_t arr[], uint64_t ans[]);
int wb_xiao_dy_xorU128(uint64_t n[]);
int wb_xiao_dy_HWU128(uint64_t n[]);
void wb_xiao_dy_printU128(uint64_t n[]);
int wb_xiao_dy_isequalV128(V128 Vec1, V128 Vec2);
void wb_xiao_dy_VecAddVecV128(V128 Vec1, V128 Vec2, V128 *Vec);

void wb_xiao_dy_MatMulVecM128(M128 Mat, V128 Vec, V128 *ans);
void wb_xiao_dy_MatMulMatM128(M128 Mat1, M128 Mat2, M128 *Mat);
void wb_xiao_dy_MattransM128(M128 Mat, M128 *Mat_trans);

void wb_xiao_dy_MatAddMatM128(M128 Mat1, M128 Mat2, M128 *Mat);
void wb_xiao_dy_genMatpairM128(M128 *Mat, M128 *Mat_inv);
void wb_xiao_dy_genaffinepairM128(Aff128 *aff, Aff128 *aff_inv);
void wb_xiao_dy_affinemixM128(Aff128 aff, Aff128 preaff_inv, Aff128 *mixaff);

void wb_xiao_dy_MatrixcomM32to128(M32 m1, M32 m2, M32 m3, M32 m4, M128 *mat);
void wb_xiao_dy_VectorcomV32to128(V32 v1, V32 v2, V32 v3, V32 v4, V128 *vec);
void wb_xiao_dy_affinecomM32to128(Aff32 aff1, Aff32 aff2, Aff32 aff3, Aff32 aff4, Aff128 *aff);
void wb_xiao_dy_MatrixcomM8to128(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8, M8 m9, M8 m10, M8 m11, M8 m12, M8 m13, M8 m14, M8 m15, M8 m16, M128 *mat);
void wb_xiao_dy_VectorcomV8to128(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8, V8 v9, V8 v10, V8 v11, V8 v12, V8 v13, V8 v14, V8 v15, V8 v16, V128 *vec);
void wb_xiao_dy_affinecomM8to128(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5, Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff8 aff9, Aff8 aff10, Aff8 aff11, Aff8 aff12, Aff8 aff13, Aff8 aff14, Aff8 aff15, Aff8 aff16, Aff128 *aff);
void wb_xiao_dy_MatrixcomM16to128(M16 m1, M16 m2, M16 m3, M16 m4, M16 m5, M16 m6, M16 m7, M16 m8, M128 *mat);
void wb_xiao_dy_VectorcomV16to128(V16 v1, V16 v2, V16 v3, V16 v4, V16 v5, V16 v6, V16 v7, V16 v8, V128 *vec);
void wb_xiao_dy_affinecomM16to128(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4, Aff16 aff5, Aff16 aff6, Aff16 aff7, Aff16 aff8, Aff128 *aff);

#ifdef __cplusplus
}
#endif

#endif
