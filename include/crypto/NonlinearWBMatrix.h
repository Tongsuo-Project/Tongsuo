/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
unsigned int permuteQPR_1(unsigned int x);
void InitRandom_1(unsigned int seedBase);
unsigned int cus_random_1(void);
typedef struct Nonlinear8 {
    uint8_t mapping[256];
} Nonlinear8;
/* 32 位非线性双射结构体，由 4 个 Nonlinear8 组成  */
typedef struct Nonlinear32 {
    Nonlinear8 n8_1;  /* 第一个 8-bit 映射*/
    Nonlinear8 n8_2;  /* 第二个 8-bit 映射*/
    Nonlinear8 n8_3;  /*第三个 8-bit 映射*/
    Nonlinear8 n8_4;  /*第四个 8-bit 映射*/
} Nonlinear32;

/*8bits   */
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
#ifdef __cplusplus
extern "C"
{
#endif

void randM8_1(M8 *Mat);
void identityM8_1(M8 *Mat);
void copyM8_1(M8 Mat1, M8 *Mat2);
void initV8_1(V8 *Vec);
void randV8_1(V8 *Vec);
uint8_t affineU8_1(Aff8 aff, uint8_t arr);
int xorU8_1(uint8_t n);
void MatMulVecM8_1(M8 Mat,V8 Vec, V8 *ans);
void genMatpairM8_1(M8 *Mat, M8 *Mat_inv);
void genaffinepairM8_1(Aff8 *aff, Aff8 *aff_inv);
int xorU16_1(uint16_t n);
void initM32_1(M32 *Mat);
void initV32_1(V32 *Vec);
uint32_t affineU32_1(Aff32 aff, uint32_t arr);
int xorU32_1(uint32_t n);
void MatMulVecM32_1(M32 Mat, V32 Vec, V32 *ans);
uint32_t MatMulNumM32_1(M32 Mat, uint32_t n);
void MatrixcomM8to32_1(M8 m1, M8 m2, M8 m3, M8 m4, M32 *mat);
void VectorcomV8to32_1(V8 v1, V8 v2, V8 v3, V8 v4, V32 *vec);
void affinecomM8to32_1(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32 *aff);

#ifdef __cplusplus
}
#endif
