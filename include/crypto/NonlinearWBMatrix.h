/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
unsigned int permuteQPR(unsigned int x);
void InitRandom(unsigned int seedBase);
unsigned int cus_random(void);
typedef struct Nonlinear8 {
    uint8_t mapping[256];
} Nonlinear8;
/* 32 位非线性双射结构体，由 4 个 Nonlinear8 组成*/
typedef struct Nonlinear32 {
    Nonlinear8 n8_1;  
    Nonlinear8 n8_2;  
    Nonlinear8 n8_3;  
    Nonlinear8 n8_4;  
} Nonlinear32;

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

void randM8(M8 *Mat);
void identityM8(M8 *Mat);
void copyM8(M8 Mat1, M8 *Mat2);
void initV8(V8 *Vec);
void randV8(V8 *Vec);
uint8_t affineU8(Aff8 aff, uint8_t arr);
int xorU8(uint8_t n);
void MatMulVecM8(M8 Mat,V8 Vec, V8 *ans);
void genMatpairM8(M8 *Mat, M8 *Mat_inv);
void genaffinepairM8(Aff8 *aff, Aff8 *aff_inv);
int xorU16(uint16_t n);
void initM32(M32 *Mat);
void initV32(V32 *Vec);
uint32_t affineU32(Aff32 aff, uint32_t arr);
int xorU32(uint32_t n);
void MatMulVecM32(M32 Mat, V32 Vec, V32 *ans);
uint32_t MatMulNumM32(M32 Mat, uint32_t n);
void MatrixcomM8to32(M8 m1, M8 m2, M8 m3, M8 m4, M32 *mat);
void VectorcomV8to32(V8 v1, V8 v2, V8 v3, V8 v4, V32 *vec);
void affinecomM8to32(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32 *aff);

#ifdef __cplusplus
}
#endif
