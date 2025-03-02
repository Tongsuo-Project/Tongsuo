//
// Created by fuyu on 2025-03-01.
//
#include "stdint.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
unsigned int permuteQPR(unsigned int x);
void InitRandom(unsigned int seedBase);
unsigned int cus_random();
typedef struct Nonlinear8 {
    uint8_t mapping[256];
} Nonlinear8;
// 32 位非线性双射结构体，由 4 个 Nonlinear8 组成
typedef struct Nonlinear32 {
    Nonlinear8 n8_1;  // 第一个 8-bit 映射
    Nonlinear8 n8_2;  // 第二个 8-bit 映射
    Nonlinear8 n8_3;  // 第三个 8-bit 映射
    Nonlinear8 n8_4;  // 第四个 8-bit 映射
} Nonlinear32;

//4bits
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

//8bits
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
//16bits
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
//32bits
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
//64bits
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
//128bits
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
#ifdef __cplusplus
extern "C"
{
#endif
void SetRandSeed(unsigned int seed);//Set random seed
/*
* 4bit Matrix operation
*/

void initM4(M4 *Mat);
void randM4(M4 *Mat);
void identityM4(M4 *Mat);
void printM4(M4 Mat);
void printbitM4(M4 Mat);
void copyM4(M4 Mat1, M4 *Mat2);
int isequalM4(M4 Mat1, M4 Mat2);
int isinvertM4(M4 Mat);
void invsM4(M4 Mat, M4 *Mat_inv);
int readbitM4(M4 Mat, int i, int j);
void flipbitM4(M4 *Mat, int i, int j);
void setbitM4(M4 *Mat, int i, int j, int bit);

void initV4(V4 *Vec);
void randV4(V4 *Vec);
void printV4(V4 Vec);
int isequalV4(V4 Vec1, V4 Vec2);
void VecAddVecV4(V4 Vec1, V4 Vec2, V4 *Vec);

uint8_t affineU4(Aff4 aff, uint8_t arr);
int xorU4(uint8_t n);
int HWU4(uint8_t n);

void MatMulVecM4(M4 Mat,V4 Vec, V4 *ans);
uint8_t MatMulNumM4(M4 Mat, uint8_t n);
void MatMulMatM4(M4 Mat1, M4 Mat2, M4 *Mat);
void MatAddMatM4(M4 Mat1, M4 Mat2, M4 *Mat);
void MattransM4(M4 Mat, M4 *Mat_trans);

void genMatpairM4(M4 *Mat, M4 *Mat_inv);
void genaffinepairM4(Aff4 *aff, Aff4 *aff_inv);
void affinemixM4(Aff4 aff, Aff4 preaff_inv, Aff4 *mixaff);

/*
* 8bit Matrix operation
*/

void initM8(M8 *Mat);
void randM8(M8 *Mat);
void identityM8(M8 *Mat);
void printM8(M8 Mat);
void printbitM8(M8 Mat);
void copyM8(M8 Mat1, M8 *Mat2);
int isequalM8(M8 Mat1, M8 Mat2);
int isinvertM8(M8 Mat);
void invsM8(M8 Mat, M8 *Mat_inv);
int readbitM8(M8 Mat, int i, int j);
void flipbitM8(M8 *Mat, int i, int j);
void setbitM8(M8 *Mat, int i, int j, int bit);

void initV8(V8 *Vec);
void randV8(V8 *Vec);
void printV8(V8 Vec);
int isequalV8(V8 Vec1, V8 Vec2);
void VecAddVecV8(V8 Vec1, V8 Vec2, V8 *Vec);

uint8_t affineU8(Aff8 aff, uint8_t arr);
int xorU8(uint8_t n);
int HWU8(uint8_t n);
void printU8(uint8_t n);

void MatMulVecM8(M8 Mat,V8 Vec, V8 *ans);
uint8_t MatMulNumM8(M8 Mat, uint8_t n);
void MatMulMatM8(M8 Mat1, M8 Mat2, M8 *Mat);
void MatAddMatM8(M8 Mat1, M8 Mat2, M8 *Mat);
void MattransM8(M8 Mat, M8 *Mat_trans);

void genMatpairM8(M8 *Mat, M8 *Mat_inv);
void genaffinepairM8(Aff8 *aff, Aff8 *aff_inv);
void affinemixM8(Aff8 aff, Aff8 preaff_inv, Aff8 *mixaff);

/*
* 16bit Matrix operation
*/

void initM16(M16 *Mat);
void randM16(M16 *Mat);
void identityM16(M16 *Mat);
void printM16(M16 Mat);
void printbitM16(M16 Mat);
void copyM16(M16 Mat1, M16 *Mat2);
int isequalM16(M16 Mat1, M16 Mat2);
int isinvertM16(M16 Mat);
void invsM16(M16 Mat, M16 *Mat_inv);
int readbitM16(M16 Mat, int i, int j);
void flipbitM16(M16 *Mat, int i, int j);
void setbitM16(M16 *Mat, int i, int j, int bit);

void initV16(V16 *Vec);
void randV16(V16 *Vec);
void printV16(V16 Vec);
int isequalV16(V16 Vec1, V16 Vec2);
void VecAddVecV16(V16 Vec1, V16 Vec2, V16 *Vec);

uint16_t affineU16(Aff16 aff, uint16_t arr);
int xorU16(uint16_t n);
int HWU16(uint16_t n);
void printU16(uint16_t n);
void MatAddMatM16(M16 Mat1, M16 Mat2, M16 *Mat);
void MatMulVecM16(M16 Mat, V16 Vec, V16 *ans);
uint16_t MatMulNumM16(M16 Mat, uint16_t n);
void MatMulMatM16(M16 Mat1, M16 Mat2, M16 *Mat);
void MattransM16(M16 Mat, M16 *Mat_trans);

void genMatpairM16(M16 *Mat, M16 *Mat_inv);
void genaffinepairM16(Aff16 *aff, Aff16 *aff_inv);
void affinemixM16(Aff16 aff, Aff16 preaff_inv, Aff16 *mixaff);

/*
* 32bit Matrix operation
*/

void initM32(M32 *Mat);
void randM32(M32 *Mat);
void identityM32(M32 *Mat);
void printM32(M32 Mat);
void printbitM32(M32 Mat);
void copyM32(M32 Mat1, M32 *Mat2);
int isequalM32(M32 Mat1, M32 Mat2);
int isinvertM32(M32 Mat);
void invsM32(M32 Mat, M32 *Mat_inv);
int readbitM32(M32 Mat, int i, int j);
void flipbitM32(M32 *Mat, int i, int j);
void setbitM32(M32 *Mat, int i, int j, int bit);

void initV32(V32 *Vec);
void randV32(V32 *Vec);
void printV32(V32 Vec);
int isequalV32(V32 Vec1, V32 Vec2);
void VecAddVecV32(V32 Vec1, V32 Vec2, V32 *Vec);

uint32_t affineU32(Aff32 aff, uint32_t arr);
int xorU32(uint32_t n);
int HWU32(uint32_t n);
void printU32(uint32_t n);

void MatMulVecM32(M32 Mat, V32 Vec, V32 *ans);
uint32_t MatMulNumM32(M32 Mat, uint32_t n);
void MatMulMatM32(M32 Mat1, M32 Mat2, M32 *Mat);
void MatAddMatM32(M32 Mat1, M32 Mat2, M32 *Mat);
void MattransM32(M32 Mat, M32 *Mat_trans);

void genMatpairM32(M32 *Mat, M32 *Mat_inv);
void genaffinepairM32(Aff32 *aff, Aff32 *aff_inv);
void affinemixM32(Aff32 aff, Aff32 preaff_inv, Aff32 *mixaff);
void MatrixcomM8to32(M8 m1, M8 m2, M8 m3, M8 m4, M32 *mat);
void VectorcomV8to32(V8 v1, V8 v2, V8 v3, V8 v4, V32 *vec);
void affinecomM8to32(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32 *aff);

/*
* 64bit Matrix operation
*/

void initM64(M64 *Mat);
void randM64(M64 *Mat);
void identityM64(M64 *Mat);
void printM64(M64 Mat);
void printbitM64(M64 Mat);
void copyM64(M64 Mat1, M64 *Mat2);
int isequalM64(M64 Mat1, M64 Mat2);
int isinvertM64(M64 Mat);
void invsM64(M64 Mat, M64 *Mat_inv);
int readbitM64(M64 Mat, int i, int j);
void flipbitM64(M64 *Mat, int i, int j);
void setbitM64(M64 *Mat, int i, int j, int bit);

void initV64(V64 *Vec);
void randV64(V64 *Vec);
void printV64(V64 Vec);
int isequalV64(V64 Vec1, V64 Vec2);
void VecAddVecV64(V64 Vec1, V64 Vec2, V64 *Vec);

uint64_t affineU64(Aff64 aff, uint64_t arr);
int xorU64(uint64_t n);
int HWU64(uint64_t n);
void printU64(uint64_t n);

void MatMulVecM64(M64 Mat, V64 Vec, V64 *ans);
uint64_t MatMulNumM64(M64 Mat, uint64_t n);
void MatMulMatM64(M64 Mat1, M64 Mat2, M64 *Mat);
void MattransM64(M64 Mat, M64 *Mat_trans);

void MatAddMatM64(M64 Mat1, M64 Mat2, M64 *Mat);
void genMatpairM64(M64 *Mat, M64 *Mat_inv);
void genaffinepairM64(Aff64 *aff, Aff64 *aff_inv);
void affinemixM64(Aff64 aff, Aff64 preaff_inv, Aff64 *mixaff);

void MatrixcomM16to64(M16 m1, M16 m2, M16 m3, M16 m4, M64 *mat);
void VectorcomV16to64(V16 v1, V16 v2, V16 v3, V16 v4, V64 *vec);
void affinecomM16to64(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4, Aff64 *aff);
void MatrixcomM8to64(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8, M64 *mat);
void VectorcomV8to64(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8, V64 *vec);
void affinecomM8to64(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5, Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff64 *aff);

/*
* 128bit Matrix operation
*/

void initM128(M128 *Mat);
void randM128(M128 *Mat);
void identityM128(M128 *Mat);
void printM128(M128 Mat);
void printbitM128(M128 Mat);
void copyM128(M128 Mat1, M128 *Mat2);
int isequalM128(M128 Mat1, M128 Mat2);
int isinvertM128(M128 Mat);
void invsM128(M128 Mat, M128 *Mat_inv);
int readbitM128(M128 Mat, int i, int j);
void flipbitM128(M128 *Mat, int i, int j);
void setbitM128(M128 *Mat, int i, int j, int bit);

void initV128(V128 *Vec);
void randV128(V128 *Vec);
void printV128(V128 Vec);

void affineU128(Aff128 aff, uint64_t arr[], uint64_t ans[]);
int xorU128(uint64_t n[]);
int HWU128(uint64_t n[]);
void printU128(uint64_t n[]);
int isequalV128(V128 Vec1, V128 Vec2);
void VecAddVecV128(V128 Vec1, V128 Vec2, V128 *Vec);

void MatMulVecM128(M128 Mat, V128 Vec, V128 *ans);
void MatMulMatM128(M128 Mat1, M128 Mat2, M128 *Mat);
void MattransM128(M128 Mat, M128 *Mat_trans);

void MatAddMatM128(M128 Mat1, M128 Mat2, M128 *Mat);
void genMatpairM128(M128 *Mat, M128 *Mat_inv);
void genaffinepairM128(Aff128 *aff, Aff128 *aff_inv);
void affinemixM128(Aff128 aff, Aff128 preaff_inv, Aff128 *mixaff);

void MatrixcomM32to128(M32 m1, M32 m2, M32 m3, M32 m4, M128 *mat);
void VectorcomV32to128(V32 v1, V32 v2, V32 v3, V32 v4, V128 *vec);
void affinecomM32to128(Aff32 aff1, Aff32 aff2, Aff32 aff3, Aff32 aff4, Aff128 *aff);
void MatrixcomM8to128(M8 m1, M8 m2, M8 m3, M8 m4, M8 m5, M8 m6, M8 m7, M8 m8, M8 m9, M8 m10, M8 m11, M8 m12, M8 m13, M8 m14, M8 m15, M8 m16, M128 *mat);
void VectorcomV8to128(V8 v1, V8 v2, V8 v3, V8 v4, V8 v5, V8 v6, V8 v7, V8 v8, V8 v9, V8 v10, V8 v11, V8 v12, V8 v13, V8 v14, V8 v15, V8 v16, V128 *vec);
void affinecomM8to128(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff8 aff5, Aff8 aff6, Aff8 aff7, Aff8 aff8, Aff8 aff9, Aff8 aff10, Aff8 aff11, Aff8 aff12, Aff8 aff13, Aff8 aff14, Aff8 aff15, Aff8 aff16, Aff128 *aff);
void MatrixcomM16to128(M16 m1, M16 m2, M16 m3, M16 m4, M16 m5, M16 m6, M16 m7, M16 m8, M128 *mat);
void VectorcomV16to128(V16 v1, V16 v2, V16 v3, V16 v4, V16 v5, V16 v6, V16 v7, V16 v8, V128 *vec);
void affinecomM16to128(Aff16 aff1, Aff16 aff2, Aff16 aff3, Aff16 aff4, Aff16 aff5, Aff16 aff6, Aff16 aff7, Aff16 aff8, Aff128 *aff);

#ifdef __cplusplus
}
#endif
