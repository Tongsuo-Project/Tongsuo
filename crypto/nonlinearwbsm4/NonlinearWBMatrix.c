/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include "crypto/NonlinearWBMatrix.h"
static unsigned int m_index;
static unsigned int m_intermediateOffset;

unsigned int permuteQPR(unsigned int x)
{
    unsigned int residue;
    static const unsigned int prime = 4294967291u;
    if (x >= prime)
        return x;
    residue = ((unsigned long long) x * x) % prime;
    return (x <= prime / 2) ? residue : prime - residue;
}

void InitRandom(unsigned int seedBase)
{
    unsigned int seedOffset = seedBase+1;
    m_index = permuteQPR(permuteQPR(seedBase) + 0x682f0161);
    m_intermediateOffset = permuteQPR(permuteQPR(seedOffset) + 0x46790905);
}

unsigned int cus_random(void)
{
    return permuteQPR((permuteQPR(m_index++) + m_intermediateOffset) ^ 0x5bf03635);
}
static unsigned int randseed;
/*8bit internal xor table */
static int xor [] = { 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0,
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
                      1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0 };




static uint8_t idM8[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };


static uint32_t idM32[32] = { 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000, 0x4000000, 0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1 };
void initM32(M32* Mat)
{
    int i;
    for (i = 0; i < 32; i++)
    {
        (*Mat).M[i] = 0;
    }
}
void initV8(V8* Vec)
{
    (*Vec).V = 0;
}

void initV32(V32* Vec)
{
    (*Vec).V = 0;
}


void randM8(M8* Mat)
{
    int i;
    InitRandom((randseed++) ^ ((unsigned int)time(NULL)));
    for (i = 0; i < 8; i++)
    {
        (*Mat).M[i] = cus_random();
    }
}

void identityM8(M8* Mat)
{
    int i;
    for (i = 0; i < 8; i++)
    {
        (*Mat).M[i] = idM8[i];
    }
}
void randV8(V8* Vec)
{
    InitRandom((randseed++) ^ (unsigned int)time(NULL));
    (*Vec).V = cus_random();
}
void copyM8(M8 Mat1, M8* Mat2)
{
    int i;
    for (i = 0; i < 8; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}
uint8_t affineU8(Aff8 aff, uint8_t arr)
{
    V8 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM8(aff.Mat, mul_vec, &ans_vec);/*mul */
    return ans_vec.V ^ aff.Vec.V;/*add */
}

uint32_t affineU32(Aff32 aff, uint32_t arr)
{
    V32 mul_vec, ans_vec;
    mul_vec.V = arr;
    MatMulVecM32(aff.Mat, mul_vec, &ans_vec);/*mul */
    return ans_vec.V ^ aff.Vec.V;/*add */
}
int xorU8(uint8_t n)
{
    if (xor [n]) return 1;
    else return 0;
}
int xorU16(uint16_t n)
{
    uint8_t temp;
    uint8_t* u = (uint8_t*)&n;
    temp = (*u) ^ (*(u + 1));
    if (xorU8(temp)) return 1;
    else return 0;
}
int xorU32(uint32_t n)
{
    uint16_t temp;
    uint16_t* u = (uint16_t*)&n;
    temp = (*u) ^ (*(u + 1));
    if (xorU16(temp)) return 1;
    else return 0;
}
uint32_t MatMulNumM32(M32 Mat, uint32_t n)
{
    int i;
    uint32_t temp = 0;
    for (i = 0; i < 32; i++)
    {
        if (xorU32(Mat.M[i] & n)) temp ^= idM32[i];
    }
    return temp;
}


void MatMulVecM8(M8 Mat, V8 Vec, V8* ans)
{
    int i;
    initV8(ans);
    for (i = 0; i < 8; i++)
    {
        if (xorU8(Mat.M[i] & Vec.V)) (*ans).V ^= idM8[i];
    }
}

void MatMulVecM32(M32 Mat, V32 Vec, V32* ans)/*matrix * vector -> vector 32*1 */
{
    int i;
    initV32(ans);
    for (i = 0; i < 32; i++)
    {
        if (xorU32(Mat.M[i] & Vec.V)) (*ans).V ^= idM32[i];
    }
}
void genMatpairM8(M8* Mat, M8* Mat_inv)
{
    int i, j, t, k;
    int p;
    M8 tempMat;
    M8 resultMat;
    uint8_t temp;
    uint8_t trail[64][3];
    int flag;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed++) ^ ((unsigned int)time(NULL)));
    identityM8(Mat);
    identityM8(Mat_inv);
    randM8(&tempMat);
    copyM8(tempMat, &resultMat);
    for (i = 0; i < 8; i++)
    {
        if ((tempMat.M[i] & idM8[i]) == idM8[i])
        {
            for (j = i + 1; j < 8; j++)
            {
                if ((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = i;
                    times++;
                }
            }
        }
        else
        {
            flag = 1;
            for (j = i + 1; j < 8; j++)
            {
                if ((tempMat.M[j] & idM8[i]) == idM8[i])
                {
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
            if (flag)
            {
                invertible = 0;
                if (i < 7)
                {
                    p = i + 1 + cus_random() % (7 - i);/*swap */
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
                    for (t = i + 1; t < 8; t++)
                    {
                        if (cus_random() % 2)
                        {
                            tempMat.M[t] ^= tempMat.M[i];
                            (*Mat_inv).M[t] ^= (*Mat_inv).M[i];
                            trail[times][0] = 1;
                            trail[times][1] = t;
                            trail[times][2] = i;
                            times++;
                        }
                    }
                }
            }
            else /*can still contiune */
            {
                for (k = i + 1; k < 8; k++)
                {
                    if ((tempMat.M[k] & idM8[i]) == idM8[i])
                    {
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
    if (!invertible)
    {
        for (t = 7; t >= 0; t--)
        {
            for (j = t - 1; j >= 0; j--)
            {
                if ((tempMat.M[j] & idM8[t]) == idM8[t])
                {
                    tempMat.M[j] ^= tempMat.M[t];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[t];
                    trail[times][0] = 1;
                    trail[times][1] = j;
                    trail[times][2] = t;
                    times++;
                }
            }
        }

        for (j = times - 1; j >= 0; j--)/*generate inverse matrix */
        {
            if (trail[j][0])/*add */
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else/*swap */
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }
        }
    }
    else/*invertible */
    {
        for (i = 7; i >= 0; i--)
        {
            for (j = i - 1; j >= 0; j--)
            {
                if ((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM8(resultMat, Mat);
    }
}
void genaffinepairM8(Aff8* aff, Aff8* aff_inv)
{
    genMatpairM8(&(aff->Mat), &(aff_inv->Mat));
    randV8(&(aff->Vec));
    MatMulVecM8((*aff_inv).Mat, (*aff).Vec, &(aff_inv->Vec));
}

void MatrixcomM8to32(M8 m1, M8 m2, M8 m3, M8 m4, M32* mat)
{
    int i;
    int j = 0;
    uint8_t* m;
    initM32(mat);
    for (i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m + 3) = m1.M[i];
        j++;
    }
    for (i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m + 2) = m2.M[i];
        j++;
    }
    for (i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *(m + 1) = m3.M[i];
        j++;
    }
    for (i = 0; i < 8; i++)
    {
        m = (uint8_t*)&(*mat).M[j];
        *m = m4.M[i];
        j++;
    }
}
void VectorcomV8to32(V8 v1, V8 v2, V8 v3, V8 v4, V32* vec)/*4 vectors concatenation */
{
    uint8_t* v;
    v = (uint8_t*)&(*vec).V;
    *(v + 3) = v1.V;
    *(v + 2) = v2.V;
    *(v + 1) = v3.V;
    *v = v4.V;
}
void affinecomM8to32(Aff8 aff1, Aff8 aff2, Aff8 aff3, Aff8 aff4, Aff32* aff)/*diagonal affine concatenation, four 8*8 -> 32*32 */
{
    MatrixcomM8to32(aff1.Mat, aff2.Mat, aff3.Mat, aff4.Mat, &(aff->Mat));
    VectorcomV8to32(aff1.Vec, aff2.Vec, aff3.Vec, aff4.Vec, &(aff->Vec));
}
