#include "crypto/wbsm4-resistdca.h"

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

static M8 H1 = {
    {
        0xA0,
        0x50,
        0x28,
        0x14,
        0x0A,
        0x05,
        0x02,
        0x01
    }
};

static M8 H2 = {
    {
        0x20,
        0x10,
        0x08,
        0x04,
        0x02,
        0x01,
        0x80,
        0x40
    }
};

static M8 H3 = {
    {
        0x80,
        0x40,
        0x20,
        0x10,
        0x08,
        0x04,
        0x82,
        0x41
    }
};

static M8 HZ = {
    {
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    }
};

unsigned int m_index;
unsigned int m_intermediateOffset;
unsigned int randseed;

static uint8_t idM8[8] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};
static uint32_t idM32[32] = {0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000, 0x4000000, 0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1};
static int xor[] = {0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 
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
    1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0};

static uint8_t  SBOX[256]={
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

unsigned int permuteQPR(unsigned int x)
{
    static const unsigned int prime = 4294967291u;
    unsigned int residue;
    residue = ((unsigned long long) x * x) % prime;
    if (x >= prime)
        return x;
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

void Gen_BytePer(uint8_t *permu, uint8_t *inver){

    int i, j;
	uint8_t temp;
    InitRandom(((unsigned int)time(NULL)));
	for (i = 0; i < 256; i++)
	{
		permu[i] = i;
	}
    while (permu[0]==0)
    {
        for (i = 0; i < 255; i++)
        {
            j = cus_random()%(256 - i);
            temp = permu[i];
            permu[i] = permu[i+j];
            permu[i + j] = temp;
        }
        for (i = 0; i < 256; i++)
        {
            inver[permu[i]] = i;
        }  
    }
    
}

int xorU8(uint8_t n)
{
    if(xor[n]) return 1;
    else return 0;
}
int xorU16(uint16_t n)
{
    uint8_t temp = 0;
    uint8_t* u = (uint8_t*)&n;
    temp = (*u) ^ (*(u+1));
    if(xorU8(temp)) return 1;
    else return 0;
}

int xorU32(uint32_t n)
{
    uint16_t temp = 0;
    uint16_t* u = (uint16_t*)&n;
    temp = (*u) ^ (*(u+1));
    if(xorU16(temp)) return 1;
    else return 0;
}


uint32_t MatMulNumM32(M32 Mat, uint32_t n)
{
    int i;
    uint32_t temp = 0;
    for(i = 0; i < 32; i++)
    {
        if(xorU32(Mat.M[i] & n)) temp ^= idM32[i];
    }
    return temp;
}

void randM8(M8 *Mat)
{
    int i;
    InitRandom((randseed++) ^ ((unsigned int)time(NULL)));
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = cus_random();
    }
}

void identityM8(M8 *Mat)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = idM8[i];
    }
}

void copyM8(M8 Mat1, M8 *Mat2)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}

void genMatpairM8(M8 *Mat, M8 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M8 tempMat;
    M8 resultMat;
    uint8_t temp;
    uint8_t trail[64][3];
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed++) ^ ((unsigned int)time(NULL)));
    identityM8(Mat);
    identityM8(Mat_inv);
    randM8(&tempMat);
    copyM8(tempMat, &resultMat);
    for(i = 0; i < 8; i++)
    {
        if((tempMat.M[i] & idM8[i]) == idM8[i])
        {
            for(j = i + 1; j < 8; j++)
            {
                if((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];

                    trail[times][0]=1;
                    trail[times][1]=j;
                    trail[times][2]=i;
                    times++;
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 8; j++)
            {
                if((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag=0;

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
            if(flag)
            {
                invertible = 0;
                if (i < 7)
                {
                    p = i + 1 + cus_random()%(7 - i);
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
                    for(t = i + 1; t < 8; t++)
                    {
                        if(cus_random()%2)
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
            else 
            {
                for(k = i + 1; k < 8; k++)
                {
                    if((tempMat.M[k] & idM8[i]) == idM8[i])
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
    if(!invertible)
    {
        for(t = 7; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM8[t]) == idM8[t])
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
        
        for(j = times - 1; j >= 0; j--)
        {
            if(trail[j][0])
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else
    {
        for(i = 7; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM8[i]) == idM8[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM8(resultMat, Mat);
    }
}

void initM8(M8 *Mat)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = 0;
    }
}

void initM32(M32 *Mat)
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = 0;
    }
}

void randM32(M32 *Mat)
{
    int i;
    InitRandom((randseed++) ^ ((unsigned int)time(NULL)));
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = cus_random();
    }
}

void copyM32(M32 Mat1, M32 *Mat2)
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat2).M[i] = Mat1.M[i];
    }
}

void identityM32(M32 *Mat)
{
    int i;
    for(i = 0; i < 32; i++)
    {
        (*Mat).M[i] = idM32[i];
    }
}

void invsM32(M32 Mat, M32 *Mat_inv)
{
    int i, j, k;
    uint32_t temp;
    identityM32(Mat_inv);
    for(i = 0; i < 32; i++)
    {
        if((Mat.M[i] & idM32[i]) == idM32[i])
        {
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        else
        {
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;

                    temp = (*Mat_inv).M[i];
                    (*Mat_inv).M[i] = (*Mat_inv).M[j];
                    (*Mat_inv).M[j] = temp;
                    break;
                }
            }
            for(k = i + 1; k < 32; k++)
            {
                if((Mat.M[k] & idM32[i]) == idM32[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                    (*Mat_inv).M[k] ^= (*Mat_inv).M[i];
                }
            }
        }
    }
    for(i = 31; i >= 0; i--)
    {
        for(j = i - 1; j >= 0; j--)
        {
            if((Mat.M[j] & idM32[i]) == idM32[i])
            {
                Mat.M[j] ^= Mat.M[i];
                (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
            }
        }
    }
}

void MattransM8(M8 Mat, M8 *Mat_trans)
{
    int i, j;
    uint8_t mask[3], k, k2, l, temp;
    mask[0] = 0x55;
    mask[1] = 0x33;
    mask[2] = 0x0f;
    for(j = 0; j < 3; j++)
    {
        k = 1 << j;
        k2 = k * 2;
        for(i = 0; i < 4; i++)
        {
            l = (k2 * i) % 7;
            temp = (Mat.M[l] & ~mask[j]) ^ ((Mat.M[l + k] & ~mask[j]) >> k);
            Mat.M[l + k] = (Mat.M[l + k] & mask[j]) ^ ((Mat.M[l] & mask[j]) << k);
            Mat.M[l] = temp;
        }
    }
    copyM8(Mat, Mat_trans);
}

void MatMulMatM8(M8 Mat1, M8 Mat2, M8 *Mat)
{
    int i, j;
    M8 Mat2_trans;
    initM8(Mat);
    MattransM8(Mat2, &Mat2_trans);
    for(i = 0; i < 8; i++)
    {
        for(j = 0; j < 8; j++)
        {
            if(xorU8(Mat1.M[i] & Mat2_trans.M[j])) (*Mat).M[i] ^= idM8[j];
        }       
    }
}

void MatAddMatM8(M8 Mat1, M8 Mat2, M8 *Mat)
{
    int i;
    for(i = 0; i < 8; i++)
    {
        (*Mat).M[i] = Mat1.M[i] ^ Mat2.M[i];
    }
}


void genMatpairM32(M32 *Mat, M32 *Mat_inv)
{
    int i, j, t, k;
    int p;
    M32 tempMat;
    M32 resultMat;
    uint32_t temp;
    uint8_t trail[1024][3];
    int flag = 0;
    int times = 0;
    int invertible = 1;
    InitRandom((randseed++) ^ ((unsigned int)time(NULL)));
    identityM32(Mat);
    identityM32(Mat_inv);
    randM32(&tempMat);
    copyM32(tempMat, &resultMat);
    for(i = 0; i < 32; i++)
    {
        if((tempMat.M[i] & idM32[i]) == idM32[i])
        {
            for(j = i + 1; j < 32; j++)
            {
                if((tempMat.M[j] & idM32[i]) == idM32[i])
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
            for(j = i + 1; j < 32; j++)
            {
                if((tempMat.M[j] & idM32[i]) == idM32[i])
                {
                    temp = tempMat.M[i];
                    tempMat.M[i] = tempMat.M[j];
                    tempMat.M[j] = temp;

                    flag=0;

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
            if(flag) 
            {
                invertible = 0;
                if (i < 31)
                {
                    p = i + 1 + cus_random()%(31 - i);
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
                    for(t = i + 1; t < 32; t++)
                    {
                        if(cus_random()%2)
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
            else 
            {
                for(k = i + 1; k < 32; k++)
                {
                    if((tempMat.M[k] & idM32[i]) == idM32[i])
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
    if(!invertible)
    {
        for(t = 31; t >= 0; t--)
        {
            for(j = t - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM32[t]) == idM32[t])
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
        
        for(j = times - 1; j >= 0; j--)
        {
            if(trail[j][0])
            {
                (*Mat).M[trail[j][1]] ^= (*Mat).M[trail[j][2]];
            }
            else
            {
                temp = (*Mat).M[trail[j][1]];
                (*Mat).M[trail[j][1]] = (*Mat).M[trail[j][2]];
                (*Mat).M[trail[j][2]] = temp;
            }   
        }
    }
    else
    {
        for(i = 31; i >= 0; i--)
        {
            for(j = i - 1; j >= 0; j--)
            {
                if((tempMat.M[j] & idM32[i]) == idM32[i])
                {
                    tempMat.M[j] ^= tempMat.M[i];

                    (*Mat_inv).M[j] ^= (*Mat_inv).M[i];
                }
            }
        }
        copyM32(resultMat, Mat);
    }
}

int isinvertM8(M8 Mat)
{
    int i, j, k;
    uint8_t temp;
    int flag;
    for(i = 0; i < 8; i++)
    {
        if((Mat.M[i] & idM8[i]) == idM8[i])
        {
            for(j = i + 1; j < 8; j++)
            {
                if((Mat.M[j] & idM8[i]) == idM8[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 8; j++)
            {
                if((Mat.M[j] & idM8[i]) == idM8[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 8; k++)
            {
                if((Mat.M[k] & idM8[i]) == idM8[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[7] == idM8[7]) return 1;
    else return 0;
}

int isinvertM32(M32 Mat)
{
    int i, j, k;
    uint32_t temp;
    int flag;
    for(i = 0; i < 32; i++)
    {
        if((Mat.M[i] & idM32[i]) == idM32[i])
        {
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    Mat.M[j] ^= Mat.M[i];
                }
            }
        }
        else
        {
            flag = 1;
            for(j = i + 1; j < 32; j++)
            {
                if((Mat.M[j] & idM32[i]) == idM32[i])
                {
                    temp = Mat.M[i];
                    Mat.M[i] = Mat.M[j];
                    Mat.M[j] = temp;
                    flag = 0;
                    break;
                }
            }
            if(flag) return 0;
            for(k = i + 1; k < 32; k++)
            {
                if((Mat.M[k] & idM32[i]) == idM32[i])
                {
                    Mat.M[k] ^= Mat.M[i];
                }
            }
        }
    }
    if(Mat.M[31] == idM32[31]) return 1;
    else return 0;
}


#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                             \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif
#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))



unsigned char sm4Sbox(unsigned char inch)
{
	unsigned char *pTable = (unsigned char *)SboxTable;
	unsigned char retVal = (unsigned char)(pTable[inch]);
	return retVal;
}

unsigned long sm4CalciRK(unsigned long ka)
{
	unsigned long bb = 0;
	unsigned long rk = 0;
	unsigned char a[4];
	unsigned char b[4];
	PUT_ULONG_BE(ka, a, 0)
	b[0] = sm4Sbox(a[0]);
	b[1] = sm4Sbox(a[1]);
	b[2] = sm4Sbox(a[2]);
	b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb, b, 0)
	rk = bb ^ (ROTL(bb, 13)) ^ (ROTL(bb, 23));
	return rk;
}

void sm4_setkey( unsigned long SK[32], unsigned char key[16] )
{
	unsigned long MK[4];
	unsigned long k[36];
	unsigned long i = 0;

	GET_ULONG_BE( MK[0], key, 0 );
	GET_ULONG_BE( MK[1], key, 4 );
	GET_ULONG_BE( MK[2], key, 8 );
	GET_ULONG_BE( MK[3], key, 12 );
	k[0] = MK[0] ^ FK[0];
	k[1] = MK[1] ^ FK[1];
	k[2] = MK[2] ^ FK[2];
	k[3] = MK[3] ^ FK[3];
	for (; i < 32; i++)
	{
		k[i + 4] = k[i] ^ (sm4CalciRK(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
		SK[i] = k[i + 4];
	}

}

void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] )
{
	ctx->mode = SM4_ENCRYPT;
	sm4_setkey( ctx->sk, key );
}

unsigned long sm4Lt(unsigned long ka)
{
	unsigned long bb = 0;
	unsigned long c = 0;
	unsigned char a[4];
	unsigned char b[4];
	PUT_ULONG_BE(ka, a, 0)
	b[0] = sm4Sbox(a[0]);
	b[1] = sm4Sbox(a[1]);
	b[2] = sm4Sbox(a[2]);
	b[3] = sm4Sbox(a[3]);
	GET_ULONG_BE(bb, b, 0)
	c = bb ^ (ROTL(bb, 2)) ^ (ROTL(bb, 10)) ^ (ROTL(bb, 18)) ^ (ROTL(bb, 24));
	return c;
}

unsigned long sm4F(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, unsigned long rk)
{
	return (x0 ^ sm4Lt(x1 ^ x2 ^ x3 ^ rk));
}

void sm4_one_round( unsigned long sk[32],
    unsigned char input[16],
    unsigned char output[16] )
{
    unsigned long i = 0;
    unsigned long ulbuf[36];

    memset(ulbuf, 0, sizeof(ulbuf));
    GET_ULONG_BE( ulbuf[0], input, 0 )
    GET_ULONG_BE( ulbuf[1], input, 4 )
    GET_ULONG_BE( ulbuf[2], input, 8 )
    GET_ULONG_BE( ulbuf[3], input, 12 )
    while (i < 32)
    {
        ulbuf[i + 4] = sm4F(ulbuf[i], ulbuf[i + 1], ulbuf[i + 2], ulbuf[i + 3], sk[i]);
    
        i++;
    }
    PUT_ULONG_BE(ulbuf[35], output, 0);
    PUT_ULONG_BE(ulbuf[34], output, 4);
    PUT_ULONG_BE(ulbuf[33], output, 8);
    PUT_ULONG_BE(ulbuf[32], output, 12);
}


void sm4_crypt_ecb( sm4_context *ctx,
    int mode,
    int length,
    unsigned char *input,
    unsigned char *output)
{
    while ( length > 0 )
    {
        sm4_one_round( ctx->sk, input, output );
        input  += 16;
        output += 16;
        length -= 16;
    }

}


void Gen_Mat_LBpair(M32* LB,M32* LB_inv){

    genMatpairM32(LB,LB_inv);

}

void Gen_LB(M32* LB){

    // uint32_t idM32[32] = {0x80000000, 0x40000000, 0x20000000, 0x10000000, 0x8000000, 0x4000000, 0x2000000, 0x1000000, 0x800000, 0x400000, 0x200000, 0x100000, 0x80000, 0x40000, 0x20000, 0x10000, 0x8000, 0x4000, 0x2000, 0x1000, 0x800, 0x400, 0x200, 0x100, 0x80, 0x40, 0x20, 0x10, 0x8, 0x4, 0x2, 0x1};
    
    M8 tmp_LB_block[4][4];
    M8 tmp_LB_inv_block[4][4];
    M32 tmp_LB;
    M8 tmp0,tmp1,tmp2,tmp3,tmp4,tmp5,tmp6;
    uint32_t tmp32[24] = {0};
    uint32_t tmp7;
    int i,j;
    int row = 0;
    
    int flag = 0;
    initM32(&tmp_LB);
    // ROW1
    while(1){
        for(i=0;i<4;i++){
            genMatpairM8(&tmp_LB_block[row][i],&tmp_LB_inv_block[row][i]);
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H3,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H1,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H3,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H1,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatAddMatM8(tmp_LB_block[row][0],tmp_LB_block[row][1],&tmp0);
        MatAddMatM8(tmp_LB_block[row][2],tmp_LB_block[row][3],&tmp1);
        MatAddMatM8(tmp0,tmp1,&tmp2);
        MatMulMatM8(tmp2,H2,&tmp3);

        if(isinvertM8(tmp3)==0){
            continue;
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],HZ,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],HZ,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)){
            break;
        }
      
    }

    for(i=0;i<8;i++){
        tmp32[i] = ((uint32_t)((tmp_LB_block[0][0].M[i])<<24))|((uint32_t)((tmp_LB_block[0][1].M[i])<<16))|((uint32_t)((tmp_LB_block[0][2].M[i])<<8))|((uint32_t)((tmp_LB_block[0][3].M[i])));
    }

    row = 1;

    // ROW2
    while(1){

        for(i=0;i<4;i++){
            genMatpairM8(&tmp_LB_block[row][i],&tmp_LB_inv_block[row][i]);
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H3,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H1,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H3,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H1,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatAddMatM8(tmp_LB_block[row][0],tmp_LB_block[row][1],&tmp0);
        MatAddMatM8(tmp_LB_block[row][2],tmp_LB_block[row][3],&tmp1);
        MatAddMatM8(tmp0,tmp1,&tmp2);
        MatMulMatM8(tmp2,H2,&tmp3);

        if(isinvertM8(tmp3)==0){
            continue;
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],HZ,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],HZ,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;;
        }

        for(i=8;i<16;i++){
            tmp32[i] = ((uint32_t)((tmp_LB_block[1][0].M[i-8])<<24))|((uint32_t)((tmp_LB_block[1][1].M[i-8])<<16))|((uint32_t)((tmp_LB_block[1][2].M[i-8])<<8))|((uint32_t)((tmp_LB_block[1][3].M[i-8])));
        }

        for(i=0;i<16;i++){

            if((tmp32[i]&idM32[i])==idM32[i]){
                for(j=i+1;j<16;j++){
                    if((tmp32[j]&idM32[i])==idM32[i]){
                        tmp32[j] = tmp32[j]^tmp32[i]; 
                    }
                }
            }

            else{
                flag = 1;
                for(j=i+1;j<16;j++){
                    if((tmp32[j]&idM32[i])==idM32[i]){
                        tmp7 = tmp32[j];
                        tmp32[j] = tmp32[i];
                        tmp32[i] = tmp7;
                        flag = 0;
                        break;
                    }
                }
                if(flag){
                    break;
                }
                for(j=i+1;j<16;j++){
                    if((tmp32[j]&idM32[i])==idM32[i]){
                        tmp32[j] = tmp32[j]^tmp32[i]; 
                    }

                }
            }

        }
        if(flag||tmp32[15]==0){
            continue;
        }else{
            break;
        }
    }

    row = 2;

    // ROW3
    while(1){

        for(i=0;i<4;i++){
            genMatpairM8(&tmp_LB_block[row][i],&tmp_LB_inv_block[row][i]);
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H3,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H1,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H3,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H1,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatAddMatM8(tmp_LB_block[row][0],tmp_LB_block[row][1],&tmp0);
        MatAddMatM8(tmp_LB_block[row][2],tmp_LB_block[row][3],&tmp1);
        MatAddMatM8(tmp0,tmp1,&tmp2);
        MatMulMatM8(tmp2,H2,&tmp3);

        if(isinvertM8(tmp3)==0){
            continue;
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],HZ,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],HZ,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;;
        }


        for(i=16;i<24;i++){
            tmp32[i] = ((uint32_t)((tmp_LB_block[2][0].M[i-16])<<24))|((uint32_t)((tmp_LB_block[2][1].M[i-16])<<16))|((uint32_t)((tmp_LB_block[2][2].M[i-16])<<8))|((uint32_t)((tmp_LB_block[2][3].M[i-16])));
        }

        for(i=0;i<24;i++){

            if((tmp32[i]&idM32[i])==idM32[i]){
                for(j=i+1;j<24;j++){
                    if((tmp32[j]&idM32[i])==idM32[i]){
                        tmp32[j] = tmp32[j]^tmp32[i]; 
                    }
                }
            }

            else{
                flag = 1;
                for(j=i+1;j<24;j++){
                    if((tmp32[j]&idM32[i])==idM32[i]){
                        tmp7 = tmp32[j];
                        tmp32[j] = tmp32[i];
                        tmp32[i] = tmp7;
                        flag = 0;
                        break;
                    }
                }
                if(flag){
                    break;
                }
                for(j=i+1;j<24;j++){
                    if((tmp32[j]&idM32[i])==idM32[i]){
                        tmp32[j] = tmp32[j]^tmp32[i]; 
                    }

                }
            }

        }
        if(flag||tmp32[23]==0){
            continue;
        }else{
            break;
        }
    }

    row = 3;
    // ROW4
    while(1){

        for(i=0;i<4;i++){
            genMatpairM8(&tmp_LB_block[row][i],&tmp_LB_inv_block[row][i]);
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H3,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H1,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H2,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H3,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H2,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H1,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatAddMatM8(tmp_LB_block[row][0],tmp_LB_block[row][1],&tmp0);
        MatAddMatM8(tmp_LB_block[row][2],tmp_LB_block[row][3],&tmp1);
        MatAddMatM8(tmp0,tmp1,&tmp2);
        MatMulMatM8(tmp2,H2,&tmp3);

        if(isinvertM8(tmp3)==0){
            continue;
        }
        
        MatMulMatM8(tmp_LB_block[row][0],H3,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],H2,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H1,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],HZ,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;
        }

        MatMulMatM8(tmp_LB_block[row][0],H1,&tmp0);
        MatMulMatM8(tmp_LB_block[row][1],HZ,&tmp1);
        MatMulMatM8(tmp_LB_block[row][2],H3,&tmp2);
        MatMulMatM8(tmp_LB_block[row][3],H2,&tmp3);
        MatAddMatM8(tmp0,tmp1,&tmp4);
        MatAddMatM8(tmp2,tmp3,&tmp5);
        MatAddMatM8(tmp4,tmp5,&tmp6);
        if(isinvertM8(tmp6)==0){
            continue;;
        }


        for(i=0;i<4;i++){
            for(j=0;j<8;j++){
                tmp_LB.M[i*8+j] = ((uint32_t)(tmp_LB_block[i][0].M[j])<<24)|((uint32_t)(tmp_LB_block[i][1].M[j])<<16)|((uint32_t)(tmp_LB_block[i][2].M[j])<<8)|((uint32_t)(tmp_LB_block[i][3].M[j]));
            }  
        }

        if(isinvertM32(tmp_LB)){
            break;
        }

    }

    
    copyM32(tmp_LB,LB);

}

void wbsm4_gen(uint8_t *key,unsigned char *whitebox,size_t* whitebox_len){
    
    M32 LB,LB_inv;
    WBLUT* wb = NULL;
    // uint8_t NB_A[4][256],NB_A_inv[4][256];
    uint8_t NB_A[32][4][256];
    uint8_t NB_B[16][256];
    uint8_t NB_C[8][256];
    uint8_t NB_D[4][256];
    uint8_t NB_E[16][256];
    uint8_t NB_F[8][256];
    uint8_t NB_G[4][256];
    uint8_t NB_H[16][256];
    uint8_t NB_I[4][256];
    uint8_t OUT[32][4][256];
    uint8_t IN_EX_E[16][256];

    uint8_t NB_A_inv[32][4][256];
    uint8_t NB_B_inv[16][256];
    uint8_t NB_C_inv[8][256];
    uint8_t NB_D_inv[4][256];
    uint8_t NB_E_inv[16][256];
    uint8_t NB_F_inv[8][256];
    uint8_t NB_G_inv[4][256];
    uint8_t NB_H_inv[16][256];
    uint8_t NB_I_inv[4][256];
    uint8_t IN[32][4][256];
    uint8_t Ex_IN_D[16][256];

    sm4_context ctx;

    int i,j,k;
    int x,y;
    uint8_t tmp8,tmp8_2;
    uint32_t tmp32,tmp32_2;
    uint32_t msk = 0xff;

    if(whitebox==NULL){
        *whitebox_len = sizeof(WBLUT);
        return;   
    }
    
    wb = (WBLUT*)malloc(sizeof(WBLUT));
    wb = (WBLUT*)whitebox;
    
    

    sm4_setkey_enc(&ctx, key);
    printf("Key Initialition Done.\n");

    InitRandom(((unsigned int)time(NULL)));
    //Gen nonlinear byte permutations
    for(i=0;i<16;i++){
        Gen_BytePer(NB_B[i],NB_B_inv[i]);
        Gen_BytePer(NB_E[i],NB_E_inv[i]);
        Gen_BytePer(NB_H[i],NB_H_inv[i]);
    }

    for(i=0;i<8;i++){
        Gen_BytePer(NB_C[i],NB_C_inv[i]);
        Gen_BytePer(NB_F[i],NB_F_inv[i]);  
    }

    for(i=0;i<4;i++){
        //Gen_BytePer(NB_A[i],NB_A_inv[i]);
        Gen_BytePer(NB_D[i],NB_D_inv[i]);
        Gen_BytePer(NB_G[i],NB_G_inv[i]);
        Gen_BytePer(NB_I[i],NB_I_inv[i]);
    }

    for(i=0;i<32;i++){
        for(j=0;j<4;j++){
            Gen_BytePer(OUT[i][j],IN[i][j]);
            Gen_BytePer(NB_A[i][j],NB_A_inv[i][j]);
        }
    }

    for(i=0;i<16;i++){
        Gen_BytePer(IN_EX_E[i],Ex_IN_D[i]);
    }
    printf("Nonlinear Byte Encodings Generation Done.\n");

    for(i=0;i<4;i++){
        for(x = 0;x<256;x++){
            wb->Ex_OUT_D[i*4][x] = IN[31-i][0][x];
            wb->Ex_OUT_D[i*4+1][x] = IN[31-i][1][x];
            wb->Ex_OUT_D[i*4+2][x] = IN[31-i][2][x];
            wb->Ex_OUT_D[i*4+3][x] = IN[31-i][3][x];
        }
    }

    for(i=0;i<16;i++){
        
        for(x = 0;x<256;x++){
            wb->Ex_IN_E[i][x] = IN_EX_E[i][x];  
        }
    }

    printf("External Encodings Generation Done.\n");

    //Gen 1st-round Table_Input
    for(i=0;i<16;i++){
        for(x=0;x<256;x++){
            
            wb->Table_Input[0][i][x] = NB_H[i][Ex_IN_D[i][x]];
        }    
    }

    //Gen 2nd-round Table_Input
    for(i=0;i<12;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[1][i][x] = NB_H[i][Ex_IN_D[i+4][x]];
        }
    }
    for(i=12;i<16;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[1][i][x] = NB_H[i][IN[0][i-12][x]];
        }
    }

    //Gen 3nd-round Table_Input
    for(i=0;i<8;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[2][i][x] = NB_H[i][Ex_IN_D[i+8][x]];
        }
    }
    for(i=8;i<12;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[2][i][x] = NB_H[i][IN[0][i-8][x]];
        }
    }
    for(i=12;i<16;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[2][i][x] = NB_H[i][IN[1][i-12][x]];
        }
    }

    //Gen 4nd-round Table_Input
    for(i=0;i<4;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[3][i][x] = NB_H[i][Ex_IN_D[i+12][x]];
        }
    }
    for(i=4;i<8;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[3][i][x] = NB_H[i][IN[0][i-4][x]];
        }
    }
    for(i=8;i<12;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[3][i][x] = NB_H[i][IN[1][i-8][x]];
        }
    }
    for(i=12;i<16;i++){
        for(x=0;x<256;x++){
            wb->Table_Input[3][i][x] = NB_H[i][IN[2][i-12][x]];
        }
    }

    //Gen 5th-round~32nd-round Table_Input
    for(i=4;i<32;i++){
        for(j=0;j<4;j++){
            for(k=0;k<4;k++){
                for(x=0;x<256;x++){
                    wb->Table_Input[i][j*4+k][x] = NB_H[j*4+k][IN[i-4+j][k][x]]; 
                }
            }
        }
    }

    printf("Input Lookup Tables Generation Done.\n");

     //Gen Table_IXOR_1 & Table Table_IIXOR_1
     for(i=0;i<8;i++){
        for(x=0;x<256;x++){
            for(y=0;y<256;y++){
                if(i<4){
                    wb->Table_IXOR_1[i][x][y] = NB_C[i][NB_B_inv[i][x]^NB_B_inv[i+4][y]];
                    wb->Table_IIXOR_1[i][x][y] = NB_F[i][NB_E_inv[i][x]^NB_E_inv[i+4][y]];
                }else{
                    wb->Table_IXOR_1[i][x][y] = NB_C[i][NB_B_inv[i+4][x]^NB_B_inv[i+8][y]];
                    wb->Table_IIXOR_1[i][x][y] = NB_F[i][NB_E_inv[i+4][x]^NB_E_inv[i+8][y]];
                }   
            }
        }

    }

    //Gen Table_IXOR_2 & Table Table_IIXOR_2 & Table Table_IIIXOR_1
    for(i=0;i<4;i++){
        for(x=0;x<256;x++){
            for(y=0;y<256;y++){
                wb->Table_IXOR_2[i][x][y] = NB_D[i][NB_C_inv[i][x]^NB_C_inv[i+4][y]];
                wb->Table_IIXOR_2[i][x][y] = NB_G[i][NB_F_inv[i][x]^NB_F_inv[i+4][y]];
                wb->Table_IIIXOR_1[i][x][y] = NB_I[i][NB_H_inv[i+4][x]^NB_H_inv[i+8][y]];
                //Talbe_IIIXOR_2[i][x][y] = NB_A[i][NB_I_inv[i][x]^NB_H_inv[i+12][y]];
            }
        }

    }

    //Gen Table Table_IIIXOR_2
    for(i=0;i<32;i++){
        for(j=0;j<4;j++){
            for(x=0;x<256;x++){
                for(y=0;y<256;y++){
                    wb->Table_IIIXOR_2[i][j][x][y] = NB_A[i][j][NB_I_inv[j][x]^NB_H_inv[j+12][y]];
                }
            }

        }
    }

    printf("XOR Lookup Tables Generation Done.\n");

    //Gen Table_OUT
    for(i=0;i<32;i++){
        for(j=0;j<4;j++){
            for(x= 0;x<256;x++){
                for(y=0;y<256;y++){
                    wb->Table_OUT[i][j][x][y] = OUT[i][j][NB_H_inv[j][x]^NB_G_inv[j][y]];
                }
            }
        }
    }

    printf("Output Lookup Tables Generation Done.\n");
    
    Gen_LB(&LB);
    invsM32(LB,&LB_inv);
    //Gen_Mat_LBpair(&LB,&LB_inv);
    printf("Confusion Matrix Generation Done.\n");

    //Gen T-tables
    for(i=0;i<32;i++){
        for(j=0;j<4;j++){
            for(x = 0;x<256;x++){
                tmp8 = SBOX[NB_A_inv[i][j][x]^(uint8_t)((ctx.sk[i]>>(24-8*j))&msk)];
                tmp8_2 = SBOX[NB_A_inv[i][j][x]^(uint8_t)((ctx.sk[31-i]>>(24-8*j))&msk)];
                tmp32 = 0;
                tmp32_2 = 0;
                for(k=0;k<32;k++){
                    tmp32 = tmp32 | ((uint32_t)(xor[tmp8&((L_matrix.M[k]>>(24-8*j))&msk)]<<(31-k)));  
                    tmp32_2 = tmp32_2 | ((uint32_t)(xor[tmp8_2&((L_matrix.M[k]>>(24-8*j))&msk)]<<(31-k)));
                }
                tmp32 = MatMulNumM32(LB,tmp32);
                tmp32_2 = MatMulNumM32(LB,tmp32_2);
                wb->Table_T[i][j][x] = (uint32_t)(NB_B[4*j][(uint8_t)((tmp32>>24)&msk)] <<24) | (uint32_t)(NB_B[4*j+1][(uint8_t)((tmp32>>16)&msk)] <<16) | (uint32_t)(NB_B[4*j+2][(uint8_t)((tmp32>>8)&msk)] <<8) | (uint32_t)(NB_B[4*j+3][(uint8_t)((tmp32)&msk)]);
                wb->De_Table_T[i][j][x] = (uint32_t)(NB_B[4*j][(uint8_t)((tmp32_2>>24)&msk)] <<24) | (uint32_t)(NB_B[4*j+1][(uint8_t)((tmp32_2>>16)&msk)] <<16) | (uint32_t)(NB_B[4*j+2][(uint8_t)((tmp32_2>>8)&msk)] <<8) | (uint32_t)(NB_B[4*j+3][(uint8_t)((tmp32_2)&msk)]);
            
            }
        } 
    }

    printf("T-tables & De-T-tables Generation Done.\n");

    //Gen LB-inv tables
    for(i=0;i<4;i++){
        for(x=0;x<256;x++){
            tmp8 = NB_D_inv[i][x];
            tmp32 = 0;
            for(j=0;j<32;j++){
                tmp32 = tmp32 | ((uint32_t)(xor[tmp8&((LB_inv.M[j]>>(24-8*i))&msk)]<<(31-j)));
            }
            wb->Table_LB_inv[i][x] = (uint32_t)(NB_E[4*i][(uint8_t)((tmp32>>24)&msk)] <<24) | (uint32_t)(NB_E[4*i+1][(uint8_t)((tmp32>>16)&msk)] <<16) | (uint32_t)(NB_E[4*i+2][(uint8_t)((tmp32>>8)&msk)] <<8) | (uint32_t)(NB_E[4*i+3][(uint8_t)((tmp32)&msk)]);
        }
    }

    
    
    //free(wb);
    printf("LB_inv-tables Generation Done.\n");
    printf("WBSM4 Generation Done!\n");

}


void wbsm4_encrypt(uint8_t input[16], uint8_t output[16],unsigned char *whitebox){

    int r,i,j;
    uint8_t tmp_state[16];
    uint8_t tmp8_X0[4];
    uint8_t tmp8_1[16];
    uint8_t tmp8_2[4];
    uint8_t tmp8_3[8];
    uint32_t tmp32[4];

    uint32_t msk = 0xff;
    
    WBLUT* wb = NULL;
    wb = (WBLUT*)malloc(sizeof(WBLUT));
    wb = (WBLUT*)whitebox;

    for(i=0;i<16;i++){
        tmp_state[i] = (wb->Ex_IN_E)[i][input[i]];
    }

    for(r=0;r<32;r++){

        //input phase
        for(i=0;i<16;i++){
            
            tmp8_1[i] = (wb->Table_Input)[r][i][tmp_state[i]];
        }
        for(i=0;i<4;i++){
            tmp8_X0[i] = tmp_state[i];
            tmp8_2[i] = (wb->Table_IIIXOR_1)[i][tmp8_1[i+4]][tmp8_1[i+8]];
        }
        for(i=0;i<4;i++){
            tmp8_2[i] = (wb->Table_IIIXOR_2)[r][i][tmp8_2[i]][tmp8_1[i+12]];
        }

        //Round function phase
        // TBox
        for(i=0;i<4;i++){
            tmp32[i] = (wb->Table_T)[r][i][tmp8_2[i]];
            for(j=0;j<4;j++){
                tmp8_1[i*4+j] = (uint8_t)(tmp32[i]>>(24-j*8) & msk);
            }
        }
        for(i=0;i<8;i++){
            if(i<4){
                tmp8_3[i] = (wb->Table_IXOR_1)[i][tmp8_1[i]][tmp8_1[i+4]];
            }else{
                tmp8_3[i] = (wb->Table_IXOR_1)[i][tmp8_1[i+4]][tmp8_1[i+8]];
            } 
        }

        // LB_inv
        for(i=0;i<4;i++){
            tmp8_2[i] = (wb->Table_IXOR_2)[i][tmp8_3[i]][tmp8_3[i+4]];

            tmp32[i] = (wb->Table_LB_inv)[i][tmp8_2[i]];
            for(j=0;j<4;j++){
                tmp8_1[i*4+j] = (uint8_t)(tmp32[i]>>(24-j*8) & msk);
            }
        }
        for(i=0;i<8;i++){
            if(i<4){
                tmp8_3[i] = (wb->Table_IIXOR_1)[i][tmp8_1[i]][tmp8_1[i+4]];
            }else{
                tmp8_3[i] = (wb->Table_IIXOR_1)[i][tmp8_1[i+4]][tmp8_1[i+8]];
            } 
        }
        
        for(i=0;i<4;i++){
            tmp8_2[i] = (wb->Table_IIXOR_2)[i][tmp8_3[i]][tmp8_3[i+4]];
            tmp8_2[i] = (wb->Table_OUT)[r][i][tmp8_X0[i]][tmp8_2[i]];
        }

        // Update input state
        for(i=0;i<12;i++){
            tmp_state[i] = tmp_state[i+4];
        }
        for(i=12;i<16;i++){
            tmp_state[i] = tmp8_2[i-12];
        }

    }
    
    //reverse
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            output[i*4+j] = tmp_state[(3-i)*4+j];
        }
    }

    for(i=0;i<16;i++){
        output[i] = (wb->Ex_OUT_D)[i][output[i]];
    }
    //free(wb);

}

void wbsm4_decrypt(uint8_t input[16], uint8_t output[16],unsigned char *whitebox){

    int r,i,j;
    uint8_t tmp_state[16];
    uint8_t tmp8_X0[4];
    uint8_t tmp8_1[16];
    uint8_t tmp8_2[4];
    uint8_t tmp8_3[8];
    uint32_t tmp32[4];

    uint32_t msk = 0xff;
    
    WBLUT* wb = NULL;
    wb = (WBLUT*)malloc(sizeof(WBLUT));
    wb = (WBLUT*)whitebox;

    for(i=0;i<16;i++){
        tmp_state[i] = (wb->Ex_IN_E)[i][input[i]];
    }

    for(r=0;r<32;r++){

        //input phase
        for(i=0;i<16;i++){
            
            tmp8_1[i] = (wb->Table_Input)[r][i][tmp_state[i]];
        }
        for(i=0;i<4;i++){
            tmp8_X0[i] = tmp_state[i];
            tmp8_2[i] = (wb->Table_IIIXOR_1)[i][tmp8_1[i+4]][tmp8_1[i+8]];
        }
        for(i=0;i<4;i++){
            tmp8_2[i] = (wb->Table_IIIXOR_2)[r][i][tmp8_2[i]][tmp8_1[i+12]];
        }

        //Round function phase
        // TBox
        for(i=0;i<4;i++){
            tmp32[i] = (wb->De_Table_T)[r][i][tmp8_2[i]];
            for(j=0;j<4;j++){
                tmp8_1[i*4+j] = (uint8_t)(tmp32[i]>>(24-j*8) & msk);
            }
        }
        for(i=0;i<8;i++){
            if(i<4){
                tmp8_3[i] = (wb->Table_IXOR_1)[i][tmp8_1[i]][tmp8_1[i+4]];
            }else{
                tmp8_3[i] = (wb->Table_IXOR_1)[i][tmp8_1[i+4]][tmp8_1[i+8]];
            } 
        }

        // LB_inv
        for(i=0;i<4;i++){
            tmp8_2[i] = (wb->Table_IXOR_2)[i][tmp8_3[i]][tmp8_3[i+4]];

            tmp32[i] = (wb->Table_LB_inv)[i][tmp8_2[i]];
            for(j=0;j<4;j++){
                tmp8_1[i*4+j] = (uint8_t)(tmp32[i]>>(24-j*8) & msk);
            }
        }
        for(i=0;i<8;i++){
            if(i<4){
                tmp8_3[i] = (wb->Table_IIXOR_1)[i][tmp8_1[i]][tmp8_1[i+4]];
            }else{
                tmp8_3[i] = (wb->Table_IIXOR_1)[i][tmp8_1[i+4]][tmp8_1[i+8]];
            } 
        }
        
        for(i=0;i<4;i++){
            tmp8_2[i] = (wb->Table_IIXOR_2)[i][tmp8_3[i]][tmp8_3[i+4]];
            tmp8_2[i] = (wb->Table_OUT)[r][i][tmp8_X0[i]][tmp8_2[i]];
        }

        // Update input state
        for(i=0;i<12;i++){
            tmp_state[i] = tmp_state[i+4];
        }
        for(i=12;i<16;i++){
            tmp_state[i] = tmp8_2[i-12];
        }

    }
    
    //reverse
    for(i=0;i<4;i++){
        for(j=0;j<4;j++){
            output[i*4+j] = tmp_state[(3-i)*4+j];
        }
    }

    for(i=0;i<16;i++){
        output[i] = (wb->Ex_OUT_D)[i][output[i]];
    }
    //free(wb);

}
