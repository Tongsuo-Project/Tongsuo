//
// Created by xurq on 2023/5/26.
//
#include "../ml_dsa_avx2_target.h"
#include <x86intrin.h>

#include "cdecl.h"
#include "consts.h"
#include "../params.h"


static const __m256i* in_zeta = (__m256i*)(inv_qdata);
// static const __m256i* v_zinvq = (__m256i*)(inv_qdata + 128);


#define shuffle8(a,b) \
    t = (a);                    \
    (a) = _mm256_permute2x128_si256(t,(b),0x20);\
    (b) = _mm256_permute2x128_si256(t,(b),0x31);


#define shuffle4(a,b) \
    t = (a);                                     \
    (a) = _mm256_unpacklo_epi64(t,(b));\
    (b) = _mm256_unpackhi_epi64(t,(b));          \
\


#define shuffle2(a,b) \
    t = (a);\
    (a) = _mm256_blend_epi32((a),_mm256_slli_epi64((b),32),0xaa);\
    (b) = _mm256_blend_epi32((b),_mm256_srli_epi64(t,32),0x55);  \
\


#define shuffle_inv(a,b) \
t = _mm256_unpacklo_epi32((a),(b)); \
f = _mm256_unpackhi_epi32((a),(b)); \
a = _mm256_permute2x128_si256(t,f,0x20); \
b = _mm256_permute2x128_si256(t,f,0x31); \
\




#define forward_shuffle(a,b) \
t = _mm256_unpacklo_epi32((a),(b)); \
f = _mm256_unpackhi_epi32((a),(b)); \
a = _mm256_unpacklo_epi64((t),(f)); \
b = _mm256_unpackhi_epi64((t),(f)); \
a = _mm256_permutevar8x32_epi32(a, idx);\
b = _mm256_permutevar8x32_epi32(b, idx);\
\




#define shuffle_forward(a, b) \
t = _mm256_permutevar8x32_epi32(a, idx); \
f = _mm256_permutevar8x32_epi32(b, idx2); \
a = _mm256_blend_epi32(t,f,0xf0); \
b = _mm256_blend_epi32(t,f,0x0f);        \
b = _mm256_permutevar8x32_epi32(b, idx3);\
\



#define  butterfly(a, b) \
t = _mm256_sub_epi32(a,b); \
a = _mm256_add_epi32(a,b); \
r0 = _mm256_mul_epi32(zinvq, t); \
b = _mm256_srli_epi64(t,32);\
r1 = _mm256_mul_epi32(b,zinvq); \
t = _mm256_mul_epi32(t,zeta);    \
b = _mm256_mul_epi32(b,zeta);\
r1 = _mm256_mul_epi32(q, r1);\
r0 = _mm256_mul_epi32(q, r0);\
t = _mm256_sub_epi32(t, r0);\
b = _mm256_sub_epi32(b, r1);\
b = _mm256_blend_epi32(_mm256_srli_epi64(t,32),b,0xaa);\
\


#define butterfly0(a, b) \
t = _mm256_sub_epi32(a,b); \
a = _mm256_add_epi32(a,b); \
r0 = _mm256_mul_epi32(zinvq, t); \
b = _mm256_srli_epi64(t,32);\
r1 = _mm256_mul_epi32(b,_mm256_srli_epi64(zinvq,32)); \
t = _mm256_mul_epi32(t,zeta);    \
b = _mm256_mul_epi32(b,_mm256_srli_epi64(zeta,32));\
r1 = _mm256_mul_epi32(q,r1);\
r0 = _mm256_mul_epi32(q,r0);\
t = _mm256_sub_epi32(t, r0);\
b = _mm256_sub_epi32(b, r1);\
b = _mm256_blend_epi32(_mm256_srli_epi64(t,32),b,0xaa);\
\


#define reduce(b) \
r0 = _mm256_mul_epi32(dqiv, b); \
t = _mm256_srli_epi64(b,32);     \
r1 = _mm256_mul_epi32(t,dqiv);  \
t = _mm256_mul_epi32(t,div);    \
b = _mm256_mul_epi32(b,div);    \
r1 = _mm256_mul_epi32(q, r1);\
r0 = _mm256_mul_epi32(q, r0);    \
t = _mm256_sub_epi32(t, r1);\
b = _mm256_sub_epi32(b, r0);\
b = _mm256_blend_epi32(_mm256_srli_epi64(b,32),t,0xaa);\
\


#define mont_reduce()\
reduce(z0)\
reduce(z1)\
reduce(z2)\
reduce(z3)\
\






#define LOAD(n,m) \
z0 = _mm256_load_si256((c + (n)     ));\
z1 = _mm256_load_si256((c + (n) + 8 ));\
z2 = _mm256_load_si256((c + (n) + 16));\
z3 = _mm256_load_si256((c + (n) + 24));\
z4 = _mm256_load_si256((c + (m)     ));\
z5 = _mm256_load_si256((c + (m) + 8 ));\
z6 = _mm256_load_si256((c + (m) + 16));\
z7 = _mm256_load_si256((c + (m) + 24));\
\



#define STORE(n,m) \
_mm256_store_si256((c + (n)     ), z0);\
_mm256_store_si256((c + (n) + 8 ), z1);\
_mm256_store_si256((c + (n) + 16), z2);\
_mm256_store_si256((c + (n) + 24), z3);\
_mm256_store_si256((c + (m)     ), z4);\
_mm256_store_si256((c + (m) + 8 ), z5);\
_mm256_store_si256((c + (m) + 16), z6);\
_mm256_store_si256((c + (m) + 24), z7);\
\




#define levels0to2(n,m) \
zeta = _mm256_load_si256(in_zeta + ((n) >> 4)); \
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 16); \
shuffle_forward(z0,z1)\
butterfly0(z0,z1)      \
shuffle2(z0,z1)        \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 1);\
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 17); \
shuffle_forward(z2,z3)\
butterfly0(z2,z3)      \
shuffle2(z2,z3)  \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 2);\
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 18); \
shuffle_forward(z4,z5)\
butterfly0(z4,z5)      \
shuffle2(z4,z5)  \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 3);\
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 19); \
shuffle_forward(z6,z7)\
butterfly0(z6,z7)      \
shuffle2(z6,z7)  \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 32);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z0,z1)      \
shuffle4(z0,z1)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 33);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z2,z3)      \
shuffle4(z2,z3)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 34);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z4,z5)      \
shuffle4(z4,z5)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 35);  \
zinvq = _mm256_srli_epi64(zeta,32);\
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z6,z7)      \
shuffle4(z6,z7)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 48);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z0,z1)      \
shuffle8(z0,z1)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 49);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z2,z3)\
shuffle8(z2,z3)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 50);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z4,z5)\
shuffle8(z4,z5)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 51);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z6,z7)\
shuffle8(z6,z7)\
\



#define levels0to2_so(n,m) \
zeta = _mm256_load_si256(in_zeta + ((n) >> 4)); \
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 16); \
butterfly0(z0,z1)      \
shuffle2(z0,z1)        \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 1);\
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 17); \
butterfly0(z2,z3)      \
shuffle2(z2,z3)  \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 2);\
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 18); \
butterfly0(z4,z5)      \
shuffle2(z4,z5)  \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 3);\
zinvq = _mm256_load_si256(in_zeta + ((n) >> 4) + 19); \
butterfly0(z6,z7)      \
shuffle2(z6,z7)  \
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 32);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z0,z1)      \
shuffle4(z0,z1)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 33);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z2,z3)      \
shuffle4(z2,z3)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 34);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z4,z5)      \
shuffle4(z4,z5)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 35);  \
zinvq = _mm256_srli_epi64(zeta,32);\
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z6,z7)      \
shuffle4(z6,z7)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 48);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z0,z1)      \
shuffle8(z0,z1)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 49);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z2,z3)\
shuffle8(z2,z3)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 50);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z4,z5)\
shuffle8(z4,z5)\
\
zeta = _mm256_load_si256(in_zeta + ((n) >> 4) + 51);  \
zinvq = _mm256_srli_epi64(zeta,32);\
butterfly(z6,z7)\
shuffle8(z6,z7)\
\



void XRQ_intt_avx2_bo(int32_t c[256]) {
    const __m256i q = _mm256_set1_epi32(Q);
    const __m256i div = _mm256_set1_epi32(DIV);
    const __m256i dqiv = _mm256_set1_epi32(DIV_QINV);

    const __m256i idx = _mm256_setr_epi32(0,2,4,6,1,3,5,7);
    const __m256i idx2 = _mm256_setr_epi32(1,3,5,7, 0,2,4,6);
    const __m256i idx3 = _mm256_setr_epi32(4,5,6,7,0,1,2,3);

    __m256i z0, z1, z2, z3, z4, z5, z6, z7;
    __m256i zeta,r0,r1,t,f,zinvq;
    int i = 0;

    LOAD(0,32)
    levels0to2(0,32)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(0,32)

    LOAD(64,96)
    levels0to2(64,96)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(64,96)

    LOAD(128,160)
    levels0to2(128,160)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(128,160)

    LOAD(192,224)
    levels0to2(192,224)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(192,224)




    //level 6
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    LOAD(0,64)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(0,64)

    LOAD(32,96)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(32,96)

    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);

    LOAD(128,192)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(128,192)

    LOAD(160,224)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(160,224)


    //level 7
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    LOAD(0,128)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(0,128)

    LOAD(32,160)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(32,160)

    LOAD(64,192)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(64,192)

    LOAD(96,224)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(96,224)

}



void XRQ_intt_avx2_so(int32_t c[256]) {
    const __m256i q = _mm256_set1_epi32(Q);
    const __m256i div = _mm256_set1_epi32(DIV);
    const __m256i dqiv = _mm256_set1_epi32(DIV_QINV);

    __m256i z0, z1, z2, z3, z4, z5, z6, z7;
    __m256i zeta,r0,r1,t,f,zinvq;
    int i = 0;

    LOAD(0,32)
    levels0to2_so(0,32)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(0,32)

    LOAD(64,96)
    levels0to2_so(64,96)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(64,96)

    LOAD(128,160)
    levels0to2_so(128,160)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(128,160)

    LOAD(192,224)
    levels0to2_so(192,224)
    //level 3
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z6, z7)
    // level 4
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 5
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(192,224)




    //level 6
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    LOAD(0,64)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(0,64)

    LOAD(32,96)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(32,96)

    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);

    LOAD(128,192)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(128,192)

    LOAD(160,224)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(160,224)


    //level 7
    zeta = _mm256_set1_epi64x(inte_data2[i++]);
    zinvq = _mm256_srli_epi64(zeta,32);
    LOAD(0,128)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(0,128)

    LOAD(32,160)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(32,160)

    LOAD(64,192)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(64,192)

    LOAD(96,224)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    mont_reduce()
    STORE(96,224)

}