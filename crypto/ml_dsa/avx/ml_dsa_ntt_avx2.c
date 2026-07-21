//
// Created by xurq on 2023/5/15.
//
#include <x86intrin.h>
#include "ml_dsa_avx2_target.h"

#include "../ml_dsa_local.h"
#include "ml_dsa_consts_avx2.h"
#include "ml_dsa_ntt_avx2.h"


static inline __m256i _mm256_mulhi_epi32(__m256i a, __m256i b) {
    __m256i lo = _mm256_mul_epu32(a, b);
    __m256i hi = _mm256_mul_epu32(_mm256_srli_epi64(a, 32), _mm256_srli_epi64(b, 32));
    return _mm256_blend_epi32(hi,_mm256_shuffle_epi32(lo,_MM_SHUFFLE(3, 3, 1, 1)),0x55);
}



static const __m256i* i_zeta = (__m256i*)(inte_qdata);
static const __m256i* i_zinvq =(__m256i*)(inte_qdata + 384);



#define shuffle8(a,b) \
    t = (a);                    \
    (a) = _mm256_permute2x128_si256(t,(b),0x20);\
    (b) = _mm256_permute2x128_si256(t,(b),0x31);\
    \


#define shuffle4(a,b) \
    t = (a);                                     \
    (a) = _mm256_unpacklo_epi64(t,(b));\
    (b) = _mm256_unpackhi_epi64(t,(b));          \
\


#define shuffle2(a,b) \
    t = (a);\
    (a) = _mm256_blend_epi32((t),_mm256_slli_epi64((b),32),0xaa);\
    (b) = _mm256_blend_epi32((b),_mm256_srli_epi64(t,32),0x55);  \
\




#define shuffle_inv(a,b) \
t = _mm256_unpacklo_epi32((a),(b)); \
f = _mm256_unpackhi_epi32((a),(b)); \
a = _mm256_permute2x128_si256(t,f,0x20); \
b = _mm256_permute2x128_si256(t,f,0x31); \
\





#define butterfly(a,b) \
r0 = _mm256_mul_epi32(zinvq,b);\
h = _mm256_srli_epi64((b),32);     \
r1 = _mm256_mul_epi32(zinvq,h);\
(b) = _mm256_mul_epi32(zeta,(b));   \
h = _mm256_mul_epi32(zeta,h);   \
r0 = _mm256_mul_epi32(r0,q); \
r1 = _mm256_mul_epi32(r1,q);    \
r1 = _mm256_sub_epi32(r1, h); \
r0 = _mm256_sub_epi32(r0, (b));  \
r1 = _mm256_blend_epi32(_mm256_srli_epi64(r0,32),r1,0xAA); \
(b) = _mm256_add_epi32((a),r1);\
(a) = _mm256_sub_epi32((a),r1);\
\


#define butterfly7(a,b) \
r0 = _mm256_mul_epi32(zinvq,b);\
h = _mm256_srli_epi64((b),32);     \
r1 = _mm256_mul_epi32(_mm256_srli_epi64(zinvq,32),h);\
(b) = _mm256_mul_epi32(zeta,(b));   \
h = _mm256_mul_epi32(_mm256_srli_epi64(zeta,32),h);   \
r0 = _mm256_mul_epi32(r0,q); \
r1 = _mm256_mul_epi32(r1,q);    \
r1 = _mm256_sub_epi32(r1, h); \
r0 = _mm256_sub_epi32(r0, (b));  \
r1 = _mm256_blend_epi32(_mm256_srli_epi64(r0,32),r1,0xAA); \
(b) = _mm256_add_epi32((a),r1);\
(a) = _mm256_sub_epi32((a),r1);\
\





#define LOAD(n,m) \
z0  = _mm256_loadu_si256((c + (n)     ));\
z1  = _mm256_loadu_si256((c + (n) + 8 ));\
z2  = _mm256_loadu_si256((c + (n) + 16));\
z3  = _mm256_loadu_si256((c + (n) + 24));\
z4  = _mm256_loadu_si256((c + (m)     ));\
z5  = _mm256_loadu_si256((c + (m) + 8 ));\
z6  = _mm256_loadu_si256((c + (m) + 16));\
z7  = _mm256_loadu_si256((c + (m) + 24));\
\



#define STORE(n,m) \
_mm256_storeu_si256((c + (n)     ), z0);\
_mm256_storeu_si256((c + (n) + 8 ), z1);\
_mm256_storeu_si256((c + (n) + 16), z2);\
_mm256_storeu_si256((c + (n) + 24), z3);\
_mm256_storeu_si256((c + (m)     ), z4);\
_mm256_storeu_si256((c + (m) + 8 ), z5);\
_mm256_storeu_si256((c + (m) + 16), z6);\
_mm256_storeu_si256((c + (m) + 24), z7);\
\



#define levels5to7(n,m) \
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4)); \
zinvq =_mm256_srli_epi64(zeta,32);\
shuffle8(z0,z1)\
butterfly(z0,z1)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 1); \
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle8(z2,z3)\
butterfly(z2,z3)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 2); \
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle8(z4,z5)\
butterfly(z4,z5)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 3); \
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle8(z6,z7)\
butterfly(z6,z7)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 16);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z0,z1)\
butterfly(z0,z1)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 17);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z2,z3)\
butterfly(z2,z3)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 18);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z4,z5)\
butterfly(z4,z5)        \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 19);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z6,z7)\
butterfly(z6,z7)  \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 32);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4));\
shuffle2(z0,z1)         \
butterfly7(z0,z1)        \
shuffle_inv(z0,z1)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 33);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4) + 1);\
shuffle2(z2,z3)         \
butterfly7(z2,z3)        \
shuffle_inv(z2,z3)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 34);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4) + 2);\
shuffle2(z4,z5)         \
butterfly7(z4,z5)        \
shuffle_inv(z4,z5)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 35);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4) + 3);\
shuffle2(z6,z7)         \
butterfly7(z6,z7)        \
shuffle_inv(z6,z7)      \
\



#define levels5to7_so(n,m) \
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4)); \
zinvq =_mm256_srli_epi64(zeta,32);\
shuffle8(z0,z1)\
butterfly(z0,z1)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 1); \
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle8(z2,z3)\
butterfly(z2,z3)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 2); \
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle8(z4,z5)\
butterfly(z4,z5)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 3); \
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle8(z6,z7)\
butterfly(z6,z7)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 16);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z0,z1)\
butterfly(z0,z1)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 17);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z2,z3)\
butterfly(z2,z3)\
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 18);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z4,z5)\
butterfly(z4,z5)        \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 19);\
zinvq = _mm256_srli_epi64(zeta,32);\
shuffle4(z6,z7)\
butterfly(z6,z7)  \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 32);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4));\
shuffle2(z0,z1)         \
butterfly7(z0,z1)        \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 33);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4) + 1);\
shuffle2(z2,z3)         \
butterfly7(z2,z3)        \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 34);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4) + 2);\
shuffle2(z4,z5)         \
butterfly7(z4,z5)        \
\
zeta = _mm256_loadu_si256(i_zeta + ((n) >> 4) + 35);\
zinvq = _mm256_loadu_si256(i_zinvq + ((n) >> 4) + 3);\
shuffle2(z6,z7)         \
butterfly7(z6,z7)        \
\

void XRQ_ntt_avx2_bo(int32_t c[256]) {
    const __m256i q = _mm256_set1_epi32(ML_DSA_Q);

    __m256i z0, z1, z2, z3, z4, z5, z6, z7;
    __m256i zeta,r0,r1,t,f,zinvq,h;


    //level 0
    zeta = _mm256_set1_epi32(25847);
    zinvq = _mm256_set1_epi32(1830765815);
    LOAD(0,128)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(0,128)

    LOAD(32,160)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(32,160)

    LOAD(64,192)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(64,192)

    LOAD(96,224)
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    STORE(96,224)


//level 1
    zeta = _mm256_set1_epi32(-2608894);
    zinvq = _mm256_set1_epi32(-1929875198);
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

    LOAD(128,192)
    zeta = _mm256_set1_epi32(-518909);
    zinvq = _mm256_set1_epi32(-1927777021);
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


    LOAD(0,32)
    //level 2
    zeta = _mm256_set1_epi32(237124);
    zinvq = _mm256_set1_epi32(1640767044);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    // level 3
    zeta = _mm256_set1_epi32(1826347);
    zinvq = _mm256_set1_epi32(308362795);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi32(2353451);
    zinvq = _mm256_set1_epi32(-1815525077);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 4
    zeta = _mm256_set1_epi32(2725464);
    zinvq = _mm256_set1_epi32(1727305304);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi32(1024112);
    zinvq = _mm256_set1_epi32(2082316400);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi32(-1079900);
    zinvq = _mm256_set1_epi32(-1364982364);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi32(3585928);
    zinvq = _mm256_set1_epi32(858240904);
    butterfly(z6, z7)

    levels5to7(0,32)

    STORE(0,32)

    LOAD(64,96)
    //level 2
    zeta = _mm256_set1_epi32(-777960);
    zinvq = _mm256_set1_epi32(1477910808);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    // level 3
    zeta = _mm256_set1_epi32(-359251);
    zinvq = _mm256_set1_epi32(-1374673747);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi32(-2091905);
    zinvq = _mm256_set1_epi32(-1091570561);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 4
    zeta = _mm256_set1_epi32(-549488);
    zinvq = _mm256_set1_epi32(1806278032);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi32(-1119584);
    zinvq = _mm256_set1_epi32(222489248);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi32(2619752);
    zinvq = _mm256_set1_epi32(-346752664);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi32(-2108549);
    zinvq = _mm256_set1_epi32(684667771);
    butterfly(z6, z7)

    levels5to7(64,96)

    STORE(64,96)

    LOAD(128,160)
    //level 2
    zeta = _mm256_set1_epi32(-876248);
    zinvq = _mm256_set1_epi32(1612161320);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    // level 3
    zeta = _mm256_set1_epi32(3119733);
    zinvq = _mm256_set1_epi32(-1929495947);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi32(-2884855);
    zinvq = _mm256_set1_epi32(515185417);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 4
    zeta = _mm256_set1_epi32(-2118186);
    zinvq = _mm256_set1_epi32(1654287830);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi32(-3859737);
    zinvq = _mm256_set1_epi32(-878576921);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi32(-1399561);
    zinvq = _mm256_set1_epi32(-1257667337);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi32(-3277672);
    zinvq = _mm256_set1_epi32(-748618600);
    butterfly(z6, z7)

    levels5to7(128,160)


    STORE(128,160)

    LOAD(192,224)
    //level 2
    zeta = _mm256_set1_epi32(466468);
    zinvq = _mm256_set1_epi32(1640734244);
    butterfly(z0, z4)
    butterfly(z1, z5)
    butterfly(z2, z6)
    butterfly(z3, z7)
    // level 3
    zeta = _mm256_set1_epi32(3111497);
    zinvq = _mm256_set1_epi32(-285697463);
    butterfly(z0, z2)
    butterfly(z1, z3)
    zeta = _mm256_set1_epi32(2680103);
    zinvq = _mm256_set1_epi32(625853735);
    butterfly(z4, z6)
    butterfly(z5, z7)
    //level 4
    zeta = _mm256_set1_epi32(1757237);
    zinvq = _mm256_set1_epi32(329347125);
    butterfly(z0, z1)
    zeta = _mm256_set1_epi32(-19422);
    zinvq = _mm256_set1_epi32(1837364258);
    butterfly(z2, z3)
    zeta = _mm256_set1_epi32(4010497);
    zinvq = _mm256_set1_epi32(-1443016191);
    butterfly(z4, z5)
    zeta = _mm256_set1_epi32(280005);
    zinvq = _mm256_set1_epi32(-1170414139);
    butterfly(z6, z7)

    levels5to7(192,224)

    STORE(192,224)

    poly_normalize_avx2(c);
}

#define forward_shuffle(a,b) \
t = _mm256_unpacklo_epi32((a),(b)); \
f = _mm256_unpackhi_epi32((a),(b)); \
a = _mm256_unpacklo_epi64((t),(f)); \
b = _mm256_unpackhi_epi64((t),(f)); \
a = _mm256_permutevar8x32_epi32(a, idx);\
b = _mm256_permutevar8x32_epi32(b, idx);\
\



void shuffle(int32_t  *c) {
    __m256i z0, z1, z2, z3, z4, z5, z6, z7;
    __m256i t,f;

    const __m256i idx = _mm256_setr_epi32(0,2,4,6,1,3,5,7);


    LOAD(0,32)
    forward_shuffle(z0,z1)
    forward_shuffle(z2,z3)
    forward_shuffle(z4,z5)
    forward_shuffle(z6,z7)
    STORE(0,32)

    LOAD(64,96)
    forward_shuffle(z0,z1)
    forward_shuffle(z2,z3)
    forward_shuffle(z4,z5)
    forward_shuffle(z6,z7)
    STORE(64,96)

    LOAD(128,160)
    forward_shuffle(z0,z1)
    forward_shuffle(z2,z3)
    forward_shuffle(z4,z5)
    forward_shuffle(z6,z7)
    STORE(128,160)

    LOAD(192,224)
    forward_shuffle(z0,z1)
    forward_shuffle(z2,z3)
    forward_shuffle(z4,z5)
    forward_shuffle(z6,z7)
    STORE(192,224)
}

void pointwise_avx(int32_t *c, const int32_t *a, const int32_t *b)
{
    __m256i ymm0 = _mm256_set1_epi32(ML_DSA_Q_INV);
    __m256i ymm1 = _mm256_set1_epi32(ML_DSA_Q);

    int i;
    for (i = 0; i < 10; i++) {
        __m256i ymm2 = _mm256_loadu_si256((const __m256i *)(a + i * 24 + 0));
        __m256i ymm4 = _mm256_loadu_si256((const __m256i *)(a + i * 24 + 8));
        __m256i ymm6 = _mm256_loadu_si256((const __m256i *)(a + i * 24 + 16));

        __m256i ymm10 = _mm256_loadu_si256((const __m256i *)(b + i * 24 + 0));
        __m256i ymm12 = _mm256_loadu_si256((const __m256i *)(b + i * 24 + 8));
        __m256i ymm14 = _mm256_loadu_si256((const __m256i *)(b + i * 24 + 16));

        __m256i ymm3 = _mm256_srli_epi64(ymm2, 32);
        __m256i ymm5 = _mm256_srli_epi64(ymm4, 32);
        __m256i ymm7 = _mm256_srli_epi64(ymm6, 32);
        __m256i ymm11 = _mm256_srli_epi64(ymm10, 32);
        __m256i ymm13 = _mm256_srli_epi64(ymm12, 32);
        __m256i ymm15 = _mm256_srli_epi64(ymm14, 32);

        __m256i tmp2  = _mm256_mul_epi32(ymm2, ymm10);
        __m256i tmp3  = _mm256_mul_epi32(ymm3, ymm11);
        __m256i tmp4  = _mm256_mul_epi32(ymm4, ymm12);
        __m256i tmp5  = _mm256_mul_epi32(ymm5, ymm13);
        __m256i tmp6  = _mm256_mul_epi32(ymm6, ymm14);
        __m256i tmp7  = _mm256_mul_epi32(ymm7, ymm15);

        __m256i red10 = _mm256_mul_epi32(ymm0, tmp2);
        __m256i red11 = _mm256_mul_epi32(ymm0, tmp3);
        __m256i red12 = _mm256_mul_epi32(ymm0, tmp4);
        __m256i red13 = _mm256_mul_epi32(ymm0, tmp5);
        __m256i red14 = _mm256_mul_epi32(ymm0, tmp6);
        __m256i red15 = _mm256_mul_epi32(ymm0, tmp7);

        red10 = _mm256_mul_epi32(ymm1, red10);
        red11 = _mm256_mul_epi32(ymm1, red11);
        red12 = _mm256_mul_epi32(ymm1, red12);
        red13 = _mm256_mul_epi32(ymm1, red13);
        red14 = _mm256_mul_epi32(ymm1, red14);
        red15 = _mm256_mul_epi32(ymm1, red15);

        tmp2 = _mm256_sub_epi64(tmp2, red10);
        tmp3 = _mm256_sub_epi64(tmp3, red11);
        tmp4 = _mm256_sub_epi64(tmp4, red12);
        tmp5 = _mm256_sub_epi64(tmp5, red13);
        tmp6 = _mm256_sub_epi64(tmp6, red14);
        tmp7 = _mm256_sub_epi64(tmp7, red15);

        tmp2 = _mm256_srli_epi64(tmp2, 32);
        tmp4 = _mm256_srli_epi64(tmp4, 32);
        tmp6 = _mm256_srli_epi64(tmp6, 32);

        __m256i res2 = _mm256_blend_epi32(tmp2, tmp3, 0xAA);
        __m256i res4 = _mm256_blend_epi32(tmp4, tmp5, 0xAA);
        __m256i res6 = _mm256_blend_epi32(tmp6, tmp7, 0xAA);

        _mm256_storeu_si256((__m256i *)(c + i * 24 + 0), res2);
        _mm256_storeu_si256((__m256i *)(c + i * 24 + 8), res4);
        _mm256_storeu_si256((__m256i *)(c + i * 24 + 16), res6);
    }

    __m256i ymm2  = _mm256_loadu_si256((const __m256i *)(a + 240));
    __m256i ymm4  = _mm256_loadu_si256((const __m256i *)(a + 248));

    __m256i ymm10 = _mm256_loadu_si256((const __m256i *)(b + 240));
    __m256i ymm12 = _mm256_loadu_si256((const __m256i *)(b + 248));


    __m256i ymm3  = _mm256_srli_epi64(ymm2, 32);
    __m256i ymm5  = _mm256_srli_epi64(ymm4, 32);
    __m256i ymm11 = _mm256_srli_epi64(ymm10, 32);
    __m256i ymm13 = _mm256_srli_epi64(ymm12, 32);

    ymm2 = _mm256_mul_epi32(ymm2, ymm10);
    ymm3 = _mm256_mul_epi32(ymm3, ymm11);
    ymm4 = _mm256_mul_epi32(ymm4, ymm12);
    ymm5 = _mm256_mul_epi32(ymm5, ymm13);

    ymm10 = _mm256_mul_epi32(ymm0, ymm2);
    ymm11 = _mm256_mul_epi32(ymm0, ymm3);
    ymm12 = _mm256_mul_epi32(ymm0, ymm4);
    ymm13 = _mm256_mul_epi32(ymm0, ymm5);

    ymm10 = _mm256_mul_epi32(ymm1, ymm10);
    ymm11 = _mm256_mul_epi32(ymm1, ymm11);
    ymm12 = _mm256_mul_epi32(ymm1, ymm12);
    ymm13 = _mm256_mul_epi32(ymm1, ymm13);

    ymm2 = _mm256_sub_epi64(ymm2, ymm10);
    ymm3 = _mm256_sub_epi64(ymm3, ymm11);
    ymm4 = _mm256_sub_epi64(ymm4, ymm12);
    ymm5 = _mm256_sub_epi64(ymm5, ymm13);

    ymm2 = _mm256_srli_epi64(ymm2, 32);
    ymm4 = _mm256_srli_epi64(ymm4, 32);


    ymm2 = _mm256_blend_epi32(ymm2, ymm3, 0xAA);
    ymm4 = _mm256_blend_epi32(ymm4, ymm5, 0xAA);

    _mm256_storeu_si256((__m256i *)(c + 240), ymm2);
    _mm256_storeu_si256((__m256i *)(c + 248), ymm4);

    poly_normalize_avx2(c);
}