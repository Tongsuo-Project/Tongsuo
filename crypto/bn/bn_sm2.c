/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * Copyright 2002-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "bn_local.h"
#include "internal/cryptlib.h"

#define BN_SM2_256_TOP (256+BN_BITS2-1)/BN_BITS2


/* Pre-computed tables are "carry-less" values of modulus*(i+1),
 * all values are in little-endian format.
 */
#if BN_BITS2 == 64
/*
 * The intermediate value of sm2 modular reduction needs to subtract at most
 * 13p, so we need to precompute p, 2p, ... , 13p for modular reduction.
 */
static const BN_ULONG _sm2_p_256[][BN_SM2_256_TOP] = {
    {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull},
    {0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFE00000001ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFDFFFFFFFFull},
    {0xFFFFFFFFFFFFFFFDull, 0xFFFFFFFD00000002ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFCFFFFFFFFull},
    {0xFFFFFFFFFFFFFFFCull, 0xFFFFFFFC00000003ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFBFFFFFFFFull},
    {0xFFFFFFFFFFFFFFFBull, 0xFFFFFFFB00000004ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFAFFFFFFFFull},
    {0xFFFFFFFFFFFFFFFAull, 0xFFFFFFFA00000005ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF9FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF9ull, 0xFFFFFFF900000006ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF8FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF8ull, 0xFFFFFFF800000007ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF7FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF7ull, 0xFFFFFFF700000008ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF6FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF6ull, 0xFFFFFFF600000009ull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF5FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF5ull, 0xFFFFFFF50000000Aull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF4FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF4ull, 0xFFFFFFF40000000Bull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF3FFFFFFFFull},
    {0xFFFFFFFFFFFFFFF3ull, 0xFFFFFFF30000000Cull,
     0xFFFFFFFFFFFFFFFFull, 0xFFFFFFF2FFFFFFFFull}
};

/* pre-compute the value of p^2 check if the input satisfies input < p^2. */
static const BN_ULONG _sm2_p_256_sqr[] = {
    0x0000000000000001ULL, 0x00000001FFFFFFFEULL,
    0xFFFFFFFE00000001ULL, 0x0000000200000000ULL,
    0xFFFFFFFDFFFFFFFEULL, 0xFFFFFFFE00000003ULL,
    0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFE00000000ULL
};

#elif BN_BITS2 == 32
static const BN_ULONG _sm2_p_256[][BN_SM2_256_TOP] = {
    {0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE},
    {0xFFFFFFFE, 0xFFFFFFFF, 0x00000001, 0xFFFFFFFE,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFD},
    {0xFFFFFFFD, 0xFFFFFFFF, 0x00000002, 0xFFFFFFFD,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFC},
    {0xFFFFFFFC, 0xFFFFFFFF, 0x00000003, 0xFFFFFFFC,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB},
    {0xFFFFFFFB, 0xFFFFFFFF, 0x00000004, 0xFFFFFFFB,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFA},
    {0xFFFFFFFA, 0xFFFFFFFF, 0x00000005, 0xFFFFFFFA,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF9},
    {0xFFFFFFF9, 0xFFFFFFFF, 0x00000006, 0xFFFFFFF9,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF8},
    {0xFFFFFFF8, 0xFFFFFFFF, 0x00000007, 0xFFFFFFF8,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF7},
    {0xFFFFFFF7, 0xFFFFFFFF, 0x00000008, 0xFFFFFFF7,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF6},
    {0xFFFFFFF6, 0xFFFFFFFF, 0x00000009, 0xFFFFFFF6,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF5},
    {0xFFFFFFF5, 0xFFFFFFFF, 0x0000000A, 0xFFFFFFF5,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF4},
    {0xFFFFFFF4, 0xFFFFFFFF, 0x0000000B, 0xFFFFFFF4,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF3},
    {0xFFFFFFF3, 0xFFFFFFFF, 0x0000000C, 0xFFFFFFF3,
     0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFF2},
};

static const BN_ULONG _sm2_p_256_sqr[] = {
    0x00000001, 0x00000000, 0xFFFFFFFE, 0x00000001,
    0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002,
    0xFFFFFFFE, 0xFFFFFFFD, 0x00000003, 0xFFFFFFFE,
    0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFE
};
#else
# error "unsupported BN_BITS2"
#endif

static const BIGNUM ossl_bignum_sm2_p_256 = {
    (BN_ULONG *)_sm2_p_256[0],
    BN_SM2_256_TOP,
    BN_SM2_256_TOP,
    0,
    BN_FLG_STATIC_DATA
};

const BIGNUM *BN_get0_sm2_prime_256(void)
{
    return &ossl_bignum_sm2_p_256;
}

/*
 * To avoid more recent compilers (specifically clang-14) from treating this
 * code as a violation of the strict aliasing conditions and omitting it, this
 * cannot be declared as a function.  Moreover, the dst parameter cannot be
 * cached in a local since this no longer references the union and again falls
 * foul of the strict aliasing criteria.  Refer to #18225 for the initial
 * diagnostics and llvm/llvm-project#55255 for the later discussions with the
 * LLVM developers.  The problem boils down to if an array in the union is
 * converted to a pointer or if it is used directly.
 *
 * This function was inlined regardless, so there is no space cost to be
 * paid for making it a macro.
 */
#define sm2_cp_bn_0(dst, src_in, top, max) \
{                                           \
    int ii;                                 \
    const BN_ULONG *src = src_in;           \
                                            \
    for (ii = 0; ii < top; ii++)            \
        (dst)[ii] = src[ii];                \
    for (; ii < max; ii++)                  \
        (dst)[ii] = 0;                      \
}

static void sm2_cp_bn(BN_ULONG *dst, const BN_ULONG *src, int top)
{
    int i;

    for (i = 0; i < top; i++)
        dst[i] = src[i];
}

#if BN_BITS2 == 64
# define bn_cp_64(to, n, from, m)        (to)[n] = (m>=0)?((from)[m]):0;
# define bn_64_set_0(to, n)              (to)[n] = (BN_ULONG)0;
/*
 * two following macros are implemented under assumption that they
 * are called in a sequence with *ascending* n, i.e. as they are...
 */
# define bn_cp_32_naked(to, n, from, m)  (((n)&1)?(to[(n)/2]|=((m)&1)?(from[(m)/2]&BN_MASK2h):(from[(m)/2]<<32))\
                                                :(to[(n)/2] =((m)&1)?(from[(m)/2]>>32):(from[(m)/2]&BN_MASK2l)))
# define bn_32_set_0(to, n)              (((n)&1)?(to[(n)/2]&=BN_MASK2l):(to[(n)/2]=0));
# define bn_cp_32(to,n,from,m)           ((m)>=0)?bn_cp_32_naked(to,n,from,m):bn_32_set_0(to,n)
# if defined(L_ENDIAN)
#  if defined(__arch64__)
#   define SM2_INT64 long
#  else
#   define SM2_INT64 long long
#  endif
# endif
#else
# define bn_cp_64(to, n, from, m) \
        { \
        bn_cp_32(to, (n)*2, from, (m)*2); \
        bn_cp_32(to, (n)*2+1, from, (m)*2+1); \
        }
# define bn_64_set_0(to, n) \
        { \
        bn_32_set_0(to, (n)*2); \
        bn_32_set_0(to, (n)*2+1); \
        }
# define bn_cp_32(to, n, from, m)        (to)[n] = (m>=0)?((from)[m]):0;
# define bn_32_set_0(to, n)              (to)[n] = (BN_ULONG)0;
# if defined(_WIN32) && !defined(__GNUC__)
#  define SM2_INT64 __int64
# elif defined(BN_LLONG)
#  define SM2_INT64 long long
# endif
#endif                          /* BN_BITS2 != 64 */

typedef BN_ULONG (*bn_addsub_f) (BN_ULONG *, const BN_ULONG *,
                                 const BN_ULONG *, int);

#define sm2_set_256(to, from, a1, a2, a3, a4, a5, a6, a7, a8) \
        { \
        bn_cp_32(to, 0, from, (a8) - 8) \
        bn_cp_32(to, 1, from, (a7) - 8) \
        bn_cp_32(to, 2, from, (a6) - 8) \
        bn_cp_32(to, 3, from, (a5) - 8) \
        bn_cp_32(to, 4, from, (a4) - 8) \
        bn_cp_32(to, 5, from, (a3) - 8) \
        bn_cp_32(to, 6, from, (a2) - 8) \
        bn_cp_32(to, 7, from, (a1) - 8) \
        }

/*
 * A fast modular reduction algorithm based on generalized Mersenne prime 
 * for SM2 P256 parameter specialization. You can get more information from
 * https://ieeexplore.ieee.org/document/7011249/ .
 */
int BN_sm2_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                    BN_CTX *ctx)
{
    int i, top = a->top;
    int carry = 0;
    register BN_ULONG *a_d = a->d, *r_d;
    union {
        BN_ULONG bn[BN_SM2_256_TOP];
        unsigned int ui[BN_SM2_256_TOP * sizeof(BN_ULONG) /
                        sizeof(unsigned int)];
    } buf;
    BN_ULONG c_d[BN_SM2_256_TOP], *res;
    PTR_SIZE_INT mask;
    union {
        bn_addsub_f f;
        PTR_SIZE_INT p;
    } u;
    static const BIGNUM ossl_bignum_sm2_p_256_sqr = {
        (BN_ULONG *)_sm2_p_256_sqr,
        OSSL_NELEM(_sm2_p_256_sqr),
        OSSL_NELEM(_sm2_p_256_sqr),
        0, BN_FLG_STATIC_DATA
    };

    field = &ossl_bignum_sm2_p_256; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &ossl_bignum_sm2_p_256_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_SM2_256_TOP))
            return 0;
        r_d = r->d;
        sm2_cp_bn(r_d, a_d, BN_SM2_256_TOP);
    } else
        r_d = a_d;

    sm2_cp_bn_0(buf.bn, a_d + BN_SM2_256_TOP, top - BN_SM2_256_TOP,
                 BN_SM2_256_TOP);

#if defined(SM2_INT64)
    {
        SM2_INT64 acc;         /* accumulator */
        unsigned int *rp = (unsigned int *)r_d;
        const unsigned int *bp = (const unsigned int *)buf.ui;

        acc = rp[0];
        acc += bp[8 - 8];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[0] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[1];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[1] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[2];
        acc -= bp[8 - 8];
        acc -= bp[9 - 8];
        acc -= bp[13 - 8];
        acc -= bp[14 - 8];
        rp[2] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[3];
        acc += bp[8 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[3] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[4];
        acc += bp[9 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[4] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[5];
        acc += bp[10 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        rp[5] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[6];
        acc += bp[11 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[6] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[7];
        acc += bp[8 - 8];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        rp[7] = (unsigned int)acc;

        carry = (int)(acc >> 32);
    }
#else
    {
        BN_ULONG t_d[BN_SM2_256_TOP];

        /*
         * s3 = (c14, 0, c15, c14, c13, 0, c14, c13)
         */
        sm2_set_256(t_d, buf.bn, 14, 0, 15, 14, 13, 0, 14, 13);
        /*
         * s4 = (c13, 0, 0, 0, 0, 0, c15, c14)
         */
        sm2_set_256(c_d, buf.bn, 13, 0, 0, 0, 0, 0, 15, 14);
        carry = (int)bn_add_words(t_d, t_d, c_d, BN_SM2_256_TOP);
        /*
         * s5 = (c12, 0, 0, 0, 0, 0, 0, c15)
         */
        sm2_set_256(c_d, buf.bn, 12, 0, 0, 0, 0, 0, 0, 15);
        carry += (int)bn_add_words(t_d, t_d, c_d, BN_SM2_256_TOP);
        /*
         * s10 = (c15, 0, 0, 0, 0, 0, 0, 0)
         */
        sm2_set_256(c_d, buf.bn, 15, 0, 0, 0, 0, 0, 0, 0);
        carry += (int)bn_add_words(t_d, t_d, c_d, BN_SM2_256_TOP);

        /* left shift */
        {
            register BN_ULONG *ap, t, c;
            ap = t_d;
            c = 0;
            for (i = BN_SM2_256_TOP; i != 0; --i) {
                t = *ap;
                *(ap++) = ((t << 1) | c) & BN_MASK2;
                c = (t & BN_TBIT) ? 1 : 0;
            }
            carry <<= 1;
            carry |= c;
        }

        /* r_d += 2 * (s3 + s4 + s5 + s10) */
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

        /*
         * r_d += s2 + s6 + s7 + s8 + s9
         * s2 = (c15, c14, c13, c12, c11, 0, c9, c8)
         */
        sm2_set_256(t_d, buf.bn, 15, 14, 13, 12, 11, 0, 9, 8);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s6 = (c11, c11, c10, c15, c14, 0, c13, c12)
         */
        sm2_set_256(t_d, buf.bn, 11, 11, 10, 15, 14, 0, 13, 12);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s7 = (c10, c15, c14, c13, c12, 0, c11, c10)
         */
        sm2_set_256(t_d, buf.bn, 10, 15, 14, 13, 12, 0, 11, 10);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s8 = (c9, 0, 0, c9, c8, 0, c10, c9)
         */
        sm2_set_256(t_d, buf.bn, 9, 0, 0, 9, 8, 0, 10, 9);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s9 = (c8, 0, 0, 0, c15, 0, c12, c11)
         */
        sm2_set_256(t_d, buf.bn, 8, 0, 0, 0, 15, 0, 12, 11);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

        /*
         * r_d =  r_d - s11 - s12 - s13 - s14
         * s11 = (0, 0, 0, 0, 0, c14, 0, 0)
         */
        sm2_set_256(t_d, buf.bn, 0, 0, 0, 0, 0, 14, 0, 0);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s12 = (0, 0, 0, 0, 0, c13, 0, 0)
         */
        sm2_set_256(t_d, buf.bn, 0, 0, 0, 0, 0, 13, 0, 0);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s13 = (0, 0, 0, 0, 0, c9, 0, 0)
         */
        sm2_set_256(t_d, buf.bn, 0, 0, 0, 0, 0, 9, 0, 0);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_SM2_256_TOP);
        /*
         * s14 = (0, 0, 0, 0, 0, c8, 0, 0)
         */
        sm2_set_256(t_d, buf.bn, 0, 0, 0, 0, 0, 8, 0, 0);
        carry -= (int)bn_sub_words(r_d, r_d, t_d, BN_SM2_256_TOP);
    }
#endif
    /* see BN_nist_mod_224 for explanation */
    u.f = bn_sub_words;
    if (carry > 0)
        carry =
            (int)bn_sub_words(r_d, r_d, _sm2_p_256[carry - 1],
                              BN_SM2_256_TOP);
    else if (carry < 0) {
        carry =
            (int)bn_add_words(r_d, r_d, _sm2_p_256[-carry - 1],
                              BN_SM2_256_TOP);
        mask = 0 - (PTR_SIZE_INT) carry;
        u.p = ((PTR_SIZE_INT) bn_sub_words & mask) |
            ((PTR_SIZE_INT) bn_add_words & ~mask);
    } else
        carry = 1;

    mask =
        0 - (PTR_SIZE_INT) (*u.f) (c_d, r_d, _sm2_p_256[0], BN_SM2_256_TOP);
    mask &= 0 - (PTR_SIZE_INT) carry;
    res = c_d;
    res = (BN_ULONG *)(((PTR_SIZE_INT) res & ~mask) |
                       ((PTR_SIZE_INT) r_d & mask));
    sm2_cp_bn(r_d, res, BN_SM2_256_TOP);
    r->top = BN_SM2_256_TOP;
    bn_correct_top(r);

    return 1;
}
