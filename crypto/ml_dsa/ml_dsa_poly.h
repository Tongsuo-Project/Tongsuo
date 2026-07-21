/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_CRYPTO_ML_DSA_POLY_H
#define OSSL_CRYPTO_ML_DSA_POLY_H
#include <openssl/crypto.h>

#include "avx/ml_dsa_poly_avx2.h"
#include "ml_dsa_avx2.h"

#define ML_DSA_NUM_POLY_COEFFICIENTS 256

/* Polynomial object with 256 coefficients. The coefficients are unsigned 32 bits */
struct poly_st {
    uint32_t coeff[ML_DSA_NUM_POLY_COEFFICIENTS];
};

static ossl_inline ossl_unused void
poly_zero(POLY *p)
{
    memset(p->coeff, 0, sizeof(*p));
}

/**
 * @brief Polynomial addition.
 *
 * @param lhs A polynomial with coefficients in the range (0..q-1)
 * @param rhs A polynomial with coefficients in the range (0..q-1) to add
 *            to the 'lhs'.
 * @param out The returned addition result with the coefficients all in the
 *            range 0..q-1
 */
static ossl_inline ossl_unused void
poly_add(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = reduce_once(lhs->coeff[i] + rhs->coeff[i]);
}

/**
 * @brief Polynomial subtraction.
 *
 * @param lhs A polynomial with coefficients in the range (0..q-1)
 * @param rhs A polynomial with coefficients in the range (0..q-1) to subtract
 *            from the 'lhs'.
 * @param out The returned subtraction result with the coefficients all in the
 *            range 0..q-1
 */
static ossl_inline ossl_unused void
poly_sub(const POLY *lhs, const POLY *rhs, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = mod_sub(lhs->coeff[i], rhs->coeff[i]);
}

/* @returns 1 if the polynomials are equal, or 0 otherwise */
static ossl_inline ossl_unused int
poly_equal(const POLY *a, const POLY *b)
{
    return CRYPTO_memcmp(a, b, sizeof(*a)) == 0;
}

static ossl_inline ossl_unused void
poly_ntt(POLY *p)
{
    ossl_ml_dsa_poly_ntt(p);
}

static ossl_inline ossl_unused int
poly_sample_in_ball_ntt(POLY *out, const uint8_t *seed, int seed_len,
                        EVP_MD_CTX *h_ctx, const EVP_MD *md, uint32_t tau)
{
    if (!ossl_ml_dsa_poly_sample_in_ball(out, seed, seed_len, h_ctx, md, tau))
        return 0;
    poly_ntt(out);
    return 1;
}

static ossl_inline ossl_unused int
poly_expand_mask(POLY *out, const uint8_t *seed, size_t seed_len,
                 uint32_t gamma1, EVP_MD_CTX *h_ctx, const EVP_MD *md)
{
    return ossl_ml_dsa_poly_expand_mask(out, seed, seed_len, gamma1, h_ctx, md);
}

/*
 * Function pointer types for poly_power2_round operations.
 * These allow selecting AVX2 or scalar implementations at initialization time.
 */
typedef void (*poly_power2_round_fn)(const POLY *t, POLY *t1, POLY *t0);

static CRYPTO_ONCE poly_power2_round_once = CRYPTO_ONCE_STATIC_INIT;

static ossl_inline ossl_unused void
poly_power2_round_scalar(const POLY *t, POLY *t1, POLY *t0)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        ossl_ml_dsa_key_compress_power2_round(t->coeff[i],
                                              t1->coeff + i, t0->coeff + i);
}

static poly_power2_round_fn poly_power2_round_impl = poly_power2_round_scalar;

static ossl_inline ossl_unused void
poly_power2_round_avx(const POLY *t, POLY *t1, POLY *t0)
{
    power2_round_avx(t->coeff, t1->coeff, t0->coeff);
}

static ossl_inline ossl_unused void poly_power2_round_init(void)
{
#ifdef ML_DSA_AVX
    if (ossl_ml_dsa_avx2_capable()) {
        poly_power2_round_impl = poly_power2_round_avx;
    }
#endif
}

static ossl_inline ossl_unused void poly_power2_round(const POLY *t, POLY *t1, POLY *t0)
{
    (void)CRYPTO_THREAD_run_once(&poly_power2_round_once, poly_power2_round_init);
    poly_power2_round_impl(t, t1, t0);
}

/* poly_power2_round end */

static ossl_inline ossl_unused void
poly_scale_power2_round(POLY *in, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = (in->coeff[i] << ML_DSA_D_BITS);
}

/*
 * Function pointer types for poly_decompose operations.
 * These allow selecting AVX2 or scalar implementations at initialization time.
 */

typedef void (*poly_high_bits_fn)(const POLY *in, uint32_t gamma2, POLY *out);
typedef void (*poly_low_bits_fn)(const POLY *in, uint32_t gamma2, POLY *out);
typedef void (*poly_use_hint_fn)(const POLY *h, const POLY *r, uint32_t gamma2, POLY *out);
typedef void (*poly_make_hint_fn)(const POLY *ct0, const POLY *cs2, const POLY *w, uint32_t gamma2,
               POLY *out);

static CRYPTO_ONCE poly_decompose_once = CRYPTO_ONCE_STATIC_INIT;

static ossl_inline ossl_unused void
poly_high_bits_scalar(const POLY *in, uint32_t gamma2, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = ossl_ml_dsa_key_compress_high_bits(in->coeff[i], gamma2);
}

static ossl_inline ossl_unused void
poly_low_bits_scalar(const POLY *in, uint32_t gamma2, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = ossl_ml_dsa_key_compress_low_bits(in->coeff[i], gamma2);
}

static ossl_inline ossl_unused void
poly_make_hint_scalar(const POLY *ct0, const POLY *cs2, const POLY *w, uint32_t gamma2,
               POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = ossl_ml_dsa_key_compress_make_hint(ct0->coeff[i],
                                                           cs2->coeff[i],
                                                           gamma2, w->coeff[i]);
}

static ossl_inline ossl_unused void
poly_use_hint_scalar(const POLY *h, const POLY *r, uint32_t gamma2, POLY *out)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
        out->coeff[i] = ossl_ml_dsa_key_compress_use_hint(h->coeff[i],
                                                          r->coeff[i], gamma2);
}

static poly_high_bits_fn poly_high_bits_impl = poly_high_bits_scalar;
static poly_low_bits_fn poly_low_bits_impl = poly_low_bits_scalar;
static poly_make_hint_fn poly_make_hint_impl = poly_make_hint_scalar;
static poly_use_hint_fn poly_use_hint_impl = poly_use_hint_scalar;


static ossl_inline ossl_unused void
poly_high_bits_avx(const POLY *in, uint32_t gamma2, POLY *out)
{
    high_bits_avx(in->coeff, gamma2, out->coeff);
}

static ossl_inline ossl_unused void
poly_low_bits_avx(const POLY *in, uint32_t gamma2, POLY *out)
{
    low_bits_avx(in->coeff, gamma2, out->coeff);
}

static ossl_inline ossl_unused void
poly_high_bits(const POLY *in, uint32_t gamma2, POLY *out);
static ossl_inline ossl_unused void
poly_low_bits(const POLY *in, uint32_t gamma2, POLY *out);

// static ossl_inline ossl_unused void
// print_poly(POLY *p)
// {
//     for(int i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
//     {
//         printf("%8d  ", p->coeff[i]);
//         if((i+1) % 8 == 0) printf("\n");
//     }
//     printf("\n");
// }


static ossl_inline ossl_unused void
poly_make_hint_avx(const POLY *ct0, const POLY *cs2, const POLY *w, uint32_t gamma2,
                        POLY *out)
{
    POLY r_plus_z, r;
    POLY r_plus_z_high, r_high;

    poly_sub(w, cs2, &r_plus_z);
    poly_add(&r_plus_z, ct0, &r);

    poly_high_bits(&r_plus_z, gamma2, &r_plus_z_high);
    poly_high_bits(&r, gamma2, &r_high);

    make_hint_avx(r_high.coeff, r_plus_z_high.coeff, out->coeff);
    // print_poly(out);
}

static ossl_inline ossl_unused void
poly_use_hint_avx(const POLY *h, const POLY *r, uint32_t gamma2, POLY *out)
{
    use_hint_avx(h->coeff, r->coeff, gamma2, out->coeff);
}

static ossl_inline ossl_unused void poly_decompose_init(void)
{
#ifdef ML_DSA_AVX
    if (ossl_ml_dsa_avx2_capable()) {
        poly_high_bits_impl = poly_high_bits_avx;
        poly_low_bits_impl = poly_low_bits_avx;
        poly_make_hint_impl = poly_make_hint_avx;
        poly_use_hint_impl = poly_use_hint_avx;
    }
#endif
}

static ossl_inline ossl_unused void
poly_high_bits(const POLY *in, uint32_t gamma2, POLY *out)
{
    (void)CRYPTO_THREAD_run_once(&poly_decompose_once, poly_decompose_init);
    poly_high_bits_impl(in, gamma2, out);
}

static ossl_inline ossl_unused void
poly_low_bits(const POLY *in, uint32_t gamma2, POLY *out)
{
    (void)CRYPTO_THREAD_run_once(&poly_decompose_once, poly_decompose_init);
    poly_low_bits_impl(in, gamma2, out);
}

static ossl_inline ossl_unused void
poly_make_hint(const POLY *ct0, const POLY *cs2, const POLY *w, uint32_t gamma2,
               POLY *out)
{
    (void)CRYPTO_THREAD_run_once(&poly_decompose_once, poly_decompose_init);
    poly_make_hint_impl(ct0, cs2, w, gamma2, out);
}

static ossl_inline ossl_unused void
poly_use_hint(const POLY *h, const POLY *r, uint32_t gamma2, POLY *out)
{
    (void)CRYPTO_THREAD_run_once(&poly_decompose_once, poly_decompose_init);
    poly_use_hint_impl(h, r, gamma2, out);
}

/* poly_decompose end */

static ossl_inline ossl_unused void
poly_max(const POLY *p, uint32_t *mx)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++) {
        uint32_t c = p->coeff[i];
        uint32_t abs = abs_mod_prime(c);

        *mx = maximum(*mx, abs);
    }
}

static ossl_inline ossl_unused void
poly_max_signed(const POLY *p, uint32_t *mx)
{
    int i;

    for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++) {
        uint32_t c = p->coeff[i];
        uint32_t abs = abs_signed(c);

        *mx = maximum(*mx, abs);
    }
}
#endif