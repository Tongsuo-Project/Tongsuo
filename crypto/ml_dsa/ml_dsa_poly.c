/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Polynomial add/sub/max with optional AVX2 (asm/ml_dsa_poly_arith-x86_64.pl).
 */
#include "ml_dsa_local.h"
#include "ml_dsa_poly.h"
#include "ml_dsa_avx2.h"
#include <openssl/crypto.h>

#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)
void ossl_ml_dsa_poly_add_avx2(const POLY *lhs, const POLY *rhs, POLY *out);
void ossl_ml_dsa_poly_sub_avx2(const POLY *lhs, const POLY *rhs, POLY *out);
void ossl_ml_dsa_poly_max_avx2(const POLY *p, uint32_t *mx);
void ossl_ml_dsa_poly_max_signed_avx2(const POLY *p, uint32_t *mx);

static int poly_arith_use_avx2;

static CRYPTO_ONCE poly_arith_once = CRYPTO_ONCE_STATIC_INIT;

static void poly_arith_init(void)
{
    poly_arith_use_avx2 = ossl_ml_dsa_avx2_capable();
}
#endif

void ossl_ml_dsa_poly_add(const POLY *lhs, const POLY *rhs, POLY *out)
{
#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)
    (void)CRYPTO_THREAD_run_once(&poly_arith_once, poly_arith_init);
    if (poly_arith_use_avx2) {
        ossl_ml_dsa_poly_add_avx2(lhs, rhs, out);
        return;
    }
#endif
    {
        int i;

        for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
            out->coeff[i] = reduce_once(lhs->coeff[i] + rhs->coeff[i]);
    }
}

void ossl_ml_dsa_poly_sub(const POLY *lhs, const POLY *rhs, POLY *out)
{
#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)
    (void)CRYPTO_THREAD_run_once(&poly_arith_once, poly_arith_init);
    if (poly_arith_use_avx2) {
        ossl_ml_dsa_poly_sub_avx2(lhs, rhs, out);
        return;
    }
#endif
    {
        int i;

        for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++)
            out->coeff[i] = mod_sub(lhs->coeff[i], rhs->coeff[i]);
    }
}

void ossl_ml_dsa_poly_max_reduce(const POLY *p, uint32_t *mx)
{
#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)
    (void)CRYPTO_THREAD_run_once(&poly_arith_once, poly_arith_init);
    if (poly_arith_use_avx2) {
        ossl_ml_dsa_poly_max_avx2(p, mx);
        return;
    }
#endif
    {
        int i;

        for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++) {
            uint32_t c = p->coeff[i];
            uint32_t abs = abs_mod_prime(c);

            *mx = maximum(*mx, abs);
        }
    }
}

void ossl_ml_dsa_poly_max_signed_reduce(const POLY *p, uint32_t *mx)
{
#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)
    (void)CRYPTO_THREAD_run_once(&poly_arith_once, poly_arith_init);
    if (poly_arith_use_avx2) {
        ossl_ml_dsa_poly_max_signed_avx2(p, mx);
        return;
    }
#endif
    {
        int i;

        for (i = 0; i < ML_DSA_NUM_POLY_COEFFICIENTS; i++) {
            uint32_t c = p->coeff[i];
            uint32_t abs = abs_signed(c);

            *mx = maximum(*mx, abs);
        }
    }
}