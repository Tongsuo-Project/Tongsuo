/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ml_dsa_local.h"
#include "ml_dsa_vector.h"
#include "ml_dsa_matrix.h"
#include "ml_dsa_avx2.h"
#include <openssl/crypto.h>

static void matrix_mult_vector_scalar(const MATRIX *a, const VECTOR *s,
                                      VECTOR *t)
{
    size_t i, j;
    POLY *poly = a->m_poly;

    vector_zero(t);

    for (i = 0; i < a->k; i++) {
        for (j = 0; j < a->l; j++) {
            POLY product;

            ossl_ml_dsa_poly_ntt_mult(poly++, &s->poly[j], &product);
            poly_add(&product, &t->poly[i], &t->poly[i]);
        }
    }
}

#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)

typedef void (*ml_dsa_pointwise_acc_fn)(uint32_t *out, const uint32_t *row,
                                        const uint32_t *vec);

void ml_dsa_pointwise_acc_avx_l4(uint32_t *out, const uint32_t *row,
                                 const uint32_t *vec);
void ml_dsa_pointwise_acc_avx_l5(uint32_t *out, const uint32_t *row,
                                 const uint32_t *vec);
void ml_dsa_pointwise_acc_avx_l7(uint32_t *out, const uint32_t *row,
                                 const uint32_t *vec);

static ml_dsa_pointwise_acc_fn pointwise_acc_for_l(size_t l)
{
    switch (l) {
    case 4:
        return ml_dsa_pointwise_acc_avx_l4;
    case 5:
        return ml_dsa_pointwise_acc_avx_l5;
    case 7:
        return ml_dsa_pointwise_acc_avx_l7;
    default:
        return NULL;
    }
}

static void matrix_mult_vector_pointwise_acc(const MATRIX *a, const VECTOR *s,
                                             VECTOR *t,
                                             ml_dsa_pointwise_acc_fn acc)
{
    size_t i, row_stride = a->l;

    vector_zero(t);
    for (i = 0; i < a->k; i++) {
        acc(t->poly[i].coeff, a->m_poly[i * row_stride].coeff,
            s->poly[0].coeff);
    }
}

static int matrix_mult_use_pointwise_acc;

static CRYPTO_ONCE matrix_mult_once = CRYPTO_ONCE_STATIC_INIT;

static void matrix_mult_init(void)
{
    matrix_mult_use_pointwise_acc = ossl_ml_dsa_avx2_capable();
}
#endif

/*
 * Matrix multiply of a k*l matrix of polynomials by a 1 * l vector of
 * polynomials to produce a 1 * k vector of polynomial results.
 * i.e. t = a * s
 */
void ossl_ml_dsa_matrix_mult_vector(const MATRIX *a, const VECTOR *s,
                                    VECTOR *t)
{
#if defined(ML_DSA_AVX) && !defined(OPENSSL_NO_ASM)
    ml_dsa_pointwise_acc_fn acc;

    (void)CRYPTO_THREAD_run_once(&matrix_mult_once, matrix_mult_init);
    acc = matrix_mult_use_pointwise_acc ? pointwise_acc_for_l(a->l) : NULL;
    if (acc != NULL) {
        matrix_mult_vector_pointwise_acc(a, s, t, acc);
        return;
    }
#endif
    matrix_mult_vector_scalar(a, s, t);
}
