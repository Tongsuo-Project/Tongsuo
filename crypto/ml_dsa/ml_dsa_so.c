/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Sign-path ExpandA + SO NTT vector helpers.
 * Low-level NTT/shuffle: asm/ml_dsa_ntt_so-x86_64.pl
 */
#include "ml_dsa_local.h"
#include "ml_dsa_matrix.h"
#include "ml_dsa_poly.h"
#include "ml_dsa_vector.h"
#include <openssl/evp.h>
#include <stdint.h>

void ossl_ml_dsa_avx_poly_shuffle(POLY *p);
void ml_dsa_avx_ntt_forward_so_impl(int32_t c[256]);
void ml_dsa_avx_ntt_inverse_so_impl(int32_t c[256]);

int matrix_expand_A_so(EVP_MD_CTX *g_ctx, const EVP_MD *md,
                       const uint8_t *rho, MATRIX *out)
{
    size_t i, n;
    POLY *poly = out->m_poly;

    if (!matrix_expand_A(g_ctx, md, rho, out))
        return 0;

    n = out->k * out->l;
    for (i = 0; i < n; i++)
        ossl_ml_dsa_avx_poly_shuffle(poly + i);
    return 1;
}

void ossl_ml_dsa_avx_poly_ntt_forward_so(POLY *p)
{
    ml_dsa_avx_ntt_forward_so_impl((int32_t *)p->coeff);
}

void ossl_ml_dsa_avx_poly_ntt_inverse_so(POLY *p)
{
    ml_dsa_avx_ntt_inverse_so_impl((int32_t *)p->coeff);
}

void vector_ntt_so(VECTOR *v)
{
    size_t i;
    POLY *poly = v->poly;

    for (i = 0; i < v->num_poly; i++)
        ossl_ml_dsa_avx_poly_ntt_forward_so(poly + i);
}

void vector_ntt_inverse_so(VECTOR *v)
{
    size_t i;
    POLY *poly = v->poly;

    for (i = 0; i < v->num_poly; i++)
        ossl_ml_dsa_avx_poly_ntt_inverse_so(poly + i);
}
