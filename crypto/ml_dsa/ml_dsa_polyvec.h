#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "ml_dsa_local.h"
#include "ml_dsa_poly.h"

/* Vectors of polynomials of length ML_DSA_L */
typedef struct {
  poly vec[ML_DSA_L];
} polyvecl;

#define polyvecl_uniform_eta ML_DSA_NAMESPACE(polyvecl_uniform_eta)
void polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[ML_DSA_CRHBYTES], uint16_t nonce);

#define polyvecl_uniform_gamma1 ML_DSA_NAMESPACE(polyvecl_uniform_gamma1)
void polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[ML_DSA_CRHBYTES], uint16_t nonce);

#define polyvecl_reduce ML_DSA_NAMESPACE(polyvecl_reduce)
void polyvecl_reduce(polyvecl *v);

#define polyvecl_add ML_DSA_NAMESPACE(polyvecl_add)
void polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);

#define polyvecl_ntt ML_DSA_NAMESPACE(polyvecl_ntt)
void polyvecl_ntt(polyvecl *v);
#define polyvecl_invntt_tomont ML_DSA_NAMESPACE(polyvecl_invntt_tomont)
void polyvecl_invntt_tomont(polyvecl *v);
#define polyvecl_pointwise_poly_montgomery ML_DSA_NAMESPACE(polyvecl_pointwise_poly_montgomery)
void polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
#define polyvecl_pointwise_acc_montgomery \
        ML_DSA_NAMESPACE(polyvecl_pointwise_acc_montgomery)
void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);


#define polyvecl_chknorm ML_DSA_NAMESPACE(polyvecl_chknorm)
int polyvecl_chknorm(const polyvecl *v, int32_t B);



/* Vectors of polynomials of length ML_DSA_K */
typedef struct {
  poly vec[ML_DSA_K];
} polyveck;

#define polyveck_uniform_eta ML_DSA_NAMESPACE(polyveck_uniform_eta)
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[ML_DSA_CRHBYTES], uint16_t nonce);

#define polyveck_reduce ML_DSA_NAMESPACE(polyveck_reduce)
void polyveck_reduce(polyveck *v);
#define polyveck_caddq ML_DSA_NAMESPACE(polyveck_caddq)
void polyveck_caddq(polyveck *v);

#define polyveck_add ML_DSA_NAMESPACE(polyveck_add)
void polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_sub ML_DSA_NAMESPACE(polyveck_sub)
void polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
#define polyveck_shiftl ML_DSA_NAMESPACE(polyveck_shiftl)
void polyveck_shiftl(polyveck *v);

#define polyveck_ntt ML_DSA_NAMESPACE(polyveck_ntt)
void polyveck_ntt(polyveck *v);
#define polyveck_invntt_tomont ML_DSA_NAMESPACE(polyveck_invntt_tomont)
void polyveck_invntt_tomont(polyveck *v);
#define polyveck_pointwise_poly_montgomery ML_DSA_NAMESPACE(polyveck_pointwise_poly_montgomery)
void polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);

#define polyveck_chknorm ML_DSA_NAMESPACE(polyveck_chknorm)
int polyveck_chknorm(const polyveck *v, int32_t B);

#define polyveck_power2round ML_DSA_NAMESPACE(polyveck_power2round)
void polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_decompose ML_DSA_NAMESPACE(polyveck_decompose)
void polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
#define polyveck_make_hint ML_DSA_NAMESPACE(polyveck_make_hint)
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
#define polyveck_use_hint ML_DSA_NAMESPACE(polyveck_use_hint)
void polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);

#define polyveck_pack_w1 ML_DSA_NAMESPACE(polyveck_pack_w1)
void polyveck_pack_w1(uint8_t r[ML_DSA_K*POLYW1_PACKEDBYTES], const polyveck *w1);

#define polyvec_matrix_expand ML_DSA_NAMESPACE(polyvec_matrix_expand)
void polyvec_matrix_expand(polyvecl mat[ML_DSA_K], const uint8_t rho[ML_DSA_SEEDBYTES]);

#define polyvec_matrix_pointwise_montgomery ML_DSA_NAMESPACE(polyvec_matrix_pointwise_montgomery)
void polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[ML_DSA_K], const polyvecl *v);

#endif
