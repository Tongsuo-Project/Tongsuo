#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "ml_dsa_local.h"

typedef struct {
  int32_t coeffs[ML_DSA_N];
} poly;

#define poly_reduce ML_DSA_NAMESPACE(poly_reduce)
void poly_reduce(poly *a);
#define poly_caddq ML_DSA_NAMESPACE(poly_caddq)
void poly_caddq(poly *a);

#define poly_add ML_DSA_NAMESPACE(poly_add)
void poly_add(poly *c, const poly *a, const poly *b);
#define poly_sub ML_DSA_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
#define poly_shiftl ML_DSA_NAMESPACE(poly_shiftl)
void poly_shiftl(poly *a);

#define poly_ntt ML_DSA_NAMESPACE(poly_ntt)
void poly_ntt(poly *a);
#define poly_invntt_tomont ML_DSA_NAMESPACE(poly_invntt_tomont)
void poly_invntt_tomont(poly *a);
#define poly_pointwise_montgomery ML_DSA_NAMESPACE(poly_pointwise_montgomery)
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

#define poly_power2round ML_DSA_NAMESPACE(poly_power2round)
void poly_power2round(poly *a1, poly *a0, const poly *a);
#define poly_decompose ML_DSA_NAMESPACE(poly_decompose)
void poly_decompose(poly *a1, poly *a0, const poly *a);
#define poly_make_hint ML_DSA_NAMESPACE(poly_make_hint)
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
#define poly_use_hint ML_DSA_NAMESPACE(poly_use_hint)
void poly_use_hint(poly *b, const poly *a, const poly *h);

#define poly_chknorm ML_DSA_NAMESPACE(poly_chknorm)
int poly_chknorm(const poly *a, int32_t B);
#define poly_uniform ML_DSA_NAMESPACE(poly_uniform)
void poly_uniform(poly *a,
                  const uint8_t seed[ML_DSA_SEEDBYTES],
                  uint16_t nonce);
#define poly_uniform_eta ML_DSA_NAMESPACE(poly_uniform_eta)
void poly_uniform_eta(poly *a,
                      const uint8_t seed[ML_DSA_CRHBYTES],
                      uint16_t nonce);
#define poly_uniform_gamma1 ML_DSA_NAMESPACE(poly_uniform_gamma1)
void poly_uniform_gamma1(poly *a,
                         const uint8_t seed[ML_DSA_CRHBYTES],
                         uint16_t nonce);
#define poly_challenge ML_DSA_NAMESPACE(poly_challenge)
void poly_challenge(poly *c, const uint8_t seed[ML_DSA_CTILDEBYTES]);

#define polyeta_pack ML_DSA_NAMESPACE(polyeta_pack)
void polyeta_pack(uint8_t *r, const poly *a);
#define polyeta_unpack ML_DSA_NAMESPACE(polyeta_unpack)
void polyeta_unpack(poly *r, const uint8_t *a);

#define polyt1_pack ML_DSA_NAMESPACE(polyt1_pack)
void polyt1_pack(uint8_t *r, const poly *a);
#define polyt1_unpack ML_DSA_NAMESPACE(polyt1_unpack)
void polyt1_unpack(poly *r, const uint8_t *a);

#define polyt0_pack ML_DSA_NAMESPACE(polyt0_pack)
void polyt0_pack(uint8_t *r, const poly *a);
#define polyt0_unpack ML_DSA_NAMESPACE(polyt0_unpack)
void polyt0_unpack(poly *r, const uint8_t *a);

#define polyz_pack ML_DSA_NAMESPACE(polyz_pack)
void polyz_pack(uint8_t *r, const poly *a);
#define polyz_unpack ML_DSA_NAMESPACE(polyz_unpack)
void polyz_unpack(poly *r, const uint8_t *a);

#define polyw1_pack ML_DSA_NAMESPACE(polyw1_pack)
void polyw1_pack(uint8_t *r, const poly *a);

#endif
