#include "ml_dsa_avx2_target.h"
#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "poly.h"
#include "ntt/ntt.h"
#include "rounding.h"
#include "rejsample.h"
#include "keccak4x/symmetric.h"
#include "fips202x4.h"
#include "ntt/consts.h"


#define _mm256_blendv_epi32(a,b,mask) \
  _mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a), \
                                       _mm256_castsi256_ps(b), \
                                       _mm256_castsi256_ps(mask)))

/*************************************************
* Name:        poly_reduce
*
* Description: Inplace reduction of all coefficients of polynomial to
*              representative in [-6283009,6283007].
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_reduce(poly *a) {
  unsigned int i;
  __m256i f, g;
  const __m256i q = _mm256_load_si256((__m256i *) &qdata[_8XQ]);
  const __m256i off = _mm256_set1_epi32(1 << 22);


  for (i = 0; i < N / 8; ++i) {
    f = _mm256_load_si256((__m256i *) &a->coeffs[8 * i]);
    g = _mm256_add_epi32(f, off);
    g = _mm256_srai_epi32(g, 23);
    g = _mm256_mullo_epi32(g, q);
    f = _mm256_sub_epi32(f, g);
    _mm256_store_si256((__m256i *) &a->coeffs[8 * i], f);
  }
}

/*************************************************
* Name:        poly_addq
*
* Description: For all coefficients of in/out polynomial add Q if
*              coefficient is negative.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_caddq(poly *a) {
  unsigned int i;
  __m256i f, g;
  const __m256i q = _mm256_load_si256((__m256i *) &qdata[_8XQ]);
  const __m256i zero = _mm256_setzero_si256();


  for (i = 0; i < N / 8; ++i) {
    f = _mm256_load_si256((__m256i *) &a->coeffs[8 * i]);
    g = _mm256_blendv_epi32(zero, q, f);
    f = _mm256_add_epi32(f, g);
    _mm256_store_si256((__m256i *) &a->coeffs[8 * i], f);
  }
}

/*************************************************
* Name:        poly_freeze
*
* Description: Inplace reduction of all coefficients of polynomial to
*              standard representatives.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_freeze(poly *a) {
  poly_reduce(a);
  poly_caddq(a);
}

/*************************************************
* Name:        poly_add
*
* Description: Add polynomials. No modular reduction is performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first summand
*              - const poly *b: pointer to second summand
**************************************************/
void poly_add(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  __m256i vec0, vec1;

  for (i = 0; i < N; i += 8) {
    vec0 = _mm256_load_si256((__m256i *) &a->coeffs[i]);
    vec1 = _mm256_load_si256((__m256i *) &b->coeffs[i]);
    vec0 = _mm256_add_epi32(vec0, vec1);
    _mm256_store_si256((__m256i *) &c->coeffs[i], vec0);
  }
}

/*************************************************
* Name:        poly_sub
*
* Description: Subtract polynomials. No modular reduction is
*              performed.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial to be
*                               subtraced from first input polynomial
**************************************************/
void poly_sub(poly *c, const poly *a, const poly *b) {
  unsigned int i;
  __m256i vec0, vec1;

  for (i = 0; i < N; i += 8) {
    vec0 = _mm256_load_si256((__m256i *) &a->coeffs[i]);
    vec1 = _mm256_load_si256((__m256i *) &b->coeffs[i]);
    vec0 = _mm256_sub_epi32(vec0, vec1);
    _mm256_store_si256((__m256i *) &c->coeffs[i], vec0);
  }
}

/*************************************************
* Name:        poly_shiftl
*
* Description: Multiply polynomial by 2^D without modular reduction. Assumes
*              input coefficients to be less than 2^{31-D} in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_shiftl(poly *a) {
  unsigned int i;
  __m256i vec;

  for (i = 0; i < N; i += 8) {
    vec = _mm256_load_si256((__m256i *) &a->coeffs[i]);
    vec = _mm256_slli_epi32(vec, D);
    _mm256_store_si256((__m256i *) &a->coeffs[i], vec);
  }
}

/*************************************************
* Name:        poly_ntt
*
* Description: Inplace forward NTT. Coefficients can grow by up to
*              8*Q in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_ntt_bo(poly *a) {
  XRQ_ntt_avx2_bo(a->coeffs);
}

void poly_ntt_so_avx2(poly *a) {
  XRQ_ntt_avx2_so(a->coeffs);
}

void poly_intt_bo(poly *a) {
  XRQ_intt_avx2_bo(a->coeffs);
}

void poly_intt_so_avx2(poly *a) {
  XRQ_intt_avx2_so(a->coeffs);
}


/*************************************************
* Name:        poly_pointwise_montgomery
*
* Description: Pointwise multiplication of polynomials in NTT domain
*              representation and multiplication of resulting polynomial
*              by 2^{-32}.
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const poly *a: pointer to first input polynomial
*              - const poly *b: pointer to second input polynomial
**************************************************/
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b) {
  pointwise_avx(c->coeffs, a->coeffs, b->coeffs, qdata);
}

/*************************************************
* Name:        poly_power2round
*
* Description: For all coefficients c of the input polynomial,
*              compute c0, c1 such that c mod^+ Q = c1*2^D + c0
*              with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_power2round(poly *a1, poly *a0, const poly *a) {
  power2round_avx(a1->coeffs, a0->coeffs, a->coeffs);
}

/*************************************************
* Name:        poly_decompose
*
* Description: For all coefficients c of the input polynomial,
*              compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
*              with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
*              set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - poly *a1: pointer to output polynomial with coefficients c1
*              - poly *a0: pointer to output polynomial with coefficients c0
*              - const poly *a: pointer to input polynomial
**************************************************/
void poly_decompose(poly *a1, poly *a0, const poly *a) {
  decompose_avx(a1->coeffs, a0->coeffs, a->coeffs);
}

/*************************************************
* Name:        poly_make_hint
*
* Description: Compute hint polynomial. The coefficients of which indicate
*              whether the low bits of the corresponding coefficient of
*              the input polynomial overflow into the high bits.
*
* Arguments:   - poly *h: pointer to output hint polynomial
*              - const poly *a0: pointer to low part of input polynomial
*              - const poly *a1: pointer to high part of input polynomial
*
* Returns number of 1 bits.
**************************************************/
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1) {
  return make_hint_avx(h->coeffs, a0->coeffs, a1->coeffs);
}

/*************************************************
* Name:        poly_use_hint
*
* Description: Use hint polynomial to correct the high bits of a polynomial.
*
* Arguments:   - poly *b: pointer to output polynomial with corrected high bits
*              - const poly *a: pointer to input polynomial
*              - const poly *h: pointer to input hint polynomial
**************************************************/
void poly_use_hint(poly *b, const poly *a, const poly *h) {
  use_hint_avx(b->coeffs, a->coeffs, h->coeffs);
}

/*************************************************
* Name:        poly_chknorm
*
* Description: Check infinity norm of polynomial against given bound.
*              Assumes input polynomial to be reduced by poly_reduce().
*
* Arguments:   - const poly *a: pointer to polynomial
*              - int32_t B: norm bound
*
* Returns 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
**************************************************/
int poly_chknorm(const poly *a, int32_t B) {
  unsigned int i;
  int r;
  __m256i f, t;
  const __m256i bound = _mm256_set1_epi32(B - 1);

  t = _mm256_setzero_si256();
  for (i = 0; i < N / 8; ++i) {
    f = _mm256_load_si256((__m256i *) &a->coeffs[8 * i]);
    f = _mm256_abs_epi32(f);
    f = _mm256_cmpgt_epi32(f, bound);
    t = _mm256_or_si256(t, f);
  }

  r = !_mm256_testz_si256(t, t);
  return r;
}

#if GAMMA1 == (1 << 17)
#define POLY_UNIFORM_GAMMA1_NBLOCKS ((576 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#elif GAMMA1 == (1 << 19)
#define POLY_UNIFORM_GAMMA1_NBLOCKS ((640 + STREAM256_BLOCKBYTES - 1)/STREAM256_BLOCKBYTES)
#endif

/*************************************************
* Name:        challenge
*
* Description: Implementation of H. Samples polynomial with TAU nonzero
*              coefficients in {-1,1} using the output stream of
*              SHAKE256(seed).
*
* Arguments:   - poly *c: pointer to output polynomial
*              - const uint8_t mu[]: byte array containing seed of length SEEDBYTES
**************************************************/
void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]) {
  unsigned int i, b, pos;
  uint64_t signs;
  uint8_t buf[SHAKE256_RATE];
  keccak_state state;

  shake256_init(&state);
  shake256_absorb(&state, seed, CTILDEBYTES);
  shake256_finalize(&state);
  shake256_squeezeblocks(buf, 1, &state);

  signs = 0;
  for (i = 0; i < 8; ++i) signs |= (uint64_t) buf[i] << 8 * i;
  pos = 8;

  for (i = 0; i < N; ++i) c->coeffs[i] = 0;
  for (i = N - TAU; i < N; ++i) {
    do {
      if (pos >= SHAKE256_RATE) {
        shake256_squeezeblocks(buf, 1, &state);
        pos = 0;
      }

      b = buf[pos++];
    } while (b > i);

    c->coeffs[i] = c->coeffs[b];
    c->coeffs[b] = 1 - 2 * (signs & 1);
    signs >>= 1;
  }
}

int poly_challenge_with_buf(poly *c, const uint8_t *c_buf, int round, uint64_t *sign) {
  int b;
  int pos = 0;
  uint64_t signs = *sign;

  if (round == N) return round;

  if (round == N - TAU) {
    signs = 0;
    for (int i = 0; i < 8; ++i) signs |= (uint64_t) c_buf[i] << 8 * i;
    pos = 8;
    for (int i = 0; i < N; ++i) c->coeffs[i] = 0;
  }

  for (; round < N; ++round) {
    do {
      if (pos >= SHAKE256_RATE) {
        *sign = signs;
        return round;
      }

      b = c_buf[pos++];
    } while (b > round);

    c->coeffs[round] = c->coeffs[b];
    c->coeffs[b] = 1 - 2 * (signs & 1);
    signs >>= 1;
  }
  *sign = signs;
  return round;
}