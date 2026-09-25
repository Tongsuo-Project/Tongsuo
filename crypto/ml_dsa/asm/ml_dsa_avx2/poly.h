#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "keccak4x/symmetric.h"
#include "align.h"

#define ALIGN(x) __attribute__ ((aligned(x)))

typedef ALIGNED_INT32(N) poly;

#if ETA == 2
typedef uint8_t sword;
#else
typedef uint16_t sword;
#endif

void poly_reduce(poly *a);
void poly_caddq(poly *a);
void poly_freeze(poly *a);

void poly_add(poly *c, const poly *a, const poly *b);
void poly_sub(poly *c, const poly *a, const poly *b);
void poly_shiftl(poly *a);
void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

void poly_power2round(poly *a1, poly *a0, const poly *a);
void poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);
void poly_use_hint(poly *b, const poly *a, const poly *h);

int poly_chknorm(const poly *a, int32_t B);
void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]);
int poly_challenge_with_buf(poly *c, const uint8_t *c_buf, int round, uint64_t *sign);

void poly_ntt_bo(poly *a);

void poly_ntt_so_avx2(poly *a);

void poly_intt_bo(poly *a);

void poly_intt_so_avx2(poly *a);


#endif
