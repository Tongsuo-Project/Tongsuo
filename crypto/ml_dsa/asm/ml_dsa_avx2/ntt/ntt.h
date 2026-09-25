#ifndef DILITHIUM_AVX2_NTT_H
#define DILITHIUM_AVX2_NTT_H

#include <immintrin.h>
#include <stdint.h>
#include "../params.h"



void XRQ_ntt_avx2_bo(int32_t c[256]);

void XRQ_intt_avx2_bo(int32_t c[256]);

void XRQ_ntt_avx2_so(int32_t c[256]);

void XRQ_intt_avx2_so(int32_t c[256]);

void shuffle(int32_t  *c);

void pointwise_avx(int32_t c[N],
                   const int32_t a[N],
                   const int32_t b[N],
                   const int32_t *qdata);

void pointwise_acc_avx(int32_t c[N],
                       const int32_t *a,
                       const int32_t *b,
                       const int32_t *qdata);


#endif
