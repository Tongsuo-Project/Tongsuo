#ifndef DILITHIUM2_AVX2_FIPS202X4_H
#define DILITHIUM2_AVX2_FIPS202X4_H

#include <fips202x4.h>
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

// typedef struct {
//     __m256i s[25];
// } keccakx4_state;

typedef struct {
    __m256i s[25];
} keccakx4_state;

void PQCLEAN_DILITHIUM2_AVX2_f1600x4(__m256i *s, const uint64_t *rc);


void XURQ_AVX2_shake128x4_squeezeblocks(uint8_t *out0,
                                        uint8_t *out1,
                                        uint8_t *out2,
                                        uint8_t *out3,
                                        int nblocks,
                                        keccakx4_state *state);

void XURQ_AVX2_shake256x4_squeezeblocks(uint8_t *out0,
                                        uint8_t *out1,
                                        uint8_t *out2,
                                        uint8_t *out3,
                                        int nblocks,
                                        keccakx4_state *state);




#endif
