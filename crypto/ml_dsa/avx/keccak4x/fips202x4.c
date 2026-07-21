#include "../ml_dsa_avx2_target.h"
#include "fips202.h"
#include "fips202x4.h"
#include "KeccakP-1600-times4-SnP.h"
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>


void XURQ_AVX2_shake128x4_squeezeblocks(uint8_t *out0,
                                        uint8_t *out1,
                                        uint8_t *out2,
                                        uint8_t *out3,
                                        int nblocks,
                                        keccakx4_state *state) {
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i t;

    for (int i = 0; i < nblocks; ++i) {
        KeccakP1600times4_PermuteAll_24rounds(state->s);

        t0 = _mm256_unpacklo_epi64(state->s[0], state->s[1]);
        t1 = _mm256_unpackhi_epi64(state->s[0], state->s[1]);
        t2 = _mm256_unpacklo_epi64(state->s[2], state->s[3]);
        t3 = _mm256_unpackhi_epi64(state->s[2], state->s[3]);

        t4 = _mm256_unpacklo_epi64(state->s[4], state->s[5]);
        t5 = _mm256_unpackhi_epi64(state->s[4], state->s[5]);
        t6 = _mm256_unpacklo_epi64(state->s[6], state->s[7]);
        t7 = _mm256_unpackhi_epi64(state->s[6], state->s[7]);

        f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
        f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
        f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
        f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

        f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
        f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
        f6 = _mm256_permute2x128_si256(t4, t6, 0x31);
        f7 = _mm256_permute2x128_si256(t5, t7, 0x31);


        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) out3, f3);
        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);
        _mm256_storeu_si256((__m256i *) (out3 + 32), f7);

        out0 += 64;
        out1 += 64;
        out2 += 64;
        out3 += 64;

        t0 = _mm256_unpacklo_epi64(state->s[8], state->s[9]);
        t1 = _mm256_unpackhi_epi64(state->s[8], state->s[9]);
        t2 = _mm256_unpacklo_epi64(state->s[10], state->s[11]);
        t3 = _mm256_unpackhi_epi64(state->s[10], state->s[11]);

        t4 = _mm256_unpacklo_epi64(state->s[12], state->s[13]);
        t5 = _mm256_unpackhi_epi64(state->s[12], state->s[13]);
        t6 = _mm256_unpacklo_epi64(state->s[14], state->s[15]);
        t7 = _mm256_unpackhi_epi64(state->s[14], state->s[15]);

        f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
        f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
        f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
        f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

        f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
        f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
        f6 = _mm256_permute2x128_si256(t4, t6, 0x31);
        f7 = _mm256_permute2x128_si256(t5, t7, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) out3, f3);
        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);
        _mm256_storeu_si256((__m256i *) (out3 + 32), f7);

        out0 += 64;
        out1 += 64;
        out2 += 64;
        out3 += 64;

        t0 = _mm256_unpacklo_epi64(state->s[16], state->s[17]);
        t1 = _mm256_unpackhi_epi64(state->s[16], state->s[17]);
        t2 = _mm256_unpacklo_epi64(state->s[18], state->s[19]);
        t3 = _mm256_unpackhi_epi64(state->s[18], state->s[19]);

        f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
        f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
        f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
        f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) out3, f3);

        out0 += 32;
        out1 += 32;
        out2 += 32;
        out3 += 32;

        t = _mm256_castsi256_si128(state->s[20]);
        _mm_storeu_si64(out0, t);
        _mm_storeu_si64(out1, _mm_bsrli_si128(t,8));
        t = _mm256_extracti128_si256(state->s[20], 1);
        _mm_storeu_si64(out2, t);
        _mm_storeu_si64(out3, _mm_bsrli_si128(t,8));

        out0 += 8;
        out1 += 8;
        out2 += 8;
        out3 += 8;

    }


}

void XURQ_AVX2_shake256x4_squeezeblocks(uint8_t *out0,
                                        uint8_t *out1,
                                        uint8_t *out2,
                                        uint8_t *out3,
                                        int nblocks,
                                        keccakx4_state *state) {
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i t;

    for (int i = 0; i < nblocks; ++i) {
        KeccakP1600times4_PermuteAll_24rounds(state->s);

        t0 = _mm256_unpacklo_epi64(state->s[0], state->s[1]);
        t1 = _mm256_unpackhi_epi64(state->s[0], state->s[1]);
        t2 = _mm256_unpacklo_epi64(state->s[2], state->s[3]);
        t3 = _mm256_unpackhi_epi64(state->s[2], state->s[3]);

        t4 = _mm256_unpacklo_epi64(state->s[4], state->s[5]);
        t5 = _mm256_unpackhi_epi64(state->s[4], state->s[5]);
        t6 = _mm256_unpacklo_epi64(state->s[6], state->s[7]);
        t7 = _mm256_unpackhi_epi64(state->s[6], state->s[7]);

        f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
        f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
        f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
        f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

        f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
        f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
        f6 = _mm256_permute2x128_si256(t4, t6, 0x31);
        f7 = _mm256_permute2x128_si256(t5, t7, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) out3, f3);
        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);
        _mm256_storeu_si256((__m256i *) (out3 + 32), f7);

        out0 += 64;
        out1 += 64;
        out2 += 64;
        out3 += 64;

        t0 = _mm256_unpacklo_epi64(state->s[8], state->s[9]);
        t1 = _mm256_unpackhi_epi64(state->s[8], state->s[9]);
        t2 = _mm256_unpacklo_epi64(state->s[10], state->s[11]);
        t3 = _mm256_unpackhi_epi64(state->s[10], state->s[11]);

        t4 = _mm256_unpacklo_epi64(state->s[12], state->s[13]);
        t5 = _mm256_unpackhi_epi64(state->s[12], state->s[13]);
        t6 = _mm256_unpacklo_epi64(state->s[14], state->s[15]);
        t7 = _mm256_unpackhi_epi64(state->s[14], state->s[15]);

        f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
        f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
        f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
        f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

        f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
        f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
        f6 = _mm256_permute2x128_si256(t4, t6, 0x31);
        f7 = _mm256_permute2x128_si256(t5, t7, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) out3, f3);
        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);
        _mm256_storeu_si256((__m256i *) (out3 + 32), f7);

        out0 += 64;
        out1 += 64;
        out2 += 64;
        out3 += 64;


        t = _mm256_castsi256_si128(state->s[16]);
        _mm_storeu_si64(out0, t);
        _mm_storeu_si64(out1, _mm_bsrli_si128(t,8));
        t = _mm256_extracti128_si256(state->s[16], 1);
        _mm_storeu_si64(out2, t);
        _mm_storeu_si64(out3, _mm_bsrli_si128(t,8));

        out0 += 8;
        out1 += 8;
        out2 += 8;
        out3 += 8;
    }


}
