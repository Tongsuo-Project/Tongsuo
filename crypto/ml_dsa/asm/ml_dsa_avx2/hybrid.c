#include "fips202x4.h"
#include "rejsample.h"
#include "hybrid.h"

#include <stdio.h>
#include <string.h>

#include "KeccakP-1600-times4-SnP.h"
#include "ntt.h"
#include "keccak4x/fips202x4.h"


uint8_t *loop_dequeue(loop_queue *loop) {
    int now = loop->start;
    loop->start = (now + 1) % LOOP_SIZE;
    loop->size -= 1;
    return loop->buf[now].coeffs;
}

uint8_t *loop_next(loop_queue *loop) {
    int next = (loop->start + loop->size) % LOOP_SIZE;
    loop->size += 1;
    return loop->buf[next].coeffs;
}

void print_loop_state(loop_queue *loop) {
    printf("loop.start: %d, loop.szie: %d\n", loop->start, loop->size);
}

static uint64_t load64(const uint8_t *x) {
    uint64_t r;
    memcpy(&r, x, sizeof(uint64_t));
    return r;
}

static inline void refresh_ExpandA_states_x3(keccakx4_state *state, const uint8_t *rho, uint16_t nonce0,
                                             uint16_t nonce1, uint16_t nonce2) {
    __m256i f0, f1, f2, f3, f4;
    const __m256i mask = _mm256_set_epi64x(UINT64_MAX, 0, 0, 0);
    const __m256i f5 = _mm256_set_epi64x(0, 0x1ULL << 63, 0x1ULL << 63, 0x1ULL << 63);

    f0 = _mm256_set_epi64x(0, load64(rho), load64(rho), load64(rho));
    f1 = _mm256_set_epi64x(0, load64(rho + 8), load64(rho + 8), load64(rho + 8));
    f2 = _mm256_set_epi64x(0, load64(rho + 16), load64(rho + 16), load64(rho + 16));
    f3 = _mm256_set_epi64x(0, load64(rho + 24), load64(rho + 24), load64(rho + 24));
    f4 = _mm256_set_epi64x(0, (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);

    for (int i = 0; i < 25; ++i) {
        state->s[i] = _mm256_and_si256(state->s[i], mask);
    }

    state->s[0] = _mm256_or_si256(state->s[0], f0);
    state->s[1] = _mm256_or_si256(state->s[1], f1);
    state->s[2] = _mm256_or_si256(state->s[2], f2);
    state->s[3] = _mm256_or_si256(state->s[3], f3);
    state->s[4] = _mm256_or_si256(state->s[4], f4);
    state->s[20] = _mm256_or_si256(state->s[20], f5);
}


static unsigned int rej_uniform(int32_t *a, unsigned int len, const uint8_t *buf, unsigned int buflen) {
    unsigned int ctr, pos;
    uint32_t t;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        t = buf[pos++];
        t |= (uint32_t) buf[pos++] << 8;
        t |= (uint32_t) buf[pos++] << 16;
        t &= 0x7FFFFF;

        if (t < Q) {
            a[ctr++] = t;
        }
    }

    return ctr;
}

static void shake128x3_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2, int nblocks, keccakx4_state *state) {
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

        f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
        f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
        f6 = _mm256_permute2x128_si256(t4, t6, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);

        out0 += 64;
        out1 += 64;
        out2 += 64;

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

        f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
        f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
        f6 = _mm256_permute2x128_si256(t4, t6, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);
        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);

        out0 += 64;
        out1 += 64;
        out2 += 64;

        t0 = _mm256_unpacklo_epi64(state->s[16], state->s[17]);
        t1 = _mm256_unpackhi_epi64(state->s[16], state->s[17]);
        t2 = _mm256_unpacklo_epi64(state->s[18], state->s[19]);
        t3 = _mm256_unpackhi_epi64(state->s[18], state->s[19]);

        f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
        f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
        f2 = _mm256_permute2x128_si256(t0, t2, 0x31);

        _mm256_storeu_si256((__m256i *) out0, f0);
        _mm256_storeu_si256((__m256i *) out1, f1);
        _mm256_storeu_si256((__m256i *) out2, f2);

        out0 += 32;
        out1 += 32;
        out2 += 32;

        t = _mm256_castsi256_si128(state->s[20]);
        *(uint64_t *) out0 = _mm_extract_epi64(t, 0);
        *(uint64_t *) out1 = _mm_extract_epi64(t, 1);
        t = _mm256_extracti128_si256(state->s[20], 1);
        *(uint64_t *) out2 = _mm_extract_epi64(t, 0);

        out0 += 8;
        out1 += 8;
        out2 += 8;
    }
}

void shake128x3_shake256x1_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, int nblocks,
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
        _mm_storeu_si64(out3, _mm256_castsi256_si128(f3));

        out0 += 32;
        out1 += 32;
        out2 += 32;
        out3 += 8;

        t = _mm256_castsi256_si128(state->s[20]);
        *(uint64_t *) out0 = _mm_extract_epi64(t, 0);
        *(uint64_t *) out1 = _mm_extract_epi64(t, 1);
        t = _mm256_extracti128_si256(state->s[20], 1);
        *(uint64_t *) out2 = _mm_extract_epi64(t, 0);

        out0 += 8;
        out1 += 8;
        out2 += 8;
    }
}


// out2 out3 is the results of shake256
// out0, out1 is is the results of shake128
static void shake128x2_shake256x2_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, int nblocks,
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
        _mm_storeu_si64(out2, _mm256_castsi256_si128(f2));
        _mm_storeu_si64(out3, _mm256_castsi256_si128(f3));

        out0 += 32;
        out1 += 32;
        out2 += 8;
        out3 += 8;

        t = _mm256_castsi256_si128(state->s[20]);
        _mm_storeu_si64(out0, t);
        _mm_storeu_si64(out1, _mm_bsrli_si128(t, 8));

        out0 += 8;
        out1 += 8;
    }
}

static void shake128x1_shake256x3_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, int nblocks,
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
        // _mm256_storeu_si256((__m256i *) out1, f1);
        _mm_storeu_si64(out1, _mm256_castsi256_si128(f1));
        _mm_storeu_si64(out2, _mm256_castsi256_si128(f2));
        _mm_storeu_si64(out3, _mm256_castsi256_si128(f3));

        out0 += 32;
        out1 += 8;
        out2 += 8;
        out3 += 8;

        t = _mm256_castsi256_si128(state->s[20]);
        _mm_storeu_si64(out0, t);
        // _mm_storeu_si64(out1, _mm_bsrli_si128(t, 8));

        out0 += 8;
        // out1 += 8;
    }
}

static uint64_t load_in(const uint8_t *x, int len) {
    uint64_t r = 0;
    for (int i = 0; i < len; ++i) {
        r |= (uint64_t)x[i] << (8 * i);
    }
    return r;
}

static void absorb_hash_SHAKE256RATE(keccakx4_state *state, const uint8_t *pk) {
    __m256i f;
    __m256i zero = _mm256_setzero_si256();
    for (int i = 0; i < 17; ++i) {
        f = _mm256_insert_epi64(zero, load64(pk + i * 8), 3);
        state->s[i] = _mm256_xor_si256(state->s[i], f);
    }
}

static void absorb_hash_SHAKE256RATE_tail_process(keccakx4_state *state, const uint8_t *pk, int tail_len) {
    __m256i f;
    int i;
    for (i = 0; i < tail_len / 8; ++i) {
        f = _mm256_set_epi64x(load64(pk + i * 8), 0, 0, 0);
        state->s[i] = _mm256_xor_si256(state->s[i], f);
    }
    f = _mm256_set_epi64x(0x1FULL, 0, 0, 0);
    state->s[tail_len / 8] = _mm256_xor_si256(state->s[tail_len / 8], f);
    f = _mm256_set_epi64x(0x1ULL << 63, 0, 0, 0);
    state->s[16] = _mm256_xor_si256(state->s[16], f);
}

static void absorb_hash_SHAKE256RATE_interval(keccakx4_state *state, const uint8_t *in, int start) {
    __m256i f;
    __m256i zero = _mm256_setzero_si256();
    for (int i = 0; start + i < 17; ++i) {
        f = _mm256_insert_epi64(zero, load64(in + i * 8), 3);
        state->s[start + i] = _mm256_xor_si256(state->s[start + i], f);
    }
}

static void absorb_hash_SHAKE256RATE_tail_process_interval(keccakx4_state *state, const uint8_t *in, int start, int tail_len) {
    __m256i f;
    int l = tail_len & 7;
    int i;
    for (i = 0; i < tail_len / 8; ++i) {
        f = _mm256_set_epi64x(load64(in + i * 8), 0, 0, 0);
        state->s[start + i] = _mm256_xor_si256(state->s[start + i], f);
    }
    f = _mm256_set_epi64x((0x1FULL << (l * 8)) | load_in(in + i * 8, l), 0, 0, 0);
    state->s[start + i] = _mm256_xor_si256(state->s[start + i], f);
    f = _mm256_set_epi64x(0x1ULL << 63, 0, 0, 0);
    state->s[16] = _mm256_xor_si256(state->s[16], f);
}

void extract_lanes_x3_shake128(uint8_t *out0, uint8_t *out1, uint8_t *out2, keccakx4_state *state) {
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i t;


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

    f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
    f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
    f6 = _mm256_permute2x128_si256(t4, t6, 0x31);


    _mm256_storeu_si256((__m256i *) out0, f0);
    _mm256_storeu_si256((__m256i *) out1, f1);
    _mm256_storeu_si256((__m256i *) out2, f2);
    _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
    _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
    _mm256_storeu_si256((__m256i *) (out2 + 32), f6);

    out0 += 64;
    out1 += 64;
    out2 += 64;

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

    f4 = _mm256_permute2x128_si256(t4, t6, 0x20);
    f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
    f6 = _mm256_permute2x128_si256(t4, t6, 0x31);

    _mm256_storeu_si256((__m256i *) out0, f0);
    _mm256_storeu_si256((__m256i *) out1, f1);
    _mm256_storeu_si256((__m256i *) out2, f2);
    _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
    _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
    _mm256_storeu_si256((__m256i *) (out2 + 32), f6);

    out0 += 64;
    out1 += 64;
    out2 += 64;

    t0 = _mm256_unpacklo_epi64(state->s[16], state->s[17]);
    t1 = _mm256_unpackhi_epi64(state->s[16], state->s[17]);
    t2 = _mm256_unpacklo_epi64(state->s[18], state->s[19]);
    t3 = _mm256_unpackhi_epi64(state->s[18], state->s[19]);

    f0 = _mm256_permute2x128_si256(t0, t2, 0x20);
    f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
    f2 = _mm256_permute2x128_si256(t0, t2, 0x31);

    _mm256_storeu_si256((__m256i *) out0, f0);
    _mm256_storeu_si256((__m256i *) out1, f1);
    _mm256_storeu_si256((__m256i *) out2, f2);

    out0 += 32;
    out1 += 32;
    out2 += 32;

    t = _mm256_castsi256_si128(state->s[20]);
    _mm_storeu_si64(out0, t);
    _mm_storeu_si64(out1, _mm_bsrli_si128(t, 8));
    t = _mm256_extracti128_si256(state->s[20], 1);
    _mm_storeu_si64(out2, t);
}

void extract_lanes_x3_shake256(uint8_t *out0,
                                        uint8_t *out1,
                                        uint8_t *out2,
                                        keccakx4_state *state) {
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i t;

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

        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);


        out0 += 64;
        out1 += 64;
        out2 += 64;


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

        _mm256_storeu_si256((__m256i *) (out0 + 32), f4);
        _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
        _mm256_storeu_si256((__m256i *) (out2 + 32), f6);


        out0 += 64;
        out1 += 64;
        out2 += 64;



        t = _mm256_castsi256_si128(state->s[16]);
        _mm_storeu_si64(out0, t);
        _mm_storeu_si64(out1, _mm_bsrli_si128(t,8));
        t = _mm256_extracti128_si256(state->s[16], 1);
        _mm_storeu_si64(out2, t);


        out0 += 8;
        out1 += 8;
        out2 += 8;

}

struct coroutine {
    int max;
    int round;
    unsigned int ctr[3];
};

static void uniform_x3(keccakx4_state *state, polyvecl mat[K], uint8_t buf[4][192], const uint8_t *rho,
                struct coroutine *cor) {
    poly *a0, *a1, *a2;
    int nonce0, nonce1, nonce2;
#if K==4
    switch (cor->round) {
        case 0:
            a0 = &mat[0].vec[0];
            a1 = &mat[0].vec[1];
            a2 = &mat[0].vec[2];
            //nonces for next round
            nonce0 = 3;
            nonce1 = 256;
            nonce2 = 257;
            break;
        case 1:
            a0 = &mat[0].vec[3];
            a1 = &mat[1].vec[0];
            a2 = &mat[1].vec[1];
            break;
        default:
            return;
    }
#elif K==6
    switch (cor->round) {
        case 0:
            a0 = &mat[0].vec[0];
            a1 = &mat[0].vec[1];
            a2 = &mat[0].vec[2];
            //nonces for next round
            nonce0 = 3;
            nonce1 = 4;
            nonce2 = 256;
            break;
        case 1:
            a0 = &mat[0].vec[3];
            a1 = &mat[0].vec[4];
            a2 = &mat[1].vec[0];
            //nonces for next round
            nonce0 = 257;
            nonce1 = 258;
            nonce2 = 259;
            break;
        case 2:
            a0 = &mat[1].vec[1];
            a1 = &mat[1].vec[2];
            a2 = &mat[1].vec[3];
            break;
        default:
            return;
    }
#elif K==8
    switch (cor->round) {
        case 0:
            a0 = &mat[0].vec[0];
            a1 = &mat[0].vec[1];
            a2 = &mat[0].vec[2];
            //nonces for next round
            nonce0 = 3;
            nonce1 = 4;
            nonce2 = 5;
            break;
        case 1:
            a0 = &mat[0].vec[3];
            a1 = &mat[0].vec[4];
            a2 = &mat[0].vec[5];
            //nonces for next round
            nonce0 = 6;
            nonce1 = 256;
            nonce2 = 257;
            break;
        case 2:
            a0 = &mat[0].vec[6];
            a1 = &mat[1].vec[0];
            a2 = &mat[1].vec[1];
            //nonces for next round
            nonce0 = 258;
            nonce1 = 259;
            nonce2 = 260;
            break;
        case 3:
            a0 = &mat[1].vec[2];
            a1 = &mat[1].vec[3];
            a2 = &mat[1].vec[4];
            break;
        default:
            return;
    }
#endif


    if (cor->ctr[0] + 56 < N || cor->ctr[1] + 56 < N || cor->ctr[2] + 56 < N) {
        cor->ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], cor->ctr[0]);
        cor->ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], cor->ctr[1]);
        cor->ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2], cor->ctr[2]);
    } else if (cor->ctr[0] < N || cor->ctr[1] < N || cor->ctr[2] < N) {
        cor->ctr[0] = rej_uniform_avx(a0->coeffs, buf[0], cor->ctr[0]);
        cor->ctr[1] = rej_uniform_avx(a1->coeffs, buf[1], cor->ctr[1]);
        cor->ctr[2] = rej_uniform_avx(a2->coeffs, buf[2], cor->ctr[2]);
        if (cor->ctr[0] >= N && cor->ctr[1] >= N && cor->ctr[2] >= N && cor->round < cor->max) {
            cor->round++;
            refresh_ExpandA_states_x3(state, rho, nonce0, nonce1, nonce2);
            cor->ctr[0] = 0;
            cor->ctr[1] = 0;
            cor->ctr[2] = 0;
        }
    }
}

static void co_uniform_x3(uint8_t buf[4][192], poly *a0, poly *a1, poly *a2, struct coroutine *cor) {
    if (cor->ctr[0] + 56 < N || cor->ctr[1] + 56 < N || cor->ctr[2] + 56 < N) {
        cor->ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], cor->ctr[0]);
        cor->ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], cor->ctr[1]);
        cor->ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2], cor->ctr[2]);
    } else if (cor->ctr[0] < N || cor->ctr[1] < N || cor->ctr[2] < N) {
        cor->ctr[0] = rej_uniform_avx(a0->coeffs, buf[0], cor->ctr[0]);
        cor->ctr[1] = rej_uniform_avx(a1->coeffs, buf[1], cor->ctr[1]);
        cor->ctr[2] = rej_uniform_avx(a2->coeffs, buf[2], cor->ctr[2]);
    }
}

//hash output length 64bytes
void hybrid_hash_ExpandA_shuffled(uint8_t *hash_out, int hash_out_len, const uint8_t *hash_in, int hash_in_len,
                                  poly *a0, poly *a1, poly *a2, const uint8_t *rho, uint16_t nonce0, uint16_t nonce1,
                                  uint16_t nonce2) {
    struct coroutine cor = {.max = 0, .round = 0, .ctr = {0}};
    ALIGN(32) uint8_t buf[4][192];
    keccakx4_state state;
    int tail_len = hash_in_len % SHAKE256_RATE;
    uint8_t *in_ptr = hash_in;

    for (int j = 0; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[0] = _mm256_set_epi64x(0, load64(rho), load64(rho), load64(rho));
    state.s[1] = _mm256_set_epi64x(0, load64(rho + 8), load64(rho + 8), load64(rho + 8));
    state.s[2] = _mm256_set_epi64x(0, load64(rho + 16), load64(rho + 16), load64(rho + 16));
    state.s[3] = _mm256_set_epi64x(0, load64(rho + 24), load64(rho + 24), load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(0, (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);
    state.s[20] = _mm256_set_epi64x(0, 0x1ULL << 63, 0x1ULL << 63, 0x1ULL << 63);

    while (in_ptr + SHAKE256_RATE <= hash_in + hash_in_len) {
        absorb_hash_SHAKE256RATE(&state, in_ptr);
        in_ptr += SHAKE256_RATE;
        KeccakP1600times4_PermuteAll_24rounds(state.s);
        extract_lanes_x3_shake128(buf[0], buf[1], buf[2], &state);
        co_uniform_x3(buf, a0, a1, a2, &cor);
    }
    absorb_hash_SHAKE256RATE_tail_process_interval(&state, in_ptr, 0, tail_len);
    XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);
    memcpy(hash_out, buf[3], CRHBYTES);
    co_uniform_x3(buf, a0, a1, a2, &cor);
    while (cor.ctr[0] < N || cor.ctr[1] < N || cor.ctr[2] < N) {
        shake128x3_squeezeblocks(buf[0], buf[1], buf[2], 1, &state);
        co_uniform_x3(buf, a0, a1, a2, &cor);
    }
    shuffle(a0->coeffs);
    shuffle(a1->coeffs);
    shuffle(a2->coeffs);
}

void hybrid_hash_pk_and_ExpandA(uint8_t *hash_out, const uint8_t *pk, polyvecl mat[K], const uint8_t *rho) {
    struct coroutine cor = {.max = (K - 2) >> 1, .round = 0, .ctr = {0}};
    ALIGN(32) uint8_t buf[4][192];
    keccakx4_state state;
    uint8_t *pk_ptr = pk;
    int tail_len = CRYPTO_PUBLICKEYBYTES % SHAKE256_RATE;

    for (int j = 0; j < 25; ++j) state.s[j] = _mm256_setzero_si256();
    refresh_ExpandA_states_x3(&state, rho, 0, 1, 2);
    while (pk_ptr + SHAKE256_RATE <= pk + CRYPTO_PUBLICKEYBYTES) {
        absorb_hash_SHAKE256RATE(&state, pk_ptr);
        pk_ptr += SHAKE256_RATE;
        KeccakP1600times4_PermuteAll_24rounds(state.s);
        extract_lanes_x3_shake128(buf[0], buf[1], buf[2], &state);
        uniform_x3(&state, mat, buf, rho, &cor);
    }
    absorb_hash_SHAKE256RATE_tail_process(&state, pk_ptr, tail_len);
    XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);
    memmove(hash_out, buf[3], CRHBYTES);
    uniform_x3(&state, mat, buf, rho, &cor);
    while (cor.ctr[0] < N || cor.ctr[1] < N || cor.ctr[2] < N) {
        shake128x3_squeezeblocks(buf[0], buf[1], buf[2], 1, &state);
        cor.ctr[0] += rej_uniform(mat[0].vec[3].coeffs + cor.ctr[0], N - cor.ctr[0], buf[0], SHAKE128_RATE);
        cor.ctr[1] += rej_uniform(mat[1].vec[0].coeffs + cor.ctr[1], N - cor.ctr[1], buf[1], SHAKE128_RATE);
        cor.ctr[2] += rej_uniform(mat[1].vec[1].coeffs + cor.ctr[2], N - cor.ctr[2], buf[2], SHAKE128_RATE);
    }
}

void hybrid_hash_ExpandRand_ExpandA_shuffled(uint8_t *hash_out, const uint8_t *hash_in, int hash_in_len,
                                             loop_queue *loop, poly *a0, poly *a1, poly *a2, const uint8_t *rho,
                                             uint16_t nonce0, uint16_t nonce1, uint16_t nonce2) {
    unsigned int ctr[4] = {0};
    ALIGN(32) uint8_t buf[4][192 * 2];
    keccakx4_state state;
    uint8_t *o1 = loop_next(loop);

    for (int j = 0; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[0] = _mm256_set1_epi64x(load64(rho));
    state.s[1] = _mm256_set1_epi64x(load64(rho + 8) );
    state.s[2] = _mm256_set1_epi64x(load64(rho + 16));
    state.s[3] = _mm256_set1_epi64x(load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(0, (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);

    state.s[20] = _mm256_set_epi64x(0, 0x1ULL << 63, 0x1ULL << 63, 0x1ULL << 63);

    for (int i = 0; i < (hash_in_len + 7) >> 3; ++i) {
        state.s[i] = _mm256_insert_epi64(state.s[i], load64(hash_in + i * 8), 3);
    }
    __m256i f = _mm256_set_epi64x(0x1FULL << ((hash_in_len & 7) * 8), 0, 0, 0);
    state.s[hash_in_len >> 3] = _mm256_xor_si256(state.s[hash_in_len >> 3], f);
    state.s[16] = _mm256_insert_epi64(state.s[16], 0x1ULL << 63, 3);

    XURQ_AVX2_shake128x4_squeezeblocks(buf[0], buf[1], buf[2], buf[3], 1, &state);

    ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], ctr[0]);
    ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], ctr[1]);
    ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2], ctr[2]);
    memmove(hash_out, buf[3], CRHBYTES);
    for (int j = 8; j < 25; ++j) state.s[j] = _mm256_insert_epi64(state.s[j], 0, 3);
    state.s[8] = _mm256_insert_epi64(state.s[8], 0x1f, 3);
    state.s[16] = _mm256_insert_epi64(state.s[16], 0x1ULL << 63, 3);

    for (int i = 0; i < 3; ++i) {
        // shake128x3_squeezeblocks(buf[0], buf[1], buf[2], 1, &state);
        shake128x3_shake256x1_squeezeblocks(buf[0], buf[1], buf[2], o1 + SHAKE256_RATE * i, 1, &state);

        ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], ctr[0]);
        ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], ctr[1]);
        ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2], ctr[2]);
    }

    // shake128x3_squeezeblocks(buf[0], buf[1], buf[2], 1, &state);
    shake128x3_shake256x1_squeezeblocks(buf[0], buf[1], buf[2], o1 + SHAKE256_RATE * 3, 2, &state);

    ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeffs, buf[0], ctr[0]);
    ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a1->coeffs, buf[1], ctr[1]);
    ctr[2] = XURQ_AVX2_rej_uniform_avx_s1s3_final(a2->coeffs, buf[2], ctr[2]);

    while (ctr[0] < N || ctr[1] < N || ctr[2] < N) {
        shake128x3_squeezeblocks(buf[0], buf[1], buf[2], 1, &state);

        ctr[0] += rej_uniform(a0->coeffs + ctr[0], N - ctr[0], buf[0], SHAKE128_RATE);
        ctr[1] += rej_uniform(a1->coeffs + ctr[1], N - ctr[1], buf[1], SHAKE128_RATE);
        ctr[2] += rej_uniform(a2->coeffs + ctr[2], N - ctr[2], buf[2], SHAKE128_RATE);
    }

    shuffle(a0->coeffs);
    shuffle(a1->coeffs);
    shuffle(a2->coeffs);
}


void hybrid_uniform_2x_and_ExpandRand(poly *a0, poly *a1, loop_queue *loop, const uint8_t rho[32],
                                      const uint8_t rhoprime[64], uint16_t nonce0, uint16_t nonce1, uint16_t noncey0,
                                      uint16_t noncey1) {
    unsigned int ctr0 = 0, ctr1 = 0;
    ALIGNED_UINT8(REJ_UNIFORM_BUFLEN + 8) buf[4];
    keccakx4_state state;

    state.s[0] = _mm256_set_epi64x(load64(rhoprime), load64(rhoprime), load64(rho), load64(rho));
    state.s[1] = _mm256_set_epi64x(load64(rhoprime + 8) , load64(rhoprime + 8) , load64(rho + 8) , load64(rho + 8) );
    state.s[2] = _mm256_set_epi64x(load64(rhoprime + 16), load64(rhoprime + 16), load64(rho + 16), load64(rho + 16));
    state.s[3] = _mm256_set_epi64x(load64(rhoprime + 24), load64(rhoprime + 24), load64(rho + 24), load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(load64(rhoprime + 32), load64(rhoprime + 32), (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);
    state.s[5] = _mm256_set_epi64x(load64(rhoprime + 40), load64(rhoprime + 40), 0, 0);
    state.s[6] = _mm256_set_epi64x(load64(rhoprime + 48), load64(rhoprime + 48), 0, 0);
    state.s[7] = _mm256_set_epi64x(load64(rhoprime + 56), load64(rhoprime + 56), 0, 0);
    state.s[8] = _mm256_set_epi64x((0x1f << 16) ^ noncey1, (0x1f << 16) ^ noncey0, 0, 0);

    for (int j = 9; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set_epi64x(0x1ULL << 63, 0x1ULL << 63, 0, 0);
    state.s[20] = _mm256_set_epi64x(0, 0, 0x1ULL << 63, 0x1ULL << 63);

    uint8_t *o1 = loop_next(loop);
    uint8_t *o2 = loop_next(loop);

    shake128x2_shake256x2_squeezeblocks(buf[0].coeffs, buf[1].coeffs, o1, o2, REJ_UNIFORM_NBLOCKS, &state);

    for (int i = 0; i < 4; ++i) {
        ctr0 = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0].coeffs + i * SHAKE128_RATE, ctr0);
        ctr1 = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1].coeffs + i * SHAKE128_RATE, ctr1);
    }

    ctr0 = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeffs, buf[0].coeffs + 4 * SHAKE128_RATE, ctr0);
    ctr1 = XURQ_AVX2_rej_uniform_avx_s1s3_final(a1->coeffs, buf[1].coeffs + 4 * SHAKE128_RATE, ctr1);

    while (ctr0 < N || ctr1 < N) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

        ctr0 += rej_uniform(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, SHAKE128_RATE);
        ctr1 += rej_uniform(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    }
}

void hybrid_uniform_3x_and_ExpandRand(poly *a0, poly *a1, poly *a2, loop_queue *loop, const uint8_t rho[32],
                                      const uint8_t rhoprime[64], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2,
                                      uint16_t noncey0) {
    unsigned int ctr0 = 0, ctr1 = 0, ctr2 = 0;
    ALIGNED_UINT8(REJ_UNIFORM_BUFLEN + 8) buf[3];
    keccakx4_state state;

    state.s[0] = _mm256_set_epi64x(load64(rhoprime), load64(rho), load64(rho), load64(rho));
    state.s[1] = _mm256_set_epi64x(load64(rhoprime + 8) , load64(rho + 8) , load64(rho + 8) , load64(rho + 8) );
    state.s[2] = _mm256_set_epi64x(load64(rhoprime + 16), load64(rho + 16), load64(rho + 16), load64(rho + 16));
    state.s[3] = _mm256_set_epi64x(load64(rhoprime + 24), load64(rho + 24), load64(rho + 24), load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(load64(rhoprime + 32), (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1, (0x1f << 16) ^ nonce0);
    state.s[5] = _mm256_set_epi64x(load64(rhoprime + 40), 0, 0, 0);
    state.s[6] = _mm256_set_epi64x(load64(rhoprime + 48), 0, 0, 0);
    state.s[7] = _mm256_set_epi64x(load64(rhoprime + 56), 0, 0, 0);
    state.s[8] = _mm256_set_epi64x((0x1f << 16) ^ noncey0, 0, 0, 0);

    for (int j = 9; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set_epi64x(0x1ULL << 63, 0, 0, 0);
    state.s[20] = _mm256_set_epi64x(0, 0x1ULL << 63, 0x1ULL << 63, 0x1ULL << 63);

    uint8_t *o1 = loop_next(loop);

    shake128x3_shake256x1_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, o1, REJ_UNIFORM_NBLOCKS, &state);

    for (int i = 0; i < 4; ++i) {
        ctr0 = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0].coeffs + i * SHAKE128_RATE, ctr0);
        ctr1 = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1].coeffs + i * SHAKE128_RATE, ctr1);
        ctr2 = XURQ_AVX2_rej_uniform_avx_s1s3(a2->coeffs, buf[2].coeffs + i * SHAKE128_RATE, ctr2);
    }

    ctr0 = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeffs, buf[0].coeffs + 4 * SHAKE128_RATE, ctr0);
    ctr1 = XURQ_AVX2_rej_uniform_avx_s1s3_final(a1->coeffs, buf[1].coeffs + 4 * SHAKE128_RATE, ctr1);
    ctr2 = XURQ_AVX2_rej_uniform_avx_s1s3_final(a2->coeffs, buf[2].coeffs + 4 * SHAKE128_RATE, ctr2);

    while (ctr0 < N || ctr1 < N || ctr2 < N) {
        shake128x3_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, 1, &state);

        ctr0 += rej_uniform(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, SHAKE128_RATE);
        ctr1 += rej_uniform(a1->coeffs + ctr1, N - ctr1, buf[1].coeffs, SHAKE128_RATE);
        ctr2 += rej_uniform(a2->coeffs + ctr2, N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    }
    shuffle(a0->coeffs);
    shuffle(a1->coeffs);
    shuffle(a2->coeffs);
}

void hybrid_uniform_1x_and_ExpandRand_3x(poly *a0, loop_queue *loop, const uint8_t rho[32],
                                      const uint8_t rhoprime[64], uint16_t nonceA0,
                                      uint16_t noncey0) {
    unsigned int ctr0 = 0, ctr1 = 0, ctr2 = 0;
    ALIGNED_UINT8(REJ_UNIFORM_BUFLEN + 8) buf[3];
    keccakx4_state state;
    uint64_t *rhoprime64 = (uint64_t *) rhoprime;

    state.s[0] = _mm256_set_epi64x(load64(rhoprime), load64(rhoprime), load64(rhoprime), load64(rho));
    state.s[1] = _mm256_set_epi64x(load64(rhoprime + 8) , load64(rhoprime + 8) , load64(rhoprime + 8) , load64(rho + 8) );
    state.s[2] = _mm256_set_epi64x(load64(rhoprime + 16), load64(rhoprime + 16), load64(rhoprime + 16), load64(rho + 16));
    state.s[3] = _mm256_set_epi64x(load64(rhoprime + 24), load64(rhoprime + 24), load64(rhoprime + 24), load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(load64(rhoprime + 32), load64(rhoprime + 32), load64(rhoprime + 32), (0x1f << 16) ^ nonceA0);
    state.s[5] = _mm256_set_epi64x(load64(rhoprime + 40), load64(rhoprime + 40), load64(rhoprime + 40), 0);
    state.s[6] = _mm256_set_epi64x(load64(rhoprime + 48), load64(rhoprime + 48), load64(rhoprime + 48), 0);
    state.s[7] = _mm256_set_epi64x(load64(rhoprime + 56), load64(rhoprime + 56), load64(rhoprime + 56), 0);
    state.s[8] = _mm256_set_epi64x((0x1f << 16) ^ (noncey0 + 2), (0x1f << 16) ^ (noncey0 + 1), (0x1f << 16) ^ noncey0, 0);

    for (int j = 9; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set_epi64x(0x1ULL << 63, 0x1ULL << 63, 0x1ULL << 63, 0);
    state.s[20] = _mm256_set_epi64x(0, 0, 0, 0x1ULL << 63);

    uint8_t *o1 = loop_next(loop);
    uint8_t *o2 = loop_next(loop);
    uint8_t *o3 = loop_next(loop);

    shake128x1_shake256x3_squeezeblocks(buf[0].coeffs,  o1, o2,o3, REJ_UNIFORM_NBLOCKS, &state);

    for (int i = 0; i < 4; ++i) {
        ctr0 = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0].coeffs + i * SHAKE128_RATE, ctr0);
    }
    ctr0 = XURQ_AVX2_rej_uniform_avx_s1s3_final(a0->coeffs, buf[0].coeffs + 4 * SHAKE128_RATE, ctr0);

    while (ctr0 < N ) {
        shake128x3_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, 1, &state);

        ctr0 += rej_uniform(a0->coeffs + ctr0, N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    }

}

//for mldsa.sign
void ExpandA_shuffled_part(polyvecl mat[K], const uint8_t rho[SEEDBYTES], loop_queue *loop, const uint8_t rhoprime[64],
                           uint16_t nonce) {
#if K == 4
    poly_uniform_4x_op13(&mat[0].vec[3],
                         &mat[1].vec[0],
                         &mat[1].vec[1],
                         &mat[1].vec[2], rho, 3, 256, 257, 258);
    shuffle(mat[0].vec[3].coeffs);
    shuffle(mat[1].vec[0].coeffs);
    shuffle(mat[1].vec[1].coeffs);
    shuffle(mat[1].vec[2].coeffs);
    poly_uniform_4x_op13(&mat[1].vec[3],
                         &mat[2].vec[0],
                         &mat[2].vec[1],
                         &mat[2].vec[2], rho, 259, 512, 513, 514);
    shuffle(mat[1].vec[3].coeffs);
    shuffle(mat[2].vec[0].coeffs);
    shuffle(mat[2].vec[1].coeffs);
    shuffle(mat[2].vec[2].coeffs);
    poly_uniform_4x_op13(&mat[2].vec[3],
                         &mat[3].vec[0],
                         &mat[3].vec[1],
                         &mat[3].vec[2], rho, 515, 768, 769, 770);
    shuffle(mat[2].vec[3].coeffs);
    shuffle(mat[3].vec[0].coeffs);
    shuffle(mat[3].vec[1].coeffs);
    shuffle(mat[3].vec[2].coeffs);
    hybrid_uniform_1x_and_ExpandRand_3x(&mat[3].vec[3], loop, rho, rhoprime, 771,nonce);
    shuffle(mat[3].vec[3].coeffs);

#elif K == 6
    hybrid_uniform_3x_and_ExpandRand(&mat[0].vec[3], &mat[0].vec[4], &mat[1].vec[0], loop, rho, rhoprime, 3, 4, 256,0);
    poly_uniform_4x_op13(&mat[1].vec[1], &mat[1].vec[2], &mat[1].vec[3], &mat[1].vec[4], rho, 257, 258, 259, 260);
    shuffle(mat[1].vec[1].coeffs);
    shuffle(mat[1].vec[2].coeffs);
    shuffle(mat[1].vec[3].coeffs);
    shuffle(mat[1].vec[4].coeffs);
    poly_uniform_4x_op13(&mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], &mat[2].vec[3], rho, 512, 513, 514, 515);
    shuffle(mat[2].vec[0].coeffs);
    shuffle(mat[2].vec[1].coeffs);
    shuffle(mat[2].vec[2].coeffs);
    shuffle(mat[2].vec[3].coeffs);
    poly_uniform_4x_op13(&mat[2].vec[4], &mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], rho, 516, 768, 769, 770);
    shuffle(mat[2].vec[4].coeffs);
    shuffle(mat[3].vec[0].coeffs);
    shuffle(mat[3].vec[1].coeffs);
    shuffle(mat[3].vec[2].coeffs);
    poly_uniform_4x_op13(&mat[3].vec[3], &mat[3].vec[4], &mat[4].vec[0], &mat[4].vec[1], rho, 771, 772, 1024, 1025);
    shuffle(mat[3].vec[3].coeffs);
    shuffle(mat[3].vec[4].coeffs);
    shuffle(mat[4].vec[0].coeffs);
    shuffle(mat[4].vec[1].coeffs);
    poly_uniform_4x_op13(&mat[4].vec[2], &mat[4].vec[3], &mat[4].vec[4], &mat[5].vec[0], rho, 1026, 1027, 1028, 1280);
    shuffle(mat[4].vec[2].coeffs);
    shuffle(mat[4].vec[3].coeffs);
    shuffle(mat[4].vec[4].coeffs);
    shuffle(mat[5].vec[0].coeffs);
    poly_uniform_4x_op13(&mat[5].vec[1], &mat[5].vec[2], &mat[5].vec[3], &mat[5].vec[4],
                                                        rho, 1281, 1282, 1283,
                                                        1284);
    shuffle(mat[5].vec[1].coeffs);
    shuffle(mat[5].vec[2].coeffs);
    shuffle(mat[5].vec[3].coeffs);
    shuffle(mat[5].vec[4].coeffs);
#elif K == 8
    /* row 0 */
    poly_uniform_4x_op13(
        &mat[0].vec[3],
        &mat[0].vec[4],
        &mat[0].vec[5],
        &mat[0].vec[6], rho, 3, 4, 5, 6);
    shuffle(mat[0].vec[3].coeffs);
    shuffle(mat[0].vec[4].coeffs);
    shuffle(mat[0].vec[5].coeffs);
    shuffle(mat[0].vec[6].coeffs);

    poly_uniform_4x_op13(
    &mat[1].vec[0],
    &mat[1].vec[1],
    &mat[1].vec[2],
    &mat[1].vec[3], rho, 256, 257, 258, 259);
    shuffle(mat[1].vec[0].coeffs);
    shuffle(mat[1].vec[1].coeffs);
    shuffle(mat[1].vec[2].coeffs);
    shuffle(mat[1].vec[3].coeffs);

    poly_uniform_4x_op13(
&mat[1].vec[4],
&mat[1].vec[5],
&mat[1].vec[6],
&mat[2].vec[0], rho, 260, 261, 262, 512);
    shuffle(mat[1].vec[4].coeffs);
    shuffle(mat[1].vec[5].coeffs);
    shuffle(mat[1].vec[6].coeffs);
    shuffle(mat[2].vec[0].coeffs);

    poly_uniform_4x_op13(
&mat[2].vec[1],
&mat[2].vec[2],
&mat[2].vec[3],
&mat[2].vec[4], rho, 513, 514, 515, 516);
    shuffle(mat[2].vec[1].coeffs);
    shuffle(mat[2].vec[2].coeffs);
    shuffle(mat[2].vec[3].coeffs);
    shuffle(mat[2].vec[4].coeffs);

    poly_uniform_4x_op13(
&mat[2].vec[5],
&mat[2].vec[6],
&mat[3].vec[0],
&mat[3].vec[1], rho, 517, 518, 768, 769);
    shuffle(mat[2].vec[5].coeffs);
    shuffle(mat[2].vec[6].coeffs);
    shuffle(mat[3].vec[0].coeffs);
    shuffle(mat[3].vec[1].coeffs);

    poly_uniform_4x_op13(
&mat[3].vec[2],
&mat[3].vec[3],
&mat[3].vec[4],
&mat[3].vec[5], rho, 770, 771, 772, 773);
    shuffle(mat[3].vec[2].coeffs);
    shuffle(mat[3].vec[3].coeffs);
    shuffle(mat[3].vec[4].coeffs);
    shuffle(mat[3].vec[5].coeffs);

    poly_uniform_4x_op13(
&mat[3].vec[6],
&mat[4].vec[0],
&mat[4].vec[1],
&mat[4].vec[2], rho, 774, 1024, 1025, 1026);
    shuffle(mat[3].vec[6].coeffs);
    shuffle(mat[4].vec[0].coeffs);
    shuffle(mat[4].vec[1].coeffs);
    shuffle(mat[4].vec[2].coeffs);

    poly_uniform_4x_op13(
&mat[4].vec[3],
&mat[4].vec[4],
&mat[4].vec[5],
&mat[4].vec[6], rho, 1027, 1028, 1029, 1030);
    shuffle(mat[4].vec[3].coeffs);
    shuffle(mat[4].vec[4].coeffs);
    shuffle(mat[4].vec[5].coeffs);
    shuffle(mat[4].vec[6].coeffs);

    poly_uniform_4x_op13(
&mat[5].vec[0],
&mat[5].vec[1],
&mat[5].vec[2],
&mat[5].vec[3], rho, 1280, 1281, 1282, 1283);
    shuffle(mat[5].vec[0].coeffs);
    shuffle(mat[5].vec[1].coeffs);
    shuffle(mat[5].vec[2].coeffs);
    shuffle(mat[5].vec[3].coeffs);

    poly_uniform_4x_op13(
&mat[5].vec[4],
&mat[5].vec[5],
&mat[5].vec[6],
&mat[6].vec[0], rho, 1284, 1285, 1286, 1536);
    shuffle(mat[5].vec[4].coeffs);
    shuffle(mat[5].vec[5].coeffs);
    shuffle(mat[5].vec[6].coeffs);
    shuffle(mat[6].vec[0].coeffs);

    poly_uniform_4x_op13(
&mat[6].vec[1],
&mat[6].vec[2],
&mat[6].vec[3],
&mat[6].vec[4], rho, 1537, 1538, 1539, 1540);
    shuffle(mat[6].vec[1].coeffs);
    shuffle(mat[6].vec[2].coeffs);
    shuffle(mat[6].vec[3].coeffs);
    shuffle(mat[6].vec[4].coeffs);

    poly_uniform_4x_op13(
&mat[6].vec[5],
&mat[6].vec[6],
&mat[7].vec[0],
&mat[7].vec[1], rho, 1541, 1542, 1792, 1793);
    shuffle(mat[6].vec[5].coeffs);
    shuffle(mat[6].vec[6].coeffs);
    shuffle(mat[7].vec[0].coeffs);
    shuffle(mat[7].vec[1].coeffs);

    poly_uniform_4x_op13(
&mat[7].vec[2],
&mat[7].vec[3],
&mat[7].vec[4],
&mat[7].vec[5], rho, 1794, 1795, 1796, 1797);
    shuffle(mat[7].vec[2].coeffs);
    shuffle(mat[7].vec[3].coeffs);
    shuffle(mat[7].vec[4].coeffs);
    shuffle(mat[7].vec[5].coeffs);
    hybrid_uniform_1x_and_ExpandRand_3x(&mat[7].vec[6], loop, rho, rhoprime, 1798,nonce);
    shuffle(mat[7].vec[6].coeffs);


    // hybrid_uniform_3x_and_ExpandRand(&mat[0].vec[3], &mat[0].vec[4],&mat[0].vec[5], loop, rho, rhoprime, 3, 4, 5, 0);
    // poly_uniform_4x_op13(&mat[0].vec[6], &mat[1].vec[0], &mat[1].vec[1], &mat[1].vec[2], rho, 6, 256, 257, 258);
    // shuffle(mat[0].vec[6].coeffs);
    // shuffle(mat[1].vec[0].coeffs);
    // shuffle(mat[1].vec[1].coeffs);
    // shuffle(mat[1].vec[2].coeffs);
    //
    // /* row 1 */
    // poly_uniform_4x_op13(&mat[1].vec[3], &mat[1].vec[4], &mat[1].vec[5], &mat[1].vec[6], rho, 259, 260, 261, 262);
    // shuffle(mat[1].vec[3].coeffs);
    // shuffle(mat[1].vec[4].coeffs);
    // shuffle(mat[1].vec[5].coeffs);
    // shuffle(mat[1].vec[6].coeffs);
    // poly_uniform_4x_op13(&mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], &mat[2].vec[3],
    //                                                     rho, 512, 513, 514, 515);
    // shuffle(mat[2].vec[0].coeffs);
    // shuffle(mat[2].vec[1].coeffs);
    // shuffle(mat[2].vec[2].coeffs);
    // shuffle(mat[2].vec[3].coeffs);
    //
    // /* row 2 */
    // poly_uniform_4x_op13(&mat[2].vec[4], &mat[2].vec[5], &mat[2].vec[6], &mat[3].vec[0], rho, 516, 517, 518, 768);
    // shuffle(mat[2].vec[4].coeffs);
    // shuffle(mat[2].vec[5].coeffs);
    // shuffle(mat[2].vec[6].coeffs);
    // shuffle(mat[3].vec[0].coeffs);
    // poly_uniform_4x_op13(&mat[3].vec[1], &mat[3].vec[2], &mat[3].vec[3], &mat[3].vec[4],
    //                                                     rho, 769, 770, 771, 772);
    // shuffle(mat[3].vec[1].coeffs); shuffle(
    //     mat[3].vec[2].coeffs);
    // shuffle(mat[3].vec[3].coeffs);
    // shuffle(mat[3].vec[4].coeffs);
    //
    // /* row 3 */
    // poly_uniform_4x_op13(&mat[3].vec[5], &mat[3].vec[6], &mat[4].vec[0], &mat[4].vec[1], rho, 773, 774, 1024, 1025);
    // shuffle(mat[3].vec[5].coeffs);
    // shuffle(mat[3].vec[6].coeffs);
    // shuffle(mat[4].vec[0].coeffs);
    // shuffle(mat[4].vec[1].coeffs);
    //
    // /* row 4 */
    // poly_uniform_4x_op13(&mat[4].vec[2], &mat[4].vec[3], &mat[4].vec[4], &mat[4].vec[5], rho, 1026, 1027, 1028, 1029);
    // shuffle(mat[4].vec[2].coeffs);
    // shuffle(mat[4].vec[3].coeffs);
    // shuffle(mat[4].vec[4].coeffs);
    // shuffle(mat[4].vec[5].coeffs);
    // poly_uniform_4x_op13(&mat[4].vec[6], &mat[5].vec[0], &mat[5].vec[1], &mat[5].vec[2],
    //                                                     rho, 1030, 1280, 1281, 1282);
    // shuffle(mat[4].vec[6].coeffs);
    // shuffle(mat[5].vec[0].coeffs);
    // shuffle(mat[5].vec[1].coeffs);
    // shuffle(mat[5].vec[2].coeffs);
    //
    // /* row 5 */
    // poly_uniform_4x_op13(&mat[5].vec[3], &mat[5].vec[4], &mat[5].vec[5], &mat[5].vec[6], rho, 1283, 1284, 1285, 1286);
    // shuffle(mat[5].vec[3].coeffs);
    // shuffle(mat[5].vec[4].coeffs);
    // shuffle(mat[5].vec[5].coeffs);
    // shuffle(mat[5].vec[6].coeffs);
    // poly_uniform_4x_op13(&mat[6].vec[0], &mat[6].vec[1], &mat[6].vec[2], &mat[6].vec[3],
    //                                                     rho, 1536, 1537, 1538, 1539);
    // shuffle(mat[6].vec[0].coeffs);
    // shuffle(mat[6].vec[1].coeffs);
    // shuffle(mat[6].vec[2].coeffs);
    // shuffle(mat[6].vec[3].coeffs);
    //
    // /* row 6 */
    // poly_uniform_4x_op13(&mat[6].vec[4], &mat[6].vec[5], &mat[6].vec[6], &mat[7].vec[0], rho, 1540, 1541, 1542, 1792);
    // shuffle(mat[6].vec[4].coeffs);
    // shuffle(mat[6].vec[5].coeffs);
    // shuffle(mat[6].vec[6].coeffs);
    // shuffle(mat[7].vec[0].coeffs);
    // poly_uniform_4x_op13(&mat[7].vec[1], &mat[7].vec[2], &mat[7].vec[3], &mat[7].vec[4],
    //                                                     rho, 1793, 1794, 1795, 1796);
    // shuffle(mat[7].vec[1].coeffs);
    // shuffle(mat[7].vec[2].coeffs);
    // shuffle(mat[7].vec[3].coeffs);
    // shuffle(mat[7].vec[4].coeffs);
    //
    // /* row 7 */
    // hybrid_uniform_2x_and_ExpandRand(&mat[7].vec[5], &mat[7].vec[6], loop, rho, rhoprime, 1797, 1798, nonce, nonce + 1);
    // shuffle(mat[7].vec[5].coeffs); shuffle(mat[7].vec[6].coeffs);
#endif
}


static void co_uniform_x2(poly *a0, poly *a1, uint8_t buf[4][192],struct coroutine *cor) {
    if (cor->ctr[0] + 56 < N || cor->ctr[1] + 56 < N ) {
        cor->ctr[0] = XURQ_AVX2_rej_uniform_avx_s1s3(a0->coeffs, buf[0], cor->ctr[0]);
        cor->ctr[1] = XURQ_AVX2_rej_uniform_avx_s1s3(a1->coeffs, buf[1], cor->ctr[1]);
    } else if (cor->ctr[0] < N || cor->ctr[1] < N ) {
        cor->ctr[0] = rej_uniform_avx(a0->coeffs, buf[0], cor->ctr[0]);
        cor->ctr[1] = rej_uniform_avx(a1->coeffs, buf[1], cor->ctr[1]);
    }
}

void hybrid_hash_mu_and_uniform(uint8_t *mu, poly *c, poly *a0, poly*a1, uint8_t *tr, const uint8_t *m, const uint8_t *c_seed, int mlen, const uint8_t *rho, uint16_t nonce0, uint16_t nonce1) {
    ALIGN(32) uint8_t buf[4][192];
    keccakx4_state state;
    int len = CRHBYTES + mlen;
    struct coroutine cor = {.max = 0, .round = 0, .ctr = {0}};
    int round = N - TAU;
    uint64_t sign;

    for (int j = 8; j < 25; ++j) state.s[j] = _mm256_setzero_si256();
#if K==4
    state.s[0] = _mm256_set_epi64x(load64(tr),      load64(c_seed), load64(rho), load64(rho));
    state.s[1] = _mm256_set_epi64x(load64(tr + 8) , load64(c_seed + 8), load64(rho + 8), load64(rho + 8));
    state.s[2] = _mm256_set_epi64x(load64(tr + 16), load64(c_seed + 16), load64(rho + 16), load64(rho + 16));
    state.s[3] = _mm256_set_epi64x(load64(tr + 24), load64(c_seed + 24), load64(rho + 24), load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(load64(tr + 32), 0x1fULL, (0x1fULL << 16) ^ nonce1, (0x1fULL << 16) ^ nonce0);
    state.s[5] = _mm256_set_epi64x(load64(tr + 40), 0, 0, 0);
    state.s[6] = _mm256_set_epi64x(load64(tr + 48), 0, 0, 0);
    state.s[7] = _mm256_set_epi64x(load64(tr + 56), 0, 0, 0);
#elif K== 6
    state.s[0] = _mm256_set_epi64x(load64(tr),      load64(c_seed), load64(rho), load64(rho));
    state.s[1] = _mm256_set_epi64x(load64(tr + 8) , load64(c_seed + 8), load64(rho + 8), load64(rho + 8));
    state.s[2] = _mm256_set_epi64x(load64(tr + 16), load64(c_seed + 16), load64(rho + 16), load64(rho + 16));
    state.s[3] = _mm256_set_epi64x(load64(tr + 24), load64(c_seed + 24), load64(rho + 24), load64(rho + 24));
    state.s[4] = _mm256_set_epi64x(load64(tr + 32), load64(c_seed + 32), (0x1fULL << 16) ^ nonce1, (0x1fULL << 16) ^ nonce0);
    state.s[5] = _mm256_set_epi64x(load64(tr + 40), load64(c_seed + 40), 0, 0);
    state.s[6] = _mm256_set_epi64x(load64(tr + 48), 0x1fULL, 0, 0);
    state.s[7] = _mm256_set_epi64x(load64(tr + 56), 0, 0, 0);
#endif

    state.s[16] = _mm256_set_epi64x(0,0x1ULL << 63, 0,  0);
    state.s[20] = _mm256_set_epi64x(0, 0, 0x1ULL << 63, 0x1ULL << 63);
    int start = 8;
    while (len >= SHAKE256_RATE) {
        absorb_hash_SHAKE256RATE_interval(&state, m, start);  // abosrb m
        m += SHAKE256_RATE - start * 8;
        len -= SHAKE256_RATE;
        KeccakP1600times4_PermuteAll_24rounds(state.s);
        extract_lanes_x3_shake128(buf[0], buf[1], buf[2], &state);
        co_uniform_x2(a0, a1, buf, &cor);   // sample A
        if (round != N) round = poly_challenge_with_buf(c,buf[2],round,&sign); // sample c
        start = 0;
    }
    absorb_hash_SHAKE256RATE_tail_process_interval(&state, m, start, len - start * 8);
    XURQ_AVX2_shake128x4_squeezeblocks(buf[0],buf[1],buf[2],buf[3],1,&state);
    co_uniform_x2(a0, a1, buf, &cor);
    if (round != N) round = poly_challenge_with_buf(c,buf[2],round,&sign);
    memcpy(mu, buf[3], CRHBYTES);

    while(cor.ctr[0] < N || cor.ctr[1] < N || round != N ) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0],buf[1],buf[2],buf[3],1,&state);
        if (round != N) round = poly_challenge_with_buf(c,buf[2],round,&sign);
        co_uniform_x2(a0, a1, buf, &cor);
    }
}

void hybrid_hash_mu_and_challenge(uint8_t *mu, poly *c, uint8_t *tr, const uint8_t *m, const uint8_t *c_seed, int mlen) {
    ALIGN(32) uint8_t buf[4][192];
    keccakx4_state state;
    int len = CRHBYTES + mlen;
    int round = N - TAU;
    uint64_t sign;

    for (int j = 8; j < 25; ++j) state.s[j] = _mm256_setzero_si256();
    state.s[0] = _mm256_set_epi64x(load64(tr), load64(c_seed), 0, 0);
    state.s[1] = _mm256_set_epi64x(load64(tr + 8), load64(c_seed + 8), 0, 0);
    state.s[2] = _mm256_set_epi64x(load64(tr + 16), load64(c_seed + 16), 0, 0);
    state.s[3] = _mm256_set_epi64x(load64(tr + 24), load64(c_seed + 24), 0, 0);
    state.s[4] = _mm256_set_epi64x(load64(tr + 32), load64(c_seed + 32), 0, 0);
    state.s[5] = _mm256_set_epi64x(load64(tr + 40), load64(c_seed + 40), 0, 0);
    state.s[6] = _mm256_set_epi64x(load64(tr + 48), load64(c_seed + 48), 0, 0);
    state.s[7] = _mm256_set_epi64x(load64(tr + 56), load64(c_seed + 56), 0, 0);
    state.s[8] = _mm256_set_epi64x(0, 0x1fULL, 0, 0);
    state.s[16] = _mm256_set_epi64x(0,0x1ULL << 63, 0,  0);
    int start = 8;
    while (len >= SHAKE256_RATE) {
        absorb_hash_SHAKE256RATE_interval(&state, m, start);  // abosrb m
        m += SHAKE256_RATE - start * 8;
        len -= SHAKE256_RATE;
        KeccakP1600times4_PermuteAll_24rounds(state.s);
        extract_lanes_x3_shake128(buf[0], buf[1], buf[2], &state);
        if (round != N) round = poly_challenge_with_buf(c,buf[2],round,&sign); // sample c
        start = 0;
    }
    absorb_hash_SHAKE256RATE_tail_process_interval(&state, m, start, len - start * 8);
    XURQ_AVX2_shake128x4_squeezeblocks(buf[0],buf[1],buf[2],buf[3],1,&state);
    if (round != N) round = poly_challenge_with_buf(c, buf[2],round,&sign);
    memcpy(mu, buf[3], CRHBYTES);

    while(round != N ) {
        XURQ_AVX2_shake128x4_squeezeblocks(buf[0],buf[1],buf[2],buf[3],1,&state);
        round = poly_challenge_with_buf(c,buf[2],round,&sign);
    }
}

//for mldsa.verify
void hybrid_ExpandA_and_hashof_mu_and_challenge(polyvecl mat[K], const uint8_t rho[SEEDBYTES],
uint8_t *mu,uint8_t *tr, const uint8_t *m,int mlen,
poly *c,const uint8_t *c_seed) {
#if K == 4
    poly_uniform_4x_op13(&mat[1].vec[2], &mat[1].vec[3], &mat[2].vec[0], &mat[2].vec[1], rho, 258, 259, 512, 513);
    poly_uniform_4x_op13(&mat[2].vec[2], &mat[2].vec[3], &mat[3].vec[0], &mat[3].vec[1], rho, 514, 515, 768, 769);
    hybrid_hash_mu_and_uniform(mu, c, &mat[3].vec[2], &mat[3].vec[3], tr, m, c_seed,  mlen, rho, 770, 771);
#elif K == 6
    poly r0, r1, r2;
    poly_uniform_4x_op13(&mat[1].vec[4], &mat[2].vec[0], &mat[2].vec[1], &mat[2].vec[2], rho, 260, 512, 513, 514);
    poly_uniform_4x_op13(&mat[2].vec[3], &mat[2].vec[4], &mat[3].vec[0], &mat[3].vec[1], rho, 515, 516, 768, 769);
    poly_uniform_4x_op13(&mat[3].vec[2], &mat[3].vec[3], &mat[3].vec[4], &mat[4].vec[0], rho, 770, 771, 772, 1024);
    poly_uniform_4x_op13(&mat[4].vec[1], &mat[4].vec[2], &mat[4].vec[3], &mat[4].vec[4], rho, 1025, 1026, 1027, 1028);
    poly_uniform_4x_op13(&mat[5].vec[0], &mat[5].vec[1], &mat[5].vec[2], &mat[5].vec[3], rho, 1280, 1281, 1282, 1283);
    hybrid_hash_mu_and_uniform(mu, c, &mat[5].vec[4], &r0, tr, m, c_seed,  mlen, rho, 1284, 0);
    #elif K == 8
    poly_uniform_4x_op13(&mat[1].vec[5], &mat[1].vec[6], &mat[2].vec[0], &mat[2].vec[1], rho, 261, 262, 512, 513);
    poly_uniform_4x_op13(&mat[2].vec[2], &mat[2].vec[3], &mat[2].vec[4], &mat[2].vec[5], rho, 514, 515, 516, 517);
    poly_uniform_4x_op13(&mat[2].vec[6], &mat[3].vec[0], &mat[3].vec[1], &mat[3].vec[2], rho, 518, 768, 769, 770);
    poly_uniform_4x_op13(&mat[3].vec[3], &mat[3].vec[4], &mat[3].vec[5], &mat[3].vec[6], rho, 771, 772, 773, 774);
    poly_uniform_4x_op13(&mat[4].vec[0], &mat[4].vec[1], &mat[4].vec[2], &mat[4].vec[3], rho, 1024, 1025, 1026, 1027);
    poly_uniform_4x_op13(&mat[4].vec[4], &mat[4].vec[5], &mat[4].vec[6], &mat[5].vec[0], rho, 1028, 1029, 1030, 1280);
    poly_uniform_4x_op13(&mat[5].vec[1], &mat[5].vec[2], &mat[5].vec[3], &mat[5].vec[4], rho, 1281, 1282, 1283, 1284);
    poly_uniform_4x_op13(&mat[5].vec[5], &mat[5].vec[6], &mat[6].vec[0], &mat[6].vec[1], rho, 1285, 1286, 1536, 1537);
    poly_uniform_4x_op13(&mat[6].vec[2], &mat[6].vec[3], &mat[6].vec[4], &mat[6].vec[5], rho, 1538, 1539, 1540, 1541);
    poly_uniform_4x_op13(&mat[6].vec[6], &mat[7].vec[0], &mat[7].vec[1], &mat[7].vec[2], rho, 1542, 1792, 1793, 1794);
    poly_uniform_4x_op13(&mat[7].vec[3], &mat[7].vec[4], &mat[7].vec[5], &mat[7].vec[6], rho, 1795, 1796, 1797, 1798);
    hybrid_hash_mu_and_challenge(mu, c, tr, m, c_seed, mlen);
    #endif
}

static void state_trans4x4(__m256i * s, __m256i f0, __m256i f1, __m256i f2, __m256i f3) {
    __m256i t0, t1, t2, t3;
    t0 = _mm256_unpacklo_epi64(f0, f1);
    t1 = _mm256_unpackhi_epi64(f0, f1);
    t2 = _mm256_unpacklo_epi64(f2, f3);
    t3 = _mm256_unpackhi_epi64(f2, f3);

    s[0] = _mm256_permute2x128_si256(t0, t2, 0x20);
    s[1] = _mm256_permute2x128_si256(t1, t3, 0x20);
    s[2] = _mm256_permute2x128_si256(t0, t2, 0x31);
    s[3] = _mm256_permute2x128_si256(t1, t3, 0x31);
}


void poly_generate_random_gamma1_4x_state_trans(loop_queue *loop, const uint8_t seed[64], uint16_t nonce0, uint16_t nonce1,
                                    uint16_t nonce2, uint16_t nonce3) {
    keccakx4_state state;
    uint64_t *seed64 = (uint64_t *) seed;
    uint8_t *y_buff1, *y_buff2, *y_buff3, *y_buff4;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;;

    f0 = _mm256_loadu_si256((__m256i *)seed);
    f1 = f0;
    f2 = f0;
    f3 = f0;
    state_trans4x4(state.s, f0,f1,f2,f3);
    f4 = _mm256_loadu_si256((__m256i *)(seed + 32));
    f5 = f4;
    f6 = f4;
    f7 = f4;
    state_trans4x4(state.s + 4, f4, f5, f6, f7);

    // state.s[0] = _mm256_set1_epi64x(seed64[0]);
    // state.s[1] = _mm256_set1_epi64x(seed64[1]);
    // state.s[2] = _mm256_set1_epi64x(seed64[2]);
    // state.s[3] = _mm256_set1_epi64x(seed64[3]);
    // state.s[4] = _mm256_set1_epi64x(seed64[4]);
    // state.s[5] = _mm256_set1_epi64x(seed64[5]);
    // state.s[6] = _mm256_set1_epi64x(seed64[6]);
    // state.s[7] = _mm256_set1_epi64x(seed64[7]);
    state.s[8] = _mm256_set_epi64x((0x1f << 16) ^ nonce3, (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1,
                                   (0x1f << 16) ^ nonce0);

    for (int j = 9; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    y_buff1 = loop_next(loop);
    y_buff2 = loop_next(loop);
    y_buff3 = loop_next(loop);
    y_buff4 = loop_next(loop);

    XURQ_AVX2_shake256x4_squeezeblocks(y_buff1, y_buff2, y_buff3, y_buff4, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
}

void poly_generate_random_gamma1_4x(loop_queue *loop, const uint8_t seed[64], uint16_t nonce0, uint16_t nonce1,
                                    uint16_t nonce2, uint16_t nonce3) {
    keccakx4_state state;
    uint64_t *seed64 = (uint64_t *) seed;
    uint8_t *y_buff1, *y_buff2, *y_buff3, *y_buff4;

    state.s[0] = _mm256_set1_epi64x(seed64[0]);
    state.s[1] = _mm256_set1_epi64x(seed64[1]);
    state.s[2] = _mm256_set1_epi64x(seed64[2]);
    state.s[3] = _mm256_set1_epi64x(seed64[3]);
    state.s[4] = _mm256_set1_epi64x(seed64[4]);
    state.s[5] = _mm256_set1_epi64x(seed64[5]);
    state.s[6] = _mm256_set1_epi64x(seed64[6]);
    state.s[7] = _mm256_set1_epi64x(seed64[7]);
    state.s[8] = _mm256_set_epi64x((0x1f << 16) ^ nonce3, (0x1f << 16) ^ nonce2, (0x1f << 16) ^ nonce1,
                                   (0x1f << 16) ^ nonce0);

    for (int j = 9; j < 25; ++j) state.s[j] = _mm256_setzero_si256();

    state.s[16] = _mm256_set1_epi64x(0x1ULL << 63);

    y_buff1 = loop_next(loop);
    y_buff2 = loop_next(loop);
    y_buff3 = loop_next(loop);
    y_buff4 = loop_next(loop);

    XURQ_AVX2_shake256x4_squeezeblocks(y_buff1, y_buff2, y_buff3, y_buff4, POLY_UNIFORM_GAMMA1_NBLOCKS, &state);
}


static void extract_last_three_lanes_from_shake256_state(uint8_t *out1, uint8_t *out2, uint8_t *out3,
                                                         const keccakx4_state *state) {
    __m256i t0, t1, t2, t3, t4, t5, t6, t7;
    __m256i f0, f1, f2, f3, f4, f5, f6, f7;
    __m128i t;


    t0 = _mm256_unpacklo_epi64(state->s[0], state->s[1]);
    t1 = _mm256_unpackhi_epi64(state->s[0], state->s[1]);
    t2 = _mm256_unpacklo_epi64(state->s[2], state->s[3]);
    t3 = _mm256_unpackhi_epi64(state->s[2], state->s[3]);

    t4 = _mm256_unpacklo_epi64(state->s[4], state->s[5]);
    t5 = _mm256_unpackhi_epi64(state->s[4], state->s[5]);
    t6 = _mm256_unpacklo_epi64(state->s[6], state->s[7]);
    t7 = _mm256_unpackhi_epi64(state->s[6], state->s[7]);

    f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
    f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
    f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

    f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
    f6 = _mm256_permute2x128_si256(t4, t6, 0x31);
    f7 = _mm256_permute2x128_si256(t5, t7, 0x31);

    _mm256_storeu_si256((__m256i *) out1, f1);
    _mm256_storeu_si256((__m256i *) out2, f2);
    _mm256_storeu_si256((__m256i *) out3, f3);
    _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
    _mm256_storeu_si256((__m256i *) (out2 + 32), f6);
    _mm256_storeu_si256((__m256i *) (out3 + 32), f7);

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

    f1 = _mm256_permute2x128_si256(t1, t3, 0x20);
    f2 = _mm256_permute2x128_si256(t0, t2, 0x31);
    f3 = _mm256_permute2x128_si256(t1, t3, 0x31);

    f5 = _mm256_permute2x128_si256(t5, t7, 0x20);
    f6 = _mm256_permute2x128_si256(t4, t6, 0x31);
    f7 = _mm256_permute2x128_si256(t5, t7, 0x31);

    _mm256_storeu_si256((__m256i *) out1, f1);
    _mm256_storeu_si256((__m256i *) out2, f2);
    _mm256_storeu_si256((__m256i *) out3, f3);
    _mm256_storeu_si256((__m256i *) (out1 + 32), f5);
    _mm256_storeu_si256((__m256i *) (out2 + 32), f6);
    _mm256_storeu_si256((__m256i *) (out3 + 32), f7);

    out1 += 64;
    out2 += 64;
    out3 += 64;

    t = _mm256_castsi256_si128(state->s[16]);
    *(uint64_t *) out1 = _mm_extract_epi64(t, 1);
    t = _mm256_extracti128_si256(state->s[16], 1);
    *(uint64_t *) out2 = _mm_extract_epi64(t, 0);
    *(uint64_t *) out3 = _mm_extract_epi64(t, 1);
}


/****
 * Hashes u and w_1 to derive 256-bit ctilde,and generate random numbers for sampling y
 * absorb CRHBYTES bytes from mu, and absorb K * POLYW1_PACKEDBYTES bytes from sig
 * squeeze CTILDEBYTES bytes to out, note out will overwrite sign
 * require K * POLYW1_PACKEDBYTES and CRHBYTES are multiples of 8
 ****/
void hybrid_challenge_and_ExpandRand_x3(uint8_t *c_tiled_out, const uint8_t *mu, const uint8_t *w1, loop_queue *loop, const uint8_t seedY[64], uint16_t nonce) {
    keccakx4_state state;
    int len = K * POLYW1_PACKEDBYTES + CRHBYTES;
    int r = 0;
    __m256i f;
    uint8_t *y_buff0 = loop_next(loop);
    uint8_t *y_buff1 = loop_next(loop);
    uint8_t *y_buff2 = loop_next(loop);

    // absorb CRHBYTES bytes from mu in the first lane, and aborb CRHBYTES bytes from seedY to the last three lanes.
    state.s[0] = _mm256_set_epi64x(load64(mu),         load64(seedY) , load64(seedY), load64(seedY));
    state.s[1] = _mm256_set_epi64x(load64(mu + 8) , load64(seedY + 8) , load64(seedY + 8) , load64(seedY + 8) );
    state.s[2] = _mm256_set_epi64x(load64(mu + 16), load64(seedY + 16), load64(seedY + 16), load64(seedY + 16));
    state.s[3] = _mm256_set_epi64x(load64(mu + 24), load64(seedY + 24), load64(seedY + 24), load64(seedY + 24));
    state.s[4] = _mm256_set_epi64x(load64(mu + 32), load64(seedY + 32), load64(seedY + 32), load64(seedY + 32));
    state.s[5] = _mm256_set_epi64x(load64(mu + 40), load64(seedY + 40), load64(seedY + 40), load64(seedY + 40));
    state.s[6] = _mm256_set_epi64x(load64(mu + 48), load64(seedY + 48), load64(seedY + 48), load64(seedY + 48));
    state.s[7] = _mm256_set_epi64x(load64(mu + 56), load64(seedY + 56), load64(seedY + 56), load64(seedY + 56));
    state.s[8] = _mm256_set_epi64x(0, (0x1F << 16) ^ (nonce + 2), (0x1F << 16) ^ (nonce + 1), (0x1F << 16) ^ nonce);

    for (int i = 9; i < 25; ++i)
        state.s[i] = _mm256_setzero_si256();

    state.s[16] = _mm256_set_epi64x(0, (0x1ULL << 63), (0x1ULL << 63), (0x1ULL << 63));

    int start = 8;
    while (len >= SHAKE256_RATE) {
        absorb_hash_SHAKE256RATE_interval(&state, w1, start);  // abosrb m
        w1 += SHAKE256_RATE - start * 8;
        len -= SHAKE256_RATE;
        KeccakP1600times4_PermuteAll_24rounds(state.s);
        if (r < 5) {
            extract_lanes_x3_shake256(y_buff0 + r * SHAKE256_RATE, y_buff1+ r * SHAKE256_RATE, y_buff2+ r * SHAKE256_RATE,  &state);
            r += 1;
        }
        start = 0;
    }
    absorb_hash_SHAKE256RATE_tail_process_interval(&state, w1, start, len - start * 8);
    KeccakP1600times4_PermuteAll_24rounds(state.s);
    for (int i = 0; i < CTILDEBYTES >> 3; ++i) {
        f = _mm256_permute4x64_epi64(state.s[i],03);
        _mm_storeu_si64(c_tiled_out + 8 * i, _mm256_castsi256_si128(f));
    }
}