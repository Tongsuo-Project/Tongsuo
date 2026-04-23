#ifndef MLDSA65_AVX2_HYBRID_H
#define MLDSA65_AVX2_HYBRID_H

#include "poly.h"
#include <immintrin.h>

#include "align.h"
#include "polyvec.h"


#define POLY_UNIFORM_GAMMA1_NBLOCKS ((POLYZ_PACKEDBYTES+STREAM256_BLOCKBYTES-1)/STREAM256_BLOCKBYTES) //5
#define LOOP_BUF_LENGTH (POLY_UNIFORM_GAMMA1_NBLOCKS * SHAKE256_RATE)
#define LOOP_SIZE (L + 3)

typedef struct {
    ALIGNED_UINT8(LOOP_BUF_LENGTH) buf[LOOP_SIZE];

    int start;
    int size;
} loop_queue;

uint8_t *loop_dequeue(loop_queue *loop);

uint8_t *loop_next(loop_queue *loop);

void print_loop_state(loop_queue *loop);

void hybrid_hash_ExpandA_shuffled(uint8_t *hash_out, int hash_out_len, const uint8_t *hash_in, int hash_in_len,
                                  poly *a0, poly *a1, poly *a2, const uint8_t *rho, uint16_t nonce0, uint16_t nonce1,
                                  uint16_t nonce2);

void hybrid_hash_ExpandRand_ExpandA_shuffled(uint8_t *hash_out, const uint8_t *hash_in, int hash_in_len, loop_queue *loop,
                                  poly *a0, poly *a1, poly *a2, const uint8_t *rho, uint16_t nonce0, uint16_t nonce1,
                                  uint16_t nonce2);

void ExpandA_shuffled_part(polyvecl mat[K], const uint8_t rho[SEEDBYTES], loop_queue *loop, const uint8_t seed[64],
                  uint16_t nonce);

void hybrid_ExpandA_and_hashof_mu_and_challenge(polyvecl mat[K], const uint8_t rho[SEEDBYTES],
uint8_t *mu,uint8_t *tr, const uint8_t *m,int mlen,
poly *c,const uint8_t *c_seed);

void hybrid_uniform_2x_and_ExpandRand(poly *a0, poly *a1, loop_queue *loop, const uint8_t rho[32],
                                      const uint8_t rhoprime[32], uint16_t nonce0, uint16_t nonce1, uint16_t noncey0,
                                      uint16_t noncey1);

void hybrid_uniform_3x_and_ExpandRand(poly *a0, poly *a1, poly *a2, loop_queue *loop, const uint8_t rho[32],
                                         const uint8_t rhoprime[64], uint16_t nonce0, uint16_t nonce1, uint16_t nonce2, uint16_t noncey0);

void poly_generate_random_gamma1_4x(loop_queue *loop, const uint8_t seed[64], uint16_t nonce0, uint16_t nonce1,
                                    uint16_t nonce2, uint16_t nonce3);

void hybrid_challenge_and_ExpandRand_x3(uint8_t *c_tiled_out, const uint8_t *mu, const uint8_t *sig, loop_queue *loop, const uint8_t seedY[64], uint16_t nonce0);

void hybrid_hash_pk_and_ExpandA(uint8_t *hash_out, const uint8_t *pk, polyvecl mat[K], const uint8_t *rho);

void hybrid_hash_mu_and_uniform(uint8_t *mu, poly*c, poly *a0, poly*a1, uint8_t *tr, const uint8_t *m, const uint8_t *c_seed, int mlen, const uint8_t *rho, uint16_t nonce0, uint16_t nonce1);

void poly_generate_random_gamma1_4x_state_trans(loop_queue *loop, const uint8_t seed[64], uint16_t nonce0, uint16_t nonce1,
                                    uint16_t nonce2, uint16_t nonce3);
#endif
