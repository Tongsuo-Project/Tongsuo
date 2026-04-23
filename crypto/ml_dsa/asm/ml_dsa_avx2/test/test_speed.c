#include <stdint.h>
#include <stdio.h>

#include "hybrid.h"
#include "../sign.h"
#include "../poly.h"
#include "../polyvec.h"
#include "../params.h"
#include "cpucycles.h"
#include "packing.h"
#include "rejsample.h"
#include "speed_print.h"

#define NTESTS 50000

uint64_t t[NTESTS];


void print_keccak_instance_for_y(int rounds) {
  int P = 4;
  int loop_size;
  loop_size = (K * L -1) % P;
  // loop_size = 0;
  int count = 0;
  for (int i = 1; i <= rounds; ++i) {
    printf("rounds: %d ,loop_size :%d \n", i, loop_size);
    while (loop_size < L) {
      count ++;
      loop_size +=4;
    }
    loop_size -= L;
    loop_size +=3;
    printf("%d  %d\n", i, count);
  }
}

int main(void)
{
  unsigned int i;
  size_t smlen;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sm[CRYPTO_BYTES + CRHBYTES];
  __attribute__((aligned(32)))
  uint8_t seed[CRHBYTES] = {0};
  polyvecl mat[K];
  poly *a = &mat[0].vec[0];
  poly *b = &mat[0].vec[1];
  poly *c = &mat[0].vec[2];
  loop_queue loop;
  loop.start = 0;
  loop.size = 0;
  polyvecl y, z;

  // print_keccak_instance_for_y(16);

  for(i = 0; i < NTESTS; ++i) {
    loop.start = 0;
    loop.size = 0;
    t[i] = cpucycles();
    while (loop.size < L) {
      poly_generate_random_gamma1_4x(&loop, sk, 0,  1,  2, 3);
    }
    for (int j = 0; j < L; ++j) polyz_unpack(&y.vec[j], loop_dequeue(&loop));
  }
  print_results("expandMask:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    loop.start = 0;
    loop.size = 0;
    t[i] = cpucycles();
    while (loop.size < L) {
      poly_generate_random_gamma1_4x(&loop, sk, 0,  1,  2, 3);
    }
    for (int j = 0; j < L; ++j) polyz_unpack(&y.vec[j], loop_dequeue(&loop));
  }
  print_results("expandMask:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    loop.start = 0;
    loop.size = 0;
    t[i] = cpucycles();
    while (loop.size < L) {
      poly_generate_random_gamma1_4x_state_trans(&loop, sk, 0,  1,  2, 3);
    }
    for (int j = 0; j < L; ++j) polyz_unpack(&y.vec[j], loop_dequeue(&loop));
  }
  print_results("expandMask_state_trans:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    loop.start = 0;
    loop.size = 0;
    t[i] = cpucycles();
    while (loop.size < L) {
      poly_generate_random_gamma1_4x_state_trans(&loop, sk, 0,  1,  2, 3);
    }
    for (int j = 0; j < L; ++j) polyz_unpack(&y.vec[j], loop_dequeue(&loop));
  }
  print_results("expandMask_state_trans:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    loop.start = 0;
    loop.size = 0;
    t[i] = cpucycles();
    while (loop.size < L) {
      poly_generate_random_gamma1_4x(&loop, sk, 0,  1,  2, 3);
    }
    for (int j = 0; j < L; ++j) polyz_unpack(&y.vec[j], loop_dequeue(&loop));
  }
  print_results("expandMask:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crh(sk,pk,128);
  }
  print_results("crh:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    hybrid_hash_ExpandA_shuffled(pk, 64, sk, CRHBYTES + 59,
                            &mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], pk, 0, 1, 2);
  }
  print_results("hybrid_hash_ExpandA_shuffled:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    hybrid_uniform_2x_and_ExpandRand(&mat[3].vec[2], &mat[3].vec[3],&loop,sk,pk,770, 771,0, 1);;
  }
  print_results("hybrid_uniform_2x_and_ExpandRand:", t, NTESTS);


  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    hybrid_challenge_and_ExpandRand_x3(sm, sk, sm, &loop, sk,  0);

  }
  print_results("hybrid_challenge_and_ExpandRand:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_uniform_4x_op13(&mat[1].vec[2], &mat[1].vec[3], &mat[2].vec[0], &mat[2].vec[1], pk, 258, 259, 512, 513);
  }
  print_results("poly_uniform_4x_op13:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_uniform_4x_op13_state_trans(&mat[1].vec[2], &mat[1].vec[3], &mat[2].vec[0], &mat[2].vec[1], pk, 258, 259, 512, 513);
  }
  print_results("poly_uniform_4x_op13_state_trans:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_pointwise_montgomery(c, a, b);
  }
  print_results("poly_pointwise_montgomery:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    poly_challenge(c, seed);
  }
  print_results("poly_challenge:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_keypair(pk, sk);
  }
  print_results("Keypair:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign(sm, &smlen, sm, CRHBYTES, sk);
  }
  print_results("Sign:", t, NTESTS);

  for(i = 0; i < NTESTS; ++i) {
    t[i] = cpucycles();
    crypto_sign_verify(sm, CRYPTO_BYTES, sm, CRHBYTES, pk);
  }
  print_results("Verify:", t, NTESTS);

  return 0;
}
