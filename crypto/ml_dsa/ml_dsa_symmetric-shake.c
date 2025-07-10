#include <stdint.h>
#include "ml_dsa_local.h"
#include "ml_dsa_symmetric.h"

void dilithium_shake128_stream_init(keccak_state *state, const uint8_t seed[ML_DSA_SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake128_init(state);
  shake128_absorb(state, seed, ML_DSA_SEEDBYTES);
  shake128_absorb(state, t, 2);
  shake128_finalize(state);
}

void dilithium_shake256_stream_init(keccak_state *state, const uint8_t seed[ML_DSA_CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  shake256_init(state);
  shake256_absorb(state, seed, ML_DSA_CRHBYTES);
  shake256_absorb(state, t, 2);
  shake256_finalize(state);
}
