/*
 * sign.h — SM4th.KeyGen / Sign / Verify (Clauses 10-11 of SM4th_spec.pdf).
 */
#ifndef SM4TH_SIGN_H
#define SM4TH_SIGN_H

#include "sm4th_params.h"
#include "owf.h"
#include "bavc.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stddef.h>

/* Random callback for KeyGen/Sign randomness (non-zero = success). */
typedef int (*sm4th_rand_fn)(void *ctx, uint8_t *out, size_t len);

/* Default DRNG: RAND_priv_bytes_ex with NULL libctx (ctx ignored). */
int sm4th_rand_default(void *ctx, uint8_t *out, size_t len);

/* Key material: sk = x || k, pk = x || y (Clause 11, Table 16).        */
#ifndef SM4TH_SK_BYTES
# define SM4TH_SK_BYTES 32
#endif
#ifndef SM4TH_PK_BYTES
# define SM4TH_PK_BYTES 32
#endif

/* Core KeyGen (rand callback).  Prefer sm4th_keygen in sm4th_sigops.h
 * for the Tongsuo key layer.                                          */
int sm4th_core_keygen(const sm4th_params_t *p, sm4th_rand_fn rnd,
                      void *rndctx, uint8_t sk[32], uint8_t pk[32]);

/* Core Sign: sigma holds sig_len octets; |msg| <= 2^60; seed is 32B.
 * shake128_md is a prefetched SHAKE-128 (from SM4TH_KEY).
 * Returns 0 or -1 (grinding counter exhausted).                        */
int sm4th_core_sign(const sm4th_params_t *p, const EVP_MD *shake128_md,
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t sk[32],
                    const uint8_t seed[32],
                    uint8_t *sigma /* sig_len octets */);

/* Core Verify: returns 1 (accept) or 0 (reject — V-0..V-3).
 * Rejects unless |sigma|=L_sigma, |pk|=32, |msg|<=2^60.               */
int sm4th_core_verify(const sm4th_params_t *p, const EVP_MD *shake128_md,
                      const uint8_t *msg, size_t msg_len,
                      const uint8_t *pk, size_t pk_len,
                      const uint8_t *sigma, size_t sigma_len);

#endif /* SM4TH_SIGN_H */
