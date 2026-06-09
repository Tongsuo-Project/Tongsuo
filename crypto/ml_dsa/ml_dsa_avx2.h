/*
 * Internal ML-DSA AVX2 dispatch helpers.
 */

#ifndef OSSL_CRYPTO_ML_DSA_AVX2_H
# define OSSL_CRYPTO_ML_DSA_AVX2_H

# include "crypto/ml_dsa.h"

# define ML_DSA_AVX2_VERIFY_UNAVAILABLE -1
# define ML_DSA_AVX2_VERIFY_INVALID      0
# define ML_DSA_AVX2_VERIFY_VALID        1

int ossl_ml_dsa_avx2_keygen(ML_DSA_KEY *key);
int ossl_ml_dsa_avx2_sign(const ML_DSA_KEY *priv, int msg_is_mu,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *rand, size_t rand_len,
                          unsigned char *sig, size_t *sig_len);
int ossl_ml_dsa_avx2_verify(const ML_DSA_KEY *pub, int msg_is_mu,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);

#endif
