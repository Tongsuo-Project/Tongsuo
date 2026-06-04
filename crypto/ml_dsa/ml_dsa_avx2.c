/*
 * Internal ML-DSA AVX2 dispatch helpers.
 */

#include "ml_dsa_avx2.h"
#include "ml_dsa_key.h"

#if defined(ML_DSA_AVX2_ASM) && defined(OPENSSL_CPUID_OBJ) \
    && (defined(__x86_64) || defined(__x86_64__) \
        || defined(_M_AMD64) || defined(_M_X64))
# include "internal/cryptlib.h"
# include <openssl/evp.h>

# define ML_DSA_AVX2_CAPABLE (OPENSSL_ia32cap_P[2] & (1 << 5))
# define ML_DSA_BMI2_CAPABLE (OPENSSL_ia32cap_P[2] & (1 << 8))
# define ML_DSA_POPCNT_CAPABLE (OPENSSL_ia32cap_P[1] & (1 << 23))

int ossl_ml_dsa_44_avx2_crypto_sign_signature_ex(uint8_t *sig, size_t *siglen,
                                                  const uint8_t *m, size_t mlen,
                                                  const uint8_t *sk,
                                                  const uint8_t *rnd,
                                                  size_t rnd_len,
                                                  int msg_is_mu);
int ossl_ml_dsa_65_avx2_crypto_sign_signature_ex(uint8_t *sig, size_t *siglen,
                                                  const uint8_t *m, size_t mlen,
                                                  const uint8_t *sk,
                                                  const uint8_t *rnd,
                                                  size_t rnd_len,
                                                  int msg_is_mu);
int ossl_ml_dsa_87_avx2_crypto_sign_signature_ex(uint8_t *sig, size_t *siglen,
                                                  const uint8_t *m, size_t mlen,
                                                  const uint8_t *sk,
                                                  const uint8_t *rnd,
                                                  size_t rnd_len,
                                                  int msg_is_mu);
int ossl_ml_dsa_44_avx2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *pk);
int ossl_ml_dsa_65_avx2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *pk);
int ossl_ml_dsa_87_avx2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *pk);

static int ml_dsa_avx2_eligible(void)
{
    return ML_DSA_AVX2_CAPABLE != 0
        && ML_DSA_BMI2_CAPABLE != 0
        && ML_DSA_POPCNT_CAPABLE != 0;
}

int ossl_ml_dsa_avx2_sign(const ML_DSA_KEY *priv, int msg_is_mu,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *rand, size_t rand_len,
                          unsigned char *sig, size_t *sig_len)
{
    int ret;
    const ML_DSA_PARAMS *params;

    if (priv == NULL || msg_is_mu || sig == NULL || rand == NULL
        || !ml_dsa_avx2_eligible())
        return 0;

    params = ossl_ml_dsa_key_params(priv);
    switch (params->evp_type) {
    case EVP_PKEY_ML_DSA_44:
        ret = ossl_ml_dsa_44_avx2_crypto_sign_signature_ex(sig, sig_len,
                                                           msg, msg_len,
                                                           priv->priv_encoding,
                                                           rand, rand_len, 0);
        break;
    case EVP_PKEY_ML_DSA_65:
        ret = ossl_ml_dsa_65_avx2_crypto_sign_signature_ex(sig, sig_len,
                                                           msg, msg_len,
                                                           priv->priv_encoding,
                                                           rand, rand_len, 0);
        break;
    case EVP_PKEY_ML_DSA_87:
        ret = ossl_ml_dsa_87_avx2_crypto_sign_signature_ex(sig, sig_len,
                                                           msg, msg_len,
                                                           priv->priv_encoding,
                                                           rand, rand_len, 0);
        break;
    default:
        return 0;
    }
    return ret == 0;
}

int ossl_ml_dsa_avx2_verify(const ML_DSA_KEY *pub, int msg_is_mu,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    int ret;
    const ML_DSA_PARAMS *params;

    if (pub == NULL || msg_is_mu || sig == NULL || !ml_dsa_avx2_eligible())
        return 0;

    params = ossl_ml_dsa_key_params(pub);
    switch (params->evp_type) {
    case EVP_PKEY_ML_DSA_44:
        ret = ossl_ml_dsa_44_avx2_crypto_sign_verify(sig, sig_len, msg,
                                                     msg_len,
                                                     pub->pub_encoding);
        break;
    case EVP_PKEY_ML_DSA_65:
        ret = ossl_ml_dsa_65_avx2_crypto_sign_verify(sig, sig_len, msg,
                                                     msg_len,
                                                     pub->pub_encoding);
        break;
    case EVP_PKEY_ML_DSA_87:
        ret = ossl_ml_dsa_87_avx2_crypto_sign_verify(sig, sig_len, msg,
                                                     msg_len,
                                                     pub->pub_encoding);
        break;
    default:
        return 0;
    }
    return ret == 0;
}

#else

int ossl_ml_dsa_avx2_sign(const ML_DSA_KEY *priv, int msg_is_mu,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *rand, size_t rand_len,
                          unsigned char *sig, size_t *sig_len)
{
    return 0;
}

int ossl_ml_dsa_avx2_verify(const ML_DSA_KEY *pub, int msg_is_mu,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    return 0;
}

#endif
