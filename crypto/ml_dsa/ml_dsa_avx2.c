/*
 * Internal ML-DSA AVX2 dispatch helpers.
 */

#include "ml_dsa_avx2.h"
#include "ml_dsa_key.h"
#include "ml_dsa_local.h"

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
int ossl_ml_dsa_44_avx2_crypto_sign_keypair_internal(uint8_t *pk, uint8_t *sk,
                                                      const uint8_t *seed);
int ossl_ml_dsa_65_avx2_crypto_sign_keypair_internal(uint8_t *pk, uint8_t *sk,
                                                      const uint8_t *seed);
int ossl_ml_dsa_87_avx2_crypto_sign_keypair_internal(uint8_t *pk, uint8_t *sk,
                                                      const uint8_t *seed);
int ossl_ml_dsa_44_avx2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *pk, int msg_is_mu);
int ossl_ml_dsa_65_avx2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *pk, int msg_is_mu);
int ossl_ml_dsa_87_avx2_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                                            const uint8_t *m, size_t mlen,
                                            const uint8_t *pk, int msg_is_mu);

int ossl_ml_dsa_avx2_eligible(void)
{
    return ML_DSA_AVX2_CAPABLE != 0
        && ML_DSA_BMI2_CAPABLE != 0
        && ML_DSA_POPCNT_CAPABLE != 0;
}

int ossl_ml_dsa_avx2_keygen(ML_DSA_KEY *key)
{
    int ret = 0;
    uint8_t *pk = NULL, *sk = NULL, *seed;
    const ML_DSA_PARAMS *params;

    if (key == NULL || key->seed == NULL)
        return 0;

    params = ossl_ml_dsa_key_params(key);
    pk = OPENSSL_malloc(params->pk_len);
    sk = OPENSSL_malloc(params->sk_len);
    if (pk == NULL || sk == NULL)
        goto err;

    switch (params->evp_type) {
    case EVP_PKEY_ML_DSA_44:
        ret = ossl_ml_dsa_44_avx2_crypto_sign_keypair_internal(pk, sk,
                                                               key->seed);
        break;
    case EVP_PKEY_ML_DSA_65:
        ret = ossl_ml_dsa_65_avx2_crypto_sign_keypair_internal(pk, sk,
                                                               key->seed);
        break;
    case EVP_PKEY_ML_DSA_87:
        ret = ossl_ml_dsa_87_avx2_crypto_sign_keypair_internal(pk, sk,
                                                               key->seed);
        break;
    default:
        goto err;
    }
    if (ret != 0)
        goto err;

    /* Decode the internally generated pair without recomputing its public key. */
    seed = key->seed;
    key->seed = NULL;
    ret = ossl_ml_dsa_generated_keypair_decode(key, pk, params->pk_len,
                                               sk, params->sk_len);
    key->seed = seed;
    if (ret) {
        if ((key->prov_flags & ML_DSA_KEY_RETAIN_SEED) == 0) {
            OPENSSL_clear_free(key->seed, ML_DSA_SEED_BYTES);
            key->seed = NULL;
        }
        goto done;
    }

    key->seed = NULL;
    ossl_ml_dsa_key_reset(key);
    key->seed = seed;
 err:
    ret = 0;
 done:
    OPENSSL_free(pk);
    OPENSSL_clear_free(sk, params->sk_len);
    return ret;
}

int ossl_ml_dsa_avx2_sign(const ML_DSA_KEY *priv, int msg_is_mu,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *rand, size_t rand_len,
                          unsigned char *sig, size_t *sig_len)
{
    int ret;
    const ML_DSA_PARAMS *params;

    if (priv == NULL || sig == NULL || rand == NULL)
        return ML_DSA_AVX2_SIGN_DATA_UNSUPPORTED;
    if (msg_is_mu && msg_len != ML_DSA_MU_BYTES)
        return ML_DSA_AVX2_SIGN_ERROR;

    params = ossl_ml_dsa_key_params(priv);
    switch (params->evp_type) {
    case EVP_PKEY_ML_DSA_44:
        ret = ossl_ml_dsa_44_avx2_crypto_sign_signature_ex(sig, sig_len,
                                                           msg, msg_len,
                                                           priv->priv_encoding,
                                                           rand, rand_len,
                                                           msg_is_mu);
        break;
    case EVP_PKEY_ML_DSA_65:
        ret = ossl_ml_dsa_65_avx2_crypto_sign_signature_ex(sig, sig_len,
                                                           msg, msg_len,
                                                           priv->priv_encoding,
                                                           rand, rand_len,
                                                           msg_is_mu);
        break;
    case EVP_PKEY_ML_DSA_87:
        ret = ossl_ml_dsa_87_avx2_crypto_sign_signature_ex(sig, sig_len,
                                                           msg, msg_len,
                                                           priv->priv_encoding,
                                                           rand, rand_len,
                                                           msg_is_mu);
        break;
    default:
        return ML_DSA_AVX2_SIGN_DATA_UNSUPPORTED;
    }
    return ret == 0 ? ML_DSA_AVX2_SIGN_SUCCESS : ML_DSA_AVX2_SIGN_ERROR;
}

int ossl_ml_dsa_avx2_verify(const ML_DSA_KEY *pub, int msg_is_mu,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    int ret;
    const ML_DSA_PARAMS *params;

    if (pub == NULL || sig == NULL)
        return ML_DSA_AVX2_VERIFY_DATA_UNSUPPORTED;
    if (msg_is_mu && msg_len != ML_DSA_MU_BYTES)
        return ML_DSA_AVX2_VERIFY_INVALID;

    params = ossl_ml_dsa_key_params(pub);
    switch (params->evp_type) {
    case EVP_PKEY_ML_DSA_44:
        ret = ossl_ml_dsa_44_avx2_crypto_sign_verify(sig, sig_len, msg,
                                                     msg_len,
                                                     pub->pub_encoding,
                                                     msg_is_mu);
        break;
    case EVP_PKEY_ML_DSA_65:
        ret = ossl_ml_dsa_65_avx2_crypto_sign_verify(sig, sig_len, msg,
                                                     msg_len,
                                                     pub->pub_encoding,
                                                     msg_is_mu);
        break;
    case EVP_PKEY_ML_DSA_87:
        ret = ossl_ml_dsa_87_avx2_crypto_sign_verify(sig, sig_len, msg,
                                                     msg_len,
                                                     pub->pub_encoding,
                                                     msg_is_mu);
        break;
    default:
        return ML_DSA_AVX2_VERIFY_DATA_UNSUPPORTED;
    }
    return ret == 0 ? ML_DSA_AVX2_VERIFY_VALID : ML_DSA_AVX2_VERIFY_INVALID;
}

#else

int ossl_ml_dsa_avx2_eligible(void)
{
    return 0;
}

int ossl_ml_dsa_avx2_keygen(ML_DSA_KEY *key)
{
    return 0;
}

int ossl_ml_dsa_avx2_sign(const ML_DSA_KEY *priv, int msg_is_mu,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *rand, size_t rand_len,
                          unsigned char *sig, size_t *sig_len)
{
    return ML_DSA_AVX2_SIGN_DATA_UNSUPPORTED;
}

int ossl_ml_dsa_avx2_verify(const ML_DSA_KEY *pub, int msg_is_mu,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len)
{
    return ML_DSA_AVX2_VERIFY_DATA_UNSUPPORTED;
}

#endif
