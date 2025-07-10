#include <string.h>
#include "ml_dsa_local.h"

ML_DSA_KEY *pqcrystals_ml_dsa_key_new(OSSL_LIB_CTX *libctx)
{
    ML_DSA_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto err;

    key->seed = OPENSSL_zalloc(ML_DSA_SEEDBYTES);
    if (key->seed == NULL)
        goto err;
    key->seed_len = 0;

    key->privkey = OPENSSL_zalloc(ML_DSA_SECRETKEYBYTES);
    if (key->privkey == NULL)
        goto err;
    key->privkey_len = 0;

    key->pubkey = OPENSSL_zalloc(ML_DSA_PUBLICKEYBYTES);
    if (key->pubkey == NULL)
        goto err;
    key->pubkey_len = 0;

    key->libctx = libctx;

    return key;
err:

    if (key != NULL) {
        OPENSSL_free(key->seed);
        OPENSSL_free(key->privkey);
        OPENSSL_free(key->pubkey);
    }
    OPENSSL_free(key);
    return NULL;
}

void pqcrystals_ml_dsa_key_free(ML_DSA_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_cleanse(key->seed, key->seed_len);
    OPENSSL_free(key->seed);
    OPENSSL_cleanse(key->privkey, key->privkey_len);
    OPENSSL_free(key->privkey);
    OPENSSL_cleanse(key->pubkey, key->pubkey_len);
    OPENSSL_free(key->pubkey);
    OPENSSL_free(key);
}

int pqcrystals_ml_dsa_pk_import(ML_DSA_KEY *key, const uint8_t *pk, size_t pk_len)
{
    if (key == NULL || pk == NULL || pk_len != ML_DSA_PUBLICKEYBYTES)
        return 0;

    OPENSSL_cleanse(key->pubkey, ML_DSA_PUBLICKEYBYTES);
    memcpy(key->pubkey, pk, pk_len);
    key->pubkey_len = pk_len;
    return 1;
}

int pqcrystals_ml_dsa_sk_import(ML_DSA_KEY *key, const uint8_t *sk, size_t sk_len)
{
    if (key == NULL || sk == NULL || sk_len != ML_DSA_SECRETKEYBYTES)
        return 0;

    OPENSSL_cleanse(key->privkey, ML_DSA_SECRETKEYBYTES);
    memcpy(key->privkey, sk, sk_len);
    key->privkey_len = sk_len;
    return 1;
}
