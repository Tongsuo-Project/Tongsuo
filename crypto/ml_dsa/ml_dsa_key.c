#include "ml_dsa_local.h"

ML_DSA_KEY *pqcrystals_ml_dsa_key_new(OSSL_LIB_CTX *libctx)
{
    ML_DSA_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto err;
    
    key->privkey = OPENSSL_zalloc(ML_DSA_SECRETKEYBYTES);
    if (key->privkey == NULL)
        goto err;
    key->privkey_len = ML_DSA_SECRETKEYBYTES;

    key->pubkey = OPENSSL_zalloc(ML_DSA_PUBLICKEYBYTES);
    if (key->pubkey == NULL)
        goto err;
    key->pubkey_len = ML_DSA_PUBLICKEYBYTES;

    key->libctx = libctx;

    return key;
err:
    if (key != NULL)
        OPENSSL_free(key->privkey);
    if (key != NULL)
        OPENSSL_free(key->pubkey);
    OPENSSL_free(key);
    return NULL;
}

void pqcrystals_ml_dsa_key_free(ML_DSA_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_cleanse(key->privkey, key->privkey_len);
    OPENSSL_free(key->privkey);
    OPENSSL_cleanse(key->pubkey, key->pubkey_len);
    OPENSSL_free(key->pubkey);
    OPENSSL_free(key);
}
