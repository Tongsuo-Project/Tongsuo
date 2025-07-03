#include "internal/deprecated.h"

#include "crypto/sm2dh_mlkem768_hybrid.h"
#include "crypto/sm2dh_mlkem768_hybriderr.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sm2dh_mlkem768_hybriderr.h>


sm2dh_mlkem768_hybrid_key * sm2dh_mlkem768_hybrid_key_new(void)
{
    sm2dh_mlkem768_hybrid_key * hybrid_key = OPENSSL_malloc(sizeof(sm2dh_mlkem768_hybrid_key));
    if(hybrid_key == NULL)
        goto err;
    memset(hybrid_key, 0x00, sizeof(sm2dh_mlkem768_hybrid_key));
    
    hybrid_key->pk = OPENSSL_malloc(SM2_DH_MLKEM_768_HYBRID_PK_SIZE);
    if(hybrid_key->pk == NULL)
        goto err;
    memset(hybrid_key->pk, 0x00, SM2_DH_MLKEM_768_HYBRID_PK_SIZE);

    hybrid_key->sk = OPENSSL_malloc(SM2_DH_MLKEM_768_HYBRID_SK_SIZE);
    if(hybrid_key->sk == NULL)
        goto err;
    memset(hybrid_key->sk, 0x00, SM2_DH_MLKEM_768_HYBRID_SK_SIZE);

    hybrid_key->ct = OPENSSL_malloc(SM2_DH_MLKEM_768_HYBRID_CT_SIZE);
    if(hybrid_key->ct == NULL)
        goto err;
    memset(hybrid_key->ct, 0x00, SM2_DH_MLKEM_768_HYBRID_CT_SIZE);

    hybrid_key->ss = OPENSSL_malloc(SM2_DH_MLKEM_768_HYBRID_SS_SIZE);
    if(hybrid_key->ss == NULL)
        goto err;
    memset(hybrid_key->ss, 0x00, SM2_DH_MLKEM_768_HYBRID_SS_SIZE);

    hybrid_key->has_kem_sk = 0;

    return hybrid_key;
err:
    if(hybrid_key->pk)
        OPENSSL_free(hybrid_key->pk);
    if(hybrid_key->sk)
        OPENSSL_free(hybrid_key->sk);
    if(hybrid_key->ct)
        OPENSSL_free(hybrid_key->ct);
    if(hybrid_key->ss)
        OPENSSL_free(hybrid_key->ss);
    OPENSSL_free(hybrid_key);
    return NULL;
}

void sm2dh_mlkem768_hybrid_key_free(sm2dh_mlkem768_hybrid_key * hybrid_key)
{
    if(hybrid_key->pk) {
        memset(hybrid_key->pk, 0x00, SM2_DH_MLKEM_768_HYBRID_PK_SIZE);
        OPENSSL_free(hybrid_key->pk);
    }    
    if(hybrid_key->sk) {
        memset(hybrid_key->sk, 0x00, SM2_DH_MLKEM_768_HYBRID_SK_SIZE);
        OPENSSL_free(hybrid_key->sk);
    }
    if(hybrid_key->ct) {
        memset(hybrid_key->ct, 0x00, SM2_DH_MLKEM_768_HYBRID_CT_SIZE);
        OPENSSL_free(hybrid_key->ct); 
    }
    if(hybrid_key->ss) {
        memset(hybrid_key->ss, 0x00, SM2_DH_MLKEM_768_HYBRID_SS_SIZE);
        OPENSSL_free(hybrid_key->ss);
    }
    OPENSSL_free(hybrid_key);
}


int sm2dh_mlkem768_hybrid_keygen(OSSL_LIB_CTX * libctx, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len) {

    int ret = 0;
    EC_KEY * ec_key = NULL;
    const BIGNUM * ec_key_sk;
    const EC_POINT * ec_key_pk;

    if(pk == NULL || sk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if((pk_len < SM2_DH_MLKEM_768_HYBRID_PK_SIZE) || 
        (sk_len < SM2_DH_MLKEM_768_HYBRID_SK_SIZE)) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    /* Generate ECDHE key with SM2Curve */
    /*
      Note that the EC_KEY_new_by_curve_name function cannot be used here,
      since it will lost the OSSL_LIB_CTX data which may finally fail some
      tests. Such context data is important for EC_KEY_generate_key and
      ECDH_compute_key.
    */
    ec_key = EC_KEY_new_by_curve_name_ex(libctx, NULL, NID_sm2);
    if(ec_key == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        return 0;
    }
    EC_KEY_set_flags(ec_key, EC_FLAG_SM2_RANGE);
   
    if(!EC_KEY_generate_key(ec_key)){
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }   
    /* Encode SM2-DH private key */
    ec_key_sk = EC_KEY_get0_private_key(ec_key);
    if(ec_key_sk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    if(!BN_bn2binpad(ec_key_sk, sk, SM2_DH_SK_SIZE)){
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
     
    /* Encode SM2-DH public key */
    ec_key_pk = EC_KEY_get0_public_key(ec_key);
    if(ec_key_pk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    if(EC_POINT_point2oct(EC_KEY_get0_group(ec_key), ec_key_pk, POINT_CONVERSION_UNCOMPRESSED, pk, SM2_DH_PK_SIZE, NULL) != SM2_DH_PK_SIZE) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    
    /* Generate MLKEM-768 key pair in binary */
    if(pqcrystals_kyber768_ref_keypair(pk + SM2_DH_PK_SIZE, sk + SM2_DH_SK_SIZE) != 0) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_MLKEM_ERROR);
        goto err;
    }
    ret = 1;

err:
    EC_KEY_free(ec_key);
    return ret;
}

int sm2dh_mlkem768_hybrid_encaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, uint8_t *ct, size_t ct_len, const uint8_t *pk, size_t pk_len) {
    int ret = 0;
    EC_KEY *ec_key_local = NULL;
    EC_POINT *ec_key_peer_pk = NULL;
    const EC_GROUP * group;
    const EC_POINT * ec_key_local_pk;

    if(pk == NULL || ct == NULL || ss == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if((pk_len != SM2_DH_MLKEM_768_HYBRID_PK_SIZE) || 
        (ss_len < SM2_DH_MLKEM_768_HYBRID_SS_SIZE) ||
        (ct_len < SM2_DH_MLKEM_768_HYBRID_CT_SIZE)){
         ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* Generate another ECDHE key with SM2Curve */
    ec_key_local = EC_KEY_new_by_curve_name_ex(libctx, NULL, NID_sm2);
    if(ec_key_local == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
     EC_KEY_set_flags(ec_key_local, EC_FLAG_SM2_RANGE);

    if(!EC_KEY_generate_key(ec_key_local)){
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }

    group = EC_KEY_get0_group(ec_key_local);
    if(group == NULL){
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    
    /* Parse peer's ECDHE public key */
    ec_key_peer_pk = EC_POINT_new(group);
    if(ec_key_peer_pk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    if(!EC_POINT_oct2point(group, ec_key_peer_pk, pk, SM2_DH_PK_SIZE, NULL)) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }

    /* Encode local's ECDHE public key as hybrid KEM's "ct" */
    ec_key_local_pk = EC_KEY_get0_public_key(ec_key_local);
    if(ec_key_local_pk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    if(EC_POINT_point2oct(group, ec_key_local_pk, POINT_CONVERSION_UNCOMPRESSED, ct, SM2_DH_PK_SIZE, NULL) != SM2_DH_PK_SIZE) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }   

    /* Calculate ECDHE shared key */
    memset(ss, 0x00, ss_len);
    if(!ECDH_compute_key(ss, SM2_DH_SS_SIZE, ec_key_peer_pk, ec_key_local, NULL)) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        OPENSSL_cleanse(ss, ss_len);
        goto err;
    }
    
    /* MLKEM-768 key encapsulation */
    if (pqcrystals_kyber768_ref_enc(ct + SM2_DH_PK_SIZE, ss + SM2_DH_SS_SIZE, pk + SM2_DH_PK_SIZE) != 0) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_MLKEM_ERROR);
        OPENSSL_cleanse(ss, ss_len);
        goto err;
    }
    
    ret = 1;
err:
    EC_POINT_free(ec_key_peer_pk);
    EC_KEY_free(ec_key_local);
    return ret;
}

int sm2dh_mlkem768_hybrid_decaps(OSSL_LIB_CTX * libctx, uint8_t *ss, size_t ss_len, const uint8_t *ct, size_t ct_len, const uint8_t *sk, size_t sk_len) {
    int ret = 0;
    const EC_GROUP * group;
    EC_KEY * ec_key_local = NULL;
    BIGNUM * ec_key_local_sk = NULL;
    EC_POINT * ec_key_peer_pk = NULL;

    if(ss == NULL || ct == NULL || sk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if((ss_len < SM2_DH_MLKEM_768_HYBRID_SS_SIZE) || 
        (ct_len != SM2_DH_MLKEM_768_HYBRID_CT_SIZE) ||
        (sk_len != SM2_DH_MLKEM_768_HYBRID_SK_SIZE)){
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    /* Parse local ECDHE sk */
    ec_key_local = EC_KEY_new_by_curve_name_ex(libctx, NULL, NID_sm2);
    if(ec_key_local == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    ec_key_local_sk = BN_bin2bn(sk, SM2_DH_SK_SIZE, NULL);
    if(ec_key_local_sk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    if(!EC_KEY_set_private_key(ec_key_local, ec_key_local_sk)) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        return 0;
    }
    
    group = EC_KEY_get0_group(ec_key_local);
    if(group == NULL){
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }

    /* Parse peer ECDHE pk */
    ec_key_peer_pk = EC_POINT_new(group);
    if(ec_key_peer_pk == NULL) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }
    if(!EC_POINT_oct2point(group, ec_key_peer_pk, ct, SM2_DH_PK_SIZE, NULL)) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }

    /* ECDHE key agreement */
    memset(ss, 0x00, ss_len);
    if(!ECDH_compute_key(ss, SM2_DH_SS_SIZE, ec_key_peer_pk, ec_key_local, NULL)) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_EC_ERROR);
        goto err;
    }   

    /* MLKEM decapsulation */
    if (pqcrystals_kyber768_ref_dec(ss + SM2_DH_SS_SIZE, ct + SM2_DH_PK_SIZE, sk + SM2_DH_SK_SIZE) != 0) {
        ERR_raise(ERR_LIB_SM2DH_MLKEM768_HYBRID, SM2DH_MLKEM768_HYBRID_R_MLKEM_ERROR);
        OPENSSL_cleanse(ss, ss_len);
        goto err;
    }

    ret = 1;
err:    
    EC_KEY_free(ec_key_local);
    EC_POINT_free(ec_key_peer_pk);
    BN_free(ec_key_local_sk);
    return ret;
}
