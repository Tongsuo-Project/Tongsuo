/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include "crypto/sm2.h"
#include "crypto/sm2err.h"
#include "crypto/ec.h" /* ossl_ecdh_kdf_X9_63() */
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <string.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_STATIC_ASN1_FUNCTIONS(SM2_Ciphertext)

typedef struct SM2_CiphertextEx_st SM2_CiphertextEx;
DECLARE_STATIC_ASN1_FUNCTIONS(SM2_CiphertextEx)

typedef struct SM2_Enveloped_Key_st SM2_Enveloped_Key;
DECLARE_STATIC_ASN1_FUNCTIONS(SM2_Enveloped_Key)

struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

struct SM2_CiphertextEx_st {
	BIGNUM* C1x;
	BIGNUM* C1y;
    ASN1_OCTET_STRING* C2;
	ASN1_OCTET_STRING* C3;
};

ASN1_SEQUENCE(SM2_Ciphertext) = {
    ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_STATIC_ASN1_FUNCTIONS(SM2_Ciphertext)

ASN1_SEQUENCE(SM2_CiphertextEx) = {
	ASN1_SIMPLE(SM2_CiphertextEx, C1x, BIGNUM),
	ASN1_SIMPLE(SM2_CiphertextEx, C1y, BIGNUM),
	ASN1_SIMPLE(SM2_CiphertextEx, C2, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_CiphertextEx, C3, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(SM2_CiphertextEx)

IMPLEMENT_STATIC_ASN1_FUNCTIONS(SM2_CiphertextEx)

/*described in section 7.4, GMT 0009/2014.*/
    struct SM2_Enveloped_Key_st {
    X509_ALGOR* symAlgID;
    SM2_Ciphertext* symEncryptedKey;
    ASN1_BIT_STRING* Sm2PublicKey;
    ASN1_BIT_STRING* Sm2EncryptedPrivateKey;
};

ASN1_SEQUENCE(SM2_Enveloped_Key) = {
    ASN1_SIMPLE(SM2_Enveloped_Key, symAlgID, X509_ALGOR),
    ASN1_SIMPLE(SM2_Enveloped_Key, symEncryptedKey, SM2_Ciphertext),
    ASN1_SIMPLE(SM2_Enveloped_Key, Sm2PublicKey, ASN1_BIT_STRING),
    ASN1_SIMPLE(SM2_Enveloped_Key, Sm2EncryptedPrivateKey, ASN1_BIT_STRING),
} static_ASN1_SEQUENCE_END(SM2_Enveloped_Key)

IMPLEMENT_STATIC_ASN1_FUNCTIONS(SM2_Enveloped_Key)


//2023年7月1日12:09:43 沈雪冰 begin add，C1|C2|C3  相互转换 C1|C2|C3
SM2_CiphertextEx* SM2_Ciphertext_to_SM2_CiphertextEx(const SM2_Ciphertext* c1c3c2) 
{
	if (!c1c3c2) 
    {
		return NULL;
	}
	SM2_CiphertextEx* c1c2c3_ex = SM2_CiphertextEx_new();
	if (!c1c2c3_ex) 
    {
		return NULL;
	}
	// 由于 BIGNUM 是引用计数的，我们需要复制 BIGNUM 而不是直接赋值
	c1c2c3_ex->C1x = BN_dup(c1c3c2->C1x);
	c1c2c3_ex->C1y = BN_dup(c1c3c2->C1y);
	// ASN1_OCTET_STRING 也需要复制
	c1c2c3_ex->C2 = ASN1_OCTET_STRING_dup(c1c3c2->C2);
	c1c2c3_ex->C3 = ASN1_OCTET_STRING_dup(c1c3c2->C3);

	// 检查复制是否成功
	if (!c1c2c3_ex->C1x || !c1c2c3_ex->C1y || !c1c2c3_ex->C2 || !c1c2c3_ex->C3) 
    {
		// 清理并返回错误
		SM2_CiphertextEx_free(c1c2c3_ex);
		return NULL;
	}
	return c1c2c3_ex;
}
SM2_Ciphertext* SM2_CiphertextEx_to_SM2_Ciphertext(const SM2_CiphertextEx* c1c2c3_ex) 
{
	if (!c1c2c3_ex) 
    {
		return NULL;
	}
	SM2_Ciphertext* c1c3c2 = SM2_Ciphertext_new();
	if (!c1c3c2) 
    {
		return NULL;
	}
	// 由于 BIGNUM 是引用计数的，我们需要复制 BIGNUM 而不是直接赋值
	c1c3c2->C1x = BN_dup(c1c2c3_ex->C1x);
	c1c3c2->C1y = BN_dup(c1c2c3_ex->C1y);
	// ASN1_OCTET_STRING 也需要复制
	c1c3c2->C3 = ASN1_OCTET_STRING_dup(c1c2c3_ex->C3);
	c1c3c2->C2 = ASN1_OCTET_STRING_dup(c1c2c3_ex->C2);

	// 检查复制是否成功
	if (!c1c3c2->C1x || !c1c3c2->C1y || !c1c3c2->C3 || !c1c3c2->C2) 
    {
		// 清理并返回错误
		SM2_Ciphertext_free(c1c3c2);
		return NULL;
	}
	return c1c3c2;
}


//2023年7月1日12:09:43 沈雪冰 end add，C1|C2|C3  相互转换 C1|C2|C3

BIO* SM2_Enveloped_Key_dataDecode(SM2_Enveloped_Key* sm2evpkey, EVP_PKEY* pkey)
{
    BIO* out = NULL, * etmp = NULL, * bio = NULL;
    const EVP_CIPHER* evp_cipher = NULL;
    EVP_CIPHER_CTX* evp_ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    X509_ALGOR* enc_alg = NULL;
    ASN1_BIT_STRING* data_body = NULL;
    SM2_Ciphertext* enc_key = NULL;
    unsigned char* sm2_ciphertext_data = NULL, * p = NULL;
    size_t sm2_ciphertext_len;
    unsigned char* ek = NULL;
    size_t eklen;

    enc_alg = sm2evpkey->symAlgID;
    enc_key = sm2evpkey->symEncryptedKey;
    data_body = sm2evpkey->Sm2EncryptedPrivateKey;
    evp_cipher = EVP_get_cipherbyobj(enc_alg->algorithm);
    if (NULL == evp_cipher)
    {
        //for compatible SM4 OID (defined in GMT 0006-2014)
#define SM4_OID_OLD     "\x2a\x81\x1c\xcf\x55\x01\x68" 
#define SM4_OID_OLD_LEN 7
        if (NULL != enc_alg && NULL != enc_alg->algorithm &&
            SM4_OID_OLD_LEN == OBJ_length(enc_alg->algorithm) &&
            0 == memcmp(OBJ_get0_data(enc_alg->algorithm), SM4_OID_OLD, SM4_OID_OLD_LEN))
        {
            if (NULL == enc_alg->parameter)
            {
                evp_cipher = EVP_sm4_ecb();
                if (NULL == evp_cipher)
                {
                    SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, SM2_R_UNSUPPORTED_CIPHER_TYPE);
                    goto err;
                }
            }
            else
            {
                evp_cipher = EVP_sm4_cbc();
                if (NULL == evp_cipher)
                {
                    SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, SM2_R_UNSUPPORTED_CIPHER_TYPE);
                    goto err;
                }
            }
        }
        else
        {
            SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, SM2_R_UNSUPPORTED_CIPHER_TYPE);
            goto err;
        }
    }
    sm2_ciphertext_len = i2d_SM2_Ciphertext(enc_key, NULL);
    if (sm2_ciphertext_len <= 0)
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    p = sm2_ciphertext_data = OPENSSL_malloc(sm2_ciphertext_len);
    if (NULL == sm2_ciphertext_data)
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    sm2_ciphertext_len = i2d_SM2_Ciphertext(enc_key, &p);
    if (sm2_ciphertext_len <= 0)
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        goto err;

    if (EVP_PKEY_decrypt_init(pctx) <= 0)
        goto err;

    if (EVP_PKEY_decrypt(pctx, NULL, &eklen, sm2_ciphertext_data, sm2_ciphertext_len) <= 0)
        goto err;

    ek = OPENSSL_malloc(eklen);

    if (ek == NULL)
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (EVP_PKEY_decrypt(pctx, ek, &eklen, sm2_ciphertext_data, sm2_ciphertext_len) <= 0)
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_EVP_LIB);
        goto err;
    }

    if ((etmp = BIO_new(BIO_f_cipher())) == NULL)
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_BIO_LIB);
        goto err;
    }
    BIO_get_cipher_ctx(etmp, &evp_ctx);

    if (EVP_CipherInit_ex(evp_ctx, evp_cipher, NULL, NULL, NULL, 0) <= 0)
        goto err;
    if (EVP_CIPHER_asn1_to_param(evp_ctx, enc_alg->parameter) < 0)
        goto err;

    if (eklen != EVP_CIPHER_CTX_key_length(evp_ctx))
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, SM2_R_KEY_LENGTH_ERROR);
        goto err;
    }

    if (EVP_CipherInit_ex(evp_ctx, NULL, NULL, ek, NULL, 0) <= 0)
        goto err;

    EVP_CIPHER_CTX_set_padding(evp_ctx, 0);

    if (data_body->length >= 32)
    {
        bio = BIO_new_mem_buf(data_body->data + data_body->length - 32, 32);
        if (NULL == bio)
        {
            SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, ERR_R_BIO_LIB);
            goto err;
        }
    }
    else
    {
        SM2err(SM2_F_SM2_ENVELOPED_KEY_DATADECODE, SM2_R_DATA_LENGTH_ERROR);
        goto err;
    }

    BIO_push(etmp, bio);
    bio = NULL;

    out = etmp;
    etmp = NULL;

err:
    if (sm2_ciphertext_data)
        OPENSSL_free(sm2_ciphertext_data);
    if (ek)
        OPENSSL_free(ek);
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    if (etmp)
        BIO_free_all(etmp);
    if (bio)
        BIO_free_all(bio);
    return out;
}

int SM2_Ciphertext_get0(const SM2_Ciphertext* cipher,
	const BIGNUM** pC1x, const BIGNUM** pC1y,
	const ASN1_OCTET_STRING** pC3, const ASN1_OCTET_STRING** pC2)
{
	if (!cipher)
		return 0;

	if (pC1x != NULL)
		*pC1x = cipher->C1x;
	if (pC1y != NULL)
		*pC1y = cipher->C1y;
	if (pC3 != NULL)
		*pC3 = cipher->C3;
	if (pC2 != NULL)
		*pC2 = cipher->C2;
	return 1;
}

const BIGNUM* SM2_Ciphertext_get0_C1x(const SM2_Ciphertext* cipher)
{
	return (cipher ? cipher->C1x : NULL);
}

const BIGNUM* SM2_Ciphertext_get0_C1y(const SM2_Ciphertext* cipher)
{
	return (cipher ? cipher->C1y : NULL);
}

const ASN1_OCTET_STRING* SM2_Ciphertext_get0_C3(const SM2_Ciphertext* cipher)
{
	return (cipher ? cipher->C3 : NULL);
}

const ASN1_OCTET_STRING* SM2_Ciphertext_get0_C2(const SM2_Ciphertext* cipher)
{
	return (cipher ? cipher->C2 : NULL);
}

int SM2_Ciphertext_set0(SM2_Ciphertext* cipher, BIGNUM* C1x, BIGNUM* C1y, ASN1_OCTET_STRING* C3, ASN1_OCTET_STRING* C2)
{
	if (!cipher)
		return 0;

	if (C1x)
	{
		BN_clear_free(cipher->C1x);
		cipher->C1x = C1x;
	}
	if (C1y)
	{
		BN_clear_free(cipher->C1y);
		cipher->C1y = C1y;
	}
	if (C3)
	{
		ASN1_STRING_clear_free(cipher->C3);
		cipher->C3 = C3;
	}
	if (C2)
	{
		ASN1_STRING_clear_free(cipher->C2);
		cipher->C2 = C2;
	}
	return 1;
}

static size_t ec_field_size(const EC_GROUP *group)
{
    const BIGNUM *p = EC_GROUP_get0_field(group);

    if (p == NULL)
        return 0;

    return BN_num_bytes(p);
}

int ossl_sm2_plaintext_size(const unsigned char *ct, size_t ct_size,
                            size_t *pt_size, int encdata_format)
{
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    struct SM2_CiphertextEx_st* sm2_ctextEx = NULL;
    if (encdata_format)
    {
        sm2_ctext = d2i_SM2_Ciphertext(NULL, &ct, ct_size);
		if (sm2_ctext == NULL) {
			ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
			return 0;
		}
		*pt_size = sm2_ctext->C2->length;
		SM2_Ciphertext_free(sm2_ctext);
    }
    else
    {           
        sm2_ctextEx = d2i_SM2_CiphertextEx(NULL, &ct, ct_size);
		if (sm2_ctextEx == NULL) {
			ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
			return 0;
		}
		*pt_size = sm2_ctextEx->C2->length;
		SM2_CiphertextEx_free(sm2_ctextEx);
    } 
    return 1;
}

int ossl_sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest,
                             size_t msg_len, size_t *ct_size)
{
    const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
    const int md_size = EVP_MD_get_size(digest);
    size_t sz;

    if (field_size == 0 || md_size < 0)
        return 0;

    /* Integer and string are simple type; set constructed = 0, means primitive and definite length encoding. */
    sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
         + ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
         + ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
    /* Sequence is structured type; set constructed = 1, means constructed and definite length encoding. */
    *ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

    return 1;
}

int ossl_sm2_encrypt(const EC_KEY *key,
                     const EVP_MD *digest,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t *ciphertext_buf, size_t *ciphertext_len, int encdata_format)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct SM2_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    const int C3_size = EVP_MD_get_size(digest);
    EVP_MD *fetched_digest = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);
    const char *propq = ossl_ec_key_get0_propq(key);

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    ctext_struct.C3 = NULL;

    if (hash == NULL || C3_size <= 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    field_size = ec_field_size(group);
    if (field_size == 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new_ex(libctx);
    if (kG == NULL || kP == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    if (!BN_priv_rand_range_ex(k, order, 0, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                             digest, libctx, propq)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    fetched_digest = EVP_MD_fetch(libctx, EVP_MD_get0_name(digest), propq);
    if (fetched_digest == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    if (EVP_DigestInit(hash, fetched_digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto done;
    }
    if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size)
            || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

	if (encdata_format)
	{
		ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
	}
	else//2023年7月1日00:36:27 沈雪冰 add C1|C2|C3格式
	{
        SM2_CiphertextEx ctext_structEx;
        ctext_structEx.C1x = ctext_struct.C1x;
        ctext_structEx.C1y = ctext_struct.C1y;
        ctext_structEx.C2 = ctext_struct.C2;
        ctext_structEx.C3 = ctext_struct.C3;
		ciphertext_leni = i2d_SM2_CiphertextEx(&ctext_structEx, &ciphertext_buf);
	}

    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    EVP_MD_free(fetched_digest);
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}

int ossl_sm2_decrypt(const EC_KEY *key,
                     const EVP_MD *digest,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *ptext_buf, size_t *ptext_len, int encdata_format)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_get_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);
    const char *propq = ossl_ec_key_get0_propq(key);

    if (field_size == 0 || hash_size <= 0)
       goto done;

    memset(ptext_buf, 0xFF, *ptext_len);
	if (encdata_format)
	{
		sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);
	}
	else //2023年7月1日00:36:27 沈雪冰 add C1|C2|C3格式
	{
        SM2_CiphertextEx *sm2_ctext_ex = NULL;
        sm2_ctext_ex = d2i_SM2_CiphertextEx(NULL, &ciphertext, ciphertext_len);       
        sm2_ctext=SM2_CiphertextEx_to_SM2_Ciphertext(sm2_ctext_ex);
        if (sm2_ctext_ex)
        {
        	SM2_CiphertextEx_free(sm2_ctext_ex);
        }
	}

    if (sm2_ctext == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_ASN1_ERROR);
        goto done;
    }

    if (sm2_ctext->C3->length != hash_size) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto done;
    }

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;
    if (*ptext_len < (size_t)msg_len) {
        ERR_raise(ERR_LIB_SM2, SM2_R_BUFFER_TOO_SMALL);
        goto done;
    }

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    computed_C3 = OPENSSL_zalloc(hash_size);

    if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                         sm2_ctext->C1y, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key),
                             ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size,
                                    NULL, 0, digest, libctx, propq)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_DIGEST);
        goto done;
    }

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    EVP_MD_CTX_free(hash);

    return rc;
}

int ossl_sm2_ciphertext_decode(const uint8_t *ciphertext, size_t ciphertext_len,
                               EC_POINT **C1p, uint8_t **C2_data,
                               size_t *C2_len, uint8_t **C3_data,
                               size_t *C3_len)
{
    int ok = 0;
    EC_GROUP *group = NULL;
    EC_POINT *C1 = NULL;
    void *temp = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;

    if (ciphertext == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);
    if (sm2_ctext == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_ASN1_ERROR);
        goto done;
    }

    if (C1p) {
        group = EC_GROUP_new_by_curve_name(NID_sm2);
        if (group == NULL)
            goto done;

        C1 = EC_POINT_new(group);
        if (C1 == NULL)
            goto done;

        if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                            sm2_ctext->C1y, NULL))
            goto done;

        EC_POINT_free(*C1p);
        *C1p = C1;
        C1 = NULL;
    }

    if (C2_data) {
        temp = OPENSSL_memdup(sm2_ctext->C2->data, sm2_ctext->C2->length);
        if (temp == NULL) {
            ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
            goto done;
        }

        OPENSSL_free(*C2_data);
        *C2_data = temp;

        if (C2_len)
            *C2_len = sm2_ctext->C2->length;
    }

    if (C3_data) {
        temp = OPENSSL_memdup(sm2_ctext->C3->data, sm2_ctext->C3->length);
        if (temp == NULL) {
            ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
            goto done;
        }

        OPENSSL_free(*C3_data);
        *C3_data = temp;

        if (C3_len)
            *C3_len = sm2_ctext->C3->length;
    }

    ok = 1;
done:
    EC_POINT_free(C1);
    EC_GROUP_free(group);
    SM2_Ciphertext_free(sm2_ctext);

    return ok;
}

/* GM/T003_2012 Defined Key Derive Function */
int kdf_gmt003_2012(unsigned char* out, size_t outlen, const unsigned char* Z, size_t Zlen, const unsigned char* SharedInfo, size_t SharedInfolen, const EVP_MD* md)
{
	EVP_MD_CTX* mctx = NULL;
	unsigned int counter;
	unsigned char ctr[4];
	size_t mdlen;
	int retval = 0;

	if (!out || !outlen)
		return retval;
	if (md == NULL) md = EVP_sm3();
	mdlen = EVP_MD_size(md);
	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		SM2err(SM2_F_KDF_GMT003_2012, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	for (counter = 1;; counter++)
	{
		unsigned char dgst[EVP_MAX_MD_SIZE];

		EVP_DigestInit(mctx, md);
		ctr[0] = (unsigned char)((counter >> 24) & 0xFF);
		ctr[1] = (unsigned char)((counter >> 16) & 0xFF);
		ctr[2] = (unsigned char)((counter >> 8) & 0xFF);
		ctr[3] = (unsigned char)(counter & 0xFF);
		if (!EVP_DigestUpdate(mctx, Z, Zlen))
			goto err;
		if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
			goto err;
		if (!EVP_DigestUpdate(mctx, SharedInfo, SharedInfolen))
			goto err;
		if (!EVP_DigestFinal(mctx, dgst, NULL))
			goto err;

		if (outlen > mdlen)
		{
			memcpy(out, dgst, mdlen);
			out += mdlen;
			outlen -= mdlen;
		}
		else
		{
			memcpy(out, dgst, outlen);
			memset(dgst, 0, mdlen);
			break;
		}
	}

	retval = 1;

err:
	EVP_MD_CTX_free(mctx);
	return retval;
}


int SM2Kap_compute_key(void* out, size_t outlen, int responsor, \
	const char* peer_uid, int peer_uid_len, const char* self_uid, int self_uid_len, \
	const EC_KEY* peer_ecdhe_key, const EC_KEY* self_ecdhe_key, const EC_KEY* peer_pub_key, const EC_KEY* self_eckey, \
	const EVP_MD* md)
{
	BN_CTX* ctx = NULL;
	EC_POINT* UorV = NULL;
	const EC_POINT* Rs, * Rp;
	BIGNUM* Xs = NULL, * Xp = NULL, * h = NULL, * t = NULL, * two_power_w = NULL, * order = NULL;
	const BIGNUM* priv_key, * r;
	const EC_GROUP* group;
	int w;
	int ret = -1;
	unsigned char* buf = NULL;

	if (outlen > INT_MAX)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!peer_pub_key || !self_eckey)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	priv_key = EC_KEY_get0_private_key(self_eckey);
	if (!priv_key)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	if (!peer_ecdhe_key || !self_ecdhe_key)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	Rs = EC_KEY_get0_public_key(self_ecdhe_key);
	Rp = EC_KEY_get0_public_key(peer_ecdhe_key);
	r = EC_KEY_get0_private_key(self_ecdhe_key);

	if (!Rs || !Rp || !r)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
		goto err;
	}

	ctx = BN_CTX_new();
	Xs = BN_new();
	Xp = BN_new();
	h = BN_new();
	t = BN_new();
	two_power_w = BN_new();
	order = BN_new();

	if (!Xs || !Xp || !h || !t || !two_power_w || !order)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	group = EC_KEY_get0_group(self_eckey);

	/*Second: Caculate -- w*/
	if (!EC_GROUP_get_order(group, order, ctx) || !EC_GROUP_get_cofactor(group, h, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	w = (BN_num_bits(order) + 1) / 2 - 1;
	if (!BN_lshift(two_power_w, BN_value_one(), w))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	/*Third: Caculate -- X =  2 ^ w + (x & (2 ^ w - 1)) = 2 ^ w + (x mod 2 ^ w)*/
	UorV = EC_POINT_new(group);

	if (!UorV)
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	/*Test peer public key On curve*/
	if (!EC_POINT_is_on_curve(group, Rp, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto err;
	}

	/*Get x*/
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_POINT_get_affine_coordinates_GFp(group, Rs, Xs, NULL, ctx))
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto err;
		}

		if (!EC_POINT_get_affine_coordinates_GFp(group, Rp, Xp, NULL, ctx))
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto err;
		}
	}
#ifndef OPENSSL_NO_EC2M
	else
	{
		if (!EC_POINT_get_affine_coordinates_GF2m(group, Rs, Xs, NULL, ctx))
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto err;
		}

		if (!EC_POINT_get_affine_coordinates_GF2m(group, Rp, Xp, NULL, ctx))
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto err;
		}
	}
#endif

	/*x mod 2 ^ w*/
	/*Caculate Self x*/
	if (!BN_nnmod(Xs, Xs, two_power_w, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	if (!BN_add(Xs, Xs, two_power_w))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	/*Caculate Peer x*/
	if (!BN_nnmod(Xp, Xp, two_power_w, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	if (!BN_add(Xp, Xp, two_power_w))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	/*Forth: Caculate t*/
	if (!BN_mod_mul(t, Xs, r, order, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	if (!BN_mod_add(t, t, priv_key, order, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	/*Fifth: Caculate V or U*/
	if (!BN_mul(t, t, h, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_BN_LIB);
		goto err;
	}

	/* [x]R */
	if (!EC_POINT_mul(group, UorV, NULL, Rp, Xp, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto err;
	}

	/* P + [x]R */
	if (!EC_POINT_add(group, UorV, UorV, EC_KEY_get0_public_key(peer_pub_key), ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto err;
	}

	if (!EC_POINT_mul(group, UorV, NULL, UorV, t, ctx))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto err;
	}

	/* Detect UorV is in */
	if (EC_POINT_is_at_infinity(group, UorV))
	{
		SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
		goto err;
	}

	/*Sixth: Caculate Key -- Need Xuorv, Yuorv, Zc, Zs, klen*/
	{
		size_t len, buflen;

		len = (size_t)((EC_GROUP_get_degree(group) + 7) / 8);
		buflen = len * 2 + 32 * 2 + 1;    /*add 1 byte tag*/
		buf = (unsigned char*)OPENSSL_malloc(buflen);
		if (!buf)
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
			goto err;
		}

		/*1 : Get public key for UorV, Notice: the first byte is a tag, not a valid char*/
		len = EC_POINT_point2oct(group, UorV, POINT_CONVERSION_UNCOMPRESSED, buf, buflen, ctx);
		if (!len)
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_EC_LIB);
			goto err;
		}

		if (!ossl_sm2_compute_z_digest((unsigned char*)(buf + len), md,
			!responsor ? (const uint8_t*)self_uid : (const uint8_t*)peer_uid,
			!responsor ? self_uid_len : peer_uid_len,
			!responsor ? self_eckey : peer_pub_key))
		{
			goto err;
		}
		len += 32;

		if (!ossl_sm2_compute_z_digest((unsigned char*)(buf + len), md,
			responsor ? (const uint8_t*)self_uid : (const uint8_t*)peer_uid,
			responsor ? self_uid_len : peer_uid_len,
			responsor ? self_eckey : peer_pub_key))
		{
			goto err;
		}
		len += 32;

		if (!kdf_gmt003_2012(out, outlen, (const unsigned char*)(buf + 1), len - 1, NULL, 0, md))
		{
			SM2err(SM2_F_SM2KAP_COMPUTE_KEY, ERR_R_INTERNAL_ERROR);
			goto err;
		}
	}

	ret = outlen;

err:
	if (Xs) BN_free(Xs);
	if (Xp) BN_free(Xp);
	if (h) BN_free(h);
	if (t) BN_free(t);
	if (two_power_w) BN_free(two_power_w);
	if (order) BN_free(order);
	if (UorV) EC_POINT_free(UorV);
	if (buf) OPENSSL_free(buf);
	if (ctx) BN_CTX_free(ctx);

	return ret;
}
