#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include "crypto/x509.h"
#include "../../ssl/ssl_local.h"
#include "internal/refcount.h"

#define DC_MAX_LEN 65535

DELEGATED_CREDENTIAL *DC_new(void)
{
    return DC_new_ex(NULL, NULL);
}

DELEGATED_CREDENTIAL *DC_new_ex(OSSL_LIB_CTX *libctx, const char *propq)
{
    DELEGATED_CREDENTIAL *dc;

    dc = OPENSSL_zalloc(sizeof(DELEGATED_CREDENTIAL));
    if (dc == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    dc->references = 1;
    dc->lock = CRYPTO_THREAD_lock_new();
    if (dc->lock == NULL)
        goto err;

    dc->libctx = libctx;
    if (propq != NULL) {
        dc->propq = OPENSSL_strdup(propq);
        if (dc->propq == NULL)
            goto err;
    }

    return dc;
err:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);

    DC_free(dc);
    return NULL;
}

void DC_free(DELEGATED_CREDENTIAL *dc)
{
    int i;

    if (dc == NULL)
        return;

    CRYPTO_DOWN_REF(&dc->references, &i, dc->lock);
    REF_PRINT_COUNT("DC", dc);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);
    CRYPTO_THREAD_lock_free(dc->lock);

    OPENSSL_free(dc->dc_publickey_raw);
    OPENSSL_free(dc->dc_signature);
    EVP_PKEY_free(dc->pkey);
    OPENSSL_free(dc->raw_byte);
    OPENSSL_free(dc->propq);

    OPENSSL_free(dc);
}

int DC_up_ref(DELEGATED_CREDENTIAL *dc)
{
    int i;

    if (CRYPTO_UP_REF(&dc->references, &i, dc->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DC", dc);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

DELEGATED_CREDENTIAL *DC_new_from_raw_byte(const unsigned char *byte,
                                           size_t len)
{
    return DC_new_from_raw_byte_ex(byte, len, NULL, NULL);
}

DELEGATED_CREDENTIAL *DC_new_from_raw_byte_ex(const unsigned char *byte,
                                              size_t len,
                                              OSSL_LIB_CTX *libctx,
                                              const char *propq)
{
    unsigned long         valid_time;
    unsigned int          expected_cert_verify_algorithm;
    unsigned long         dc_publickey_raw_len;
    unsigned char        *dc_publickey_raw = NULL;
    unsigned int          signature_sign_algorithm;
    unsigned int          dc_signature_len;
    unsigned char        *dc_signature = NULL;
    PACKET                pkt;
    DELEGATED_CREDENTIAL *dc = NULL;
    EVP_PKEY             *pkey = NULL;

    dc = DC_new_ex(libctx, propq);
    if (dc == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if(!DC_set1_raw_byte(dc, byte, len))
        goto err;

    if (!PACKET_buf_init(&pkt, dc->raw_byte, dc->raw_byte_len))
        goto err;

    if (PACKET_remaining(&pkt) <= 0)
        goto err;

    if (!PACKET_get_net_4(&pkt, &valid_time)
        || !PACKET_get_net_2(&pkt, &expected_cert_verify_algorithm)
        || !PACKET_get_net_3(&pkt, &dc_publickey_raw_len)) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_FORMAT);
        goto err;
    }
    dc->valid_time = valid_time;
    dc->expected_cert_verify_algorithm = expected_cert_verify_algorithm;
    dc->dc_publickey_raw_len = dc_publickey_raw_len;

    if (dc_publickey_raw_len > pkt.remaining) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE);
        goto err;
    }
    dc_publickey_raw = OPENSSL_malloc(dc_publickey_raw_len);
    if (dc_publickey_raw == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    dc->dc_publickey_raw = dc_publickey_raw;

    if (!PACKET_copy_bytes(&pkt, dc_publickey_raw, dc_publickey_raw_len)) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE);
        goto err;
    }

    pkey = d2i_PUBKEY_ex(NULL, (const unsigned char **)&dc_publickey_raw,
                         dc_publickey_raw_len, libctx, propq);
    if (pkey == NULL) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE);
        goto err;
    }

    /* DC public key MUST NOT use the rsaEncryption OID */
    if (EVP_PKEY_is_a(pkey, "RSA")) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_PUBLIC_KEY_TYPE);
        goto err;
    }

    dc->pkey = pkey;

    if (!PACKET_get_net_2(&pkt, &signature_sign_algorithm)
        || !PACKET_get_net_2(&pkt, &dc_signature_len)) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_FORMAT);
        goto err;
    }
    dc->signature_sign_algorithm = signature_sign_algorithm;

    if (dc_signature_len > pkt.remaining) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE);
        goto err;
    }
    dc->dc_signature_len = dc_signature_len;
    dc_signature = OPENSSL_malloc(dc_signature_len);
    if (dc_signature == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    dc->dc_signature = dc_signature;

    if (!PACKET_copy_bytes(&pkt, dc_signature, dc_signature_len)) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE);
        goto err;
    }

    return dc;
err:
    DC_free(dc);
    return NULL;
}

DELEGATED_CREDENTIAL *DC_load_from_file(const char *file)
{
    return DC_load_from_file_ex(file, NULL, NULL);
}

DELEGATED_CREDENTIAL *DC_load_from_file_ex(const char *file,
                                           OSSL_LIB_CTX *libctx,
                                           const char *propq)
{
    DELEGATED_CREDENTIAL *dc = NULL;
    BIO *bio_dc = NULL;
    char *dc_hex_buf = NULL;
    unsigned char *dc_buf = NULL;
    int dc_hex_len, len;
    size_t dc_buf_len;

    dc_hex_buf = OPENSSL_malloc(DC_MAX_LEN);
    if (dc_hex_buf == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    bio_dc = BIO_new_file(file, "r");
    if (bio_dc == NULL) {
        goto err;
    }

    dc_hex_len = BIO_read(bio_dc, dc_hex_buf, DC_MAX_LEN - 1);
    if (dc_hex_len <= 0) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT);
        goto err;
    }

    if (dc_hex_buf[dc_hex_len - 1] == '\n')
        dc_hex_buf[dc_hex_len - 1] = '\0';
    else
        dc_hex_buf[dc_hex_len] = '\0';

    /*
     * parse from hex byte, just for tmp, because there is no
     * standard dc format define
     */
    len = dc_hex_len / 2;

    dc_buf = OPENSSL_malloc(len);
    if (dc_buf == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!OPENSSL_hexstr2buf_ex(dc_buf, len, &dc_buf_len, dc_hex_buf, '\0')) {
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT);
        goto err;
    }

    dc = DC_new_from_raw_byte_ex(dc_buf, dc_buf_len, libctx, propq);
    if (dc == NULL)
        goto err;

err:
    OPENSSL_free(dc_buf);
    OPENSSL_free(dc_hex_buf);
    BIO_free(bio_dc);
    return dc;
}
