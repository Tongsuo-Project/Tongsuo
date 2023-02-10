/*
 * Copyright 2019 The BabaSSL Project Authors. All Rights Reserved.
 */

#include <stdio.h>
#include <openssl/opensslconf.h>
#include "ssl_local_ntls.h"
#include "statem_local_ntls.h"
#include "internal/constant_time.h"
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>

#ifndef OPENSSL_NO_NTLS

#include "internal/sockets.h"

# if !defined(OPENSSL_NO_SM2) && !defined(OPENSSL_NO_SM3)
int ntls_sm2_derive_ntls(SSL *s, EVP_PKEY *tmp_priv, EVP_PKEY *peer_tmp_pub)
{
    int ret = 0, idx = 1;
    /* peer ecdh temporary public key */
    EC_KEY *peer_tmp_pub_ec;
    /* self ecdh temporary private key */
    EC_KEY *tmp_priv_ec;
    /* peer encryption certificate, public PKEY and public EC key */
    X509 *peer_x509;
    EVP_PKEY *peer_cert_pub;
    EC_KEY *peer_cert_pub_ec;
    /* self encryption certificate private key (PKEY and EC) */
    EVP_PKEY *cert_priv = NULL;
    EC_KEY *cert_priv_ec = NULL;
    /* self SM2 ID */
    char *id = "1234567812345678";
    /* peer SM2 ID */
    char *peer_id = "1234567812345678";
    /* pre-master secret */
    unsigned char *pms = NULL;
    size_t pmslen = SSL_MAX_MASTER_KEY_LENGTH;

    if (!(peer_tmp_pub_ec = EVP_PKEY_get0_EC_KEY(peer_tmp_pub))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!(tmp_priv_ec = EVP_PKEY_get0_EC_KEY(tmp_priv))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* SM2 requires to use the private key in encryption certificate */
    if (!(cert_priv = s->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey)) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!(cert_priv_ec = EVP_PKEY_get0_EC_KEY(cert_priv))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /*
     * XXX:
     *
     * For NTLS server side, s->session->peer stores the client signing
     * certificate and s->session->peer_chain is an one-item stack which
     * stores the client encryption certificate.
     *
     * We need to get the client encryption certificate at this stage,
     * so we use index 0 in peer_chain.
     *
     * For client side of NTLS, the peer is an reference of the first element
     * of the two-item stack stored in s->session->peer_chain, which is the
     * signing certificate of server. So we need to get the second certificate
     * in this scenario for encryption usage.
     */
    if (s->session->peer_chain == NULL) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (s->server)
        idx = 0;

    if (!(peer_x509 = sk_X509_value(s->session->peer_chain, idx))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    peer_cert_pub = X509_get0_pubkey(peer_x509);
    if (!(peer_cert_pub_ec = EVP_PKEY_get0_EC_KEY(peer_cert_pub))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((pms = OPENSSL_malloc(pmslen)) == NULL) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!SM2_compute_key(pms, pmslen, s->server,
                         peer_id, strlen(peer_id),
                         id, strlen(id),
                         /* peer and self ecdh temp key */
                         peer_tmp_pub_ec, tmp_priv_ec,
                         /* peer and self certificate key */
                         peer_cert_pub_ec, cert_priv_ec,
                         EVP_sm3())) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        goto end;
    }

    if (s->server) {
        ret = ssl_generate_master_secret(s, pms, pmslen, 1);
    } else {
        s->s3->tmp.pms = pms;
        s->s3->tmp.pmslen = pmslen;
        ret = 1;
    }

 end:
    return ret;
}
# endif

int SSL_connection_is_ntls(SSL *s, int is_server)
{
    int ret = 0;
    unsigned int version;
    uint8_t *p, *data = NULL;

    /*
     * For client, or sometimes ssl_version is fixed,
     * we can easily determine if version is NTLS
     */
    if (s->version == NTLS1_1_VERSION)
        return 1;

    if (is_server) {
        /* After receiving client hello and before choosing server version,
         * get version from s->clienthello->legacy_version
         */
        if (s->clienthello)
            return s->clienthello->legacy_version == NTLS1_1_VERSION;

        if (s->preread_len >= sizeof(s->preread_buf)) {
            p = &s->preread_buf[1];
            n2s(p, version);
            return version == NTLS1_1_VERSION;
        }

        /*
         * For server, first flight has not set version, we
         * have to get the server version from clientHello
         */
        if (!SSL_IS_FIRST_HANDSHAKE(s) || !SSL_in_before(s))
            return 0;

        if (s->rbio == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                     SSL_R_READ_BIO_NOT_SET);
            return -1;
        }

        data = s->preread_buf + s->preread_len;

        clear_sys_error();
        s->rwstate = SSL_READING;
        ret = BIO_read(s->rbio, data, sizeof(s->preread_buf) - s->preread_len);

        if (ret <= 0)
            return -1;

        if (ret > 0)
            s->preread_len += ret;

        if (s->preread_len >= sizeof(s->preread_buf)) {
            BIO *bbio = BIO_new(BIO_f_buffer());
            if (bbio == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                         ERR_R_MALLOC_FAILURE);
                return -1;
            }

            if (BIO_set_buffer_read_data(bbio, s->preread_buf,
                                         sizeof(s->preread_buf))
                != 1) {
                BIO_vfree(bbio);
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                         ERR_R_INTERNAL_ERROR);
                return -1;
            }

            s->rwstate = SSL_NOTHING;
            s->rbio = BIO_push(bbio, s->rbio);

            p = &s->preread_buf[1];
            n2s(p, version);
            return version == NTLS1_1_VERSION;
        }

        return -1;
    }

    return 0;
}

#endif
