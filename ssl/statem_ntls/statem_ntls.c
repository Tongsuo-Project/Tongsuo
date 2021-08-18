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

#if (!defined OPENSSL_NO_NTLS) && (!defined OPENSSL_NO_SM2)    \
     && (!defined OPENSSL_NO_SM3) && (!defined OPENSSL_NO_SM4)

#include <sys/socket.h>
#include <arpa/inet.h>

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

int ntls_output_cert_chain_ntls(SSL *s, WPACKET *pkt, int a_idx, int k_idx)
{
    int i;
    STACK_OF(X509) *extra_certs;
    STACK_OF(X509) *chain = NULL;
    X509_STORE *chain_store;
    CERT_PKEY *a_cpk;
    CERT_PKEY *k_cpk;
    X509_STORE_CTX *xs_ctx = NULL;

    if (!WPACKET_start_sub_packet_u24(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_OUTPUT_CERT_CHAIN_NTLS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    a_cpk = &s->cert->pkeys[a_idx];
    k_cpk = &s->cert->pkeys[k_idx];

    if (a_cpk->chain)
        extra_certs = a_cpk->chain;
    else if (k_cpk->chain)
        extra_certs = k_cpk->chain;
    else
        extra_certs = s->ctx->extra_certs;

    if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || extra_certs)
        chain_store = NULL;
    else if (s->cert->chain_store)
        chain_store = s->cert->chain_store;
    else
        chain_store = s->ctx->cert_store;

    if (chain_store) {
        xs_ctx = X509_STORE_CTX_new();
        if (xs_ctx == NULL)
            goto err;

        if (!X509_STORE_CTX_init(xs_ctx, chain_store, a_cpk->x509, NULL))
            goto err;

        /*
         * deliberately skip the cert chain verification by don't check the
         * return value
         */
        (void)X509_verify_cert(xs_ctx);
        ERR_clear_error();

        chain = X509_STORE_CTX_get0_chain(xs_ctx);
        if (chain == NULL)
            goto err;

        i = ssl_security_cert_chain(s, chain, NULL, 0);
        if (i != 1) {
            goto err;
        }

        /* add signing certificate */
        if (!ssl_add_cert_to_wpacket_ntls(s, pkt, s->cert->pkeys[a_idx].x509, 0)) {
            goto err;
        }

        /* add key encryption certificate */
        if (!ssl_add_cert_to_wpacket_ntls(s, pkt, s->cert->pkeys[k_idx].x509, 0)) {
            goto err;
        }

        /* add the following chain */
        for (i = 1; i < sk_X509_num(chain); i++) {
            X509 *x = sk_X509_value(chain, i);
            if (!ssl_add_cert_to_wpacket_ntls(s, pkt, x, i))
                goto err;
        }
    } else {
        if (extra_certs == NULL && a_cpk->x509 == NULL)
            goto err;

        i = ssl_security_cert_chain(s, extra_certs, a_cpk->x509, 0);
        if (i != 1)
            goto err;

        /* output sign cert and enc cert */
        if (!ssl_add_cert_to_wpacket_ntls(s, pkt, s->cert->pkeys[a_idx].x509, 0))
            goto err;

        if (!ssl_add_cert_to_wpacket_ntls(s, pkt, s->cert->pkeys[k_idx].x509, 0))
            goto err;

        /* output the following chain */
        for (i = 0; i < sk_X509_num(extra_certs); i++) {
            X509 *x = sk_X509_value(extra_certs, i);
            if (!ssl_add_cert_to_wpacket_ntls(s, pkt, x, i))
                goto err;
        }
    }

    if (!WPACKET_close(pkt))
        goto err;
    X509_STORE_CTX_free(xs_ctx);
    return 1;

 err:
    X509_STORE_CTX_free(xs_ctx);
    SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_OUTPUT_CERT_CHAIN_NTLS,
             ERR_R_INTERNAL_ERROR);
    return 0;
}


# define PEEK_HEADER_LENGTH 3
int SSL_connection_is_ntls(SSL *s, int is_server)
{
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
        if (s->clienthello) {
            if (s->clienthello->legacy_version == NTLS1_1_VERSION)
                return 1;
            else
                return 0;
        }

        /*
         * For server, first flight has not set version, we
         * have to get the server version from clientHello
         */
        if (SSL_IS_FIRST_HANDSHAKE(s) && SSL_in_before(s)) {
            int ret, fd;
            PACKET pkt;
            unsigned int version, type;
            unsigned char buf[PEEK_HEADER_LENGTH];

            ret = BIO_get_fd(s->rbio, &fd);

            if (ret <= 0) {
                /* NTLS only support socket communication */
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                            ERR_R_INTERNAL_ERROR);
                return -1;
            }

            ret = recv(fd, buf, PEEK_HEADER_LENGTH, MSG_PEEK);
            if (ret < PEEK_HEADER_LENGTH) {
                s->rwstate = SSL_READING;
                return -1;
            }

            if (!PACKET_buf_init(&pkt, buf, 3)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                            ERR_R_INTERNAL_ERROR);
                return -1;
            }

            if (!PACKET_get_1(&pkt, &type)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                         ERR_R_INTERNAL_ERROR);
                return -1;
            }

            if (!PACKET_get_net_2(&pkt, &version)) {
                SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_F_SSL_CONNECTION_IS_NTLS,
                         ERR_R_INTERNAL_ERROR);
                return -1;
            }

            if (version == NTLS1_1_VERSION)
                return 1;
            else
                return 0;
        }
    }

    return 0;
}

#endif
