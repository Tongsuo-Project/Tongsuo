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

# if !(defined(OPENSSL_NO_KEYLESS) && defined(OPENSSL_NO_LURK))
static int ntls_i2d_pkey(int (*i2d) (EVP_PKEY *, unsigned char **),
                         EVP_PKEY *pkey_in, unsigned char **str_out, int *len_out)
{
    int dsize;
    unsigned char *idx;

    if ((dsize = i2d(pkey_in, NULL)) < 0) {
        SSLerr(SSL_F_NTLS_I2D_PKEY, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* dsize + 8 bytes are needed */
    /* actually it needs the cipher block size extra... */
    *str_out = OPENSSL_malloc((unsigned int)dsize + 20);
    idx = *str_out;
    if (*str_out == NULL) {
        SSLerr(SSL_F_NTLS_I2D_PKEY, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    *len_out = i2d(pkey_in, &idx);
    if (*len_out <= 0) {
        OPENSSL_free(str_out);
        SSLerr(SSL_F_NTLS_I2D_PKEY, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}
# endif

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

#ifndef OPENSSL_NO_KEYLESS
    if (s->keyless_ntls && s->keyless_again)
        goto keyless_recover;
#endif
#ifndef OPENSSL_NO_LURK
    if (s->lurk_ntls && s->lurk_again)
        goto lurk_recover;
#endif

    if (!(peer_tmp_pub_ec = EVP_PKEY_get0_EC_KEY(peer_tmp_pub))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!(tmp_priv_ec = EVP_PKEY_get0_EC_KEY(tmp_priv))) {
        SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (1
#ifndef OPENSSL_NO_KEYLESS
        && !s->keyless_ntls
#endif
#ifndef OPENSSL_NO_LURK
        && !s->lurk_ntls
#endif
       )
    {
        /* SM2 requires to use the private key in encryption certificate */
        if (!(cert_priv = s->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey)) {
            SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!(cert_priv_ec = EVP_PKEY_get0_EC_KEY(cert_priv))) {
            SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
            return 0;
        }
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

#if !(defined(OPENSSL_NO_KEYLESS) && defined(OPENSSL_NO_LURK))
    if (0
# ifndef OPENSSL_NO_KEYLESS
        || s->keyless_ntls
# endif
# ifndef OPENSSL_NO_LURK
        || s->lurk_ntls
# endif
       )
    {
        unsigned char *tmp_priv_char, *peer_tmp_pub_char, *peer_cert_pub_char;
        unsigned char *tmp_buf, *buf_index;
        int     tmp_priv_len, peer_tmp_pub_len, peer_cert_pub_len;
        uint32_t  prefix_len;
        uint32_t  len_net;
        int keyless_ret  = 0;


        if (ntls_i2d_pkey(i2d_PrivateKey,
                          tmp_priv, &tmp_priv_char, &tmp_priv_len) <=0 ) {
            SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (ntls_i2d_pkey(i2d_PUBKEY,peer_tmp_pub,
                          &peer_tmp_pub_char, &peer_tmp_pub_len) <=0 ) {
            SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(tmp_priv_char);
            return 0;
        }

        if (ntls_i2d_pkey(i2d_PUBKEY,peer_cert_pub,
                          &peer_cert_pub_char, &peer_cert_pub_len) <=0 ) {
            SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(tmp_priv_char);
            OPENSSL_free(peer_tmp_pub_char);
            return 0;
        }

        /*
         * package format
         * --------------------------------------------------
         * tmp_priv_char (4byte) | data (tmp_priv_len bytes)| ...
         * --------------------------------------------------
         * ----------------------------------------------------------
         * peer_tmp_pub_char (4byte) | data (peer_tmp_pub_len bytes)| ...
         * ----------------------------------------------------------
         * ------------------------------------------------------------
         * peer_cert_pub_char (4byte) | data (peer_cert_pub_len bytes)|
         * ------------------------------------------------------------
         */
        prefix_len = 4;

        tmp_buf = (unsigned char *)OPENSSL_malloc(prefix_len + tmp_priv_len +
                                                  prefix_len + peer_tmp_pub_len +
                                                  prefix_len + peer_cert_pub_len);
        if (tmp_buf == NULL) {
            SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
            OPENSSL_free(tmp_priv_char);
            OPENSSL_free(peer_tmp_pub_char);
            OPENSSL_free(peer_cert_pub_char);
            return 0;
        }
        buf_index = tmp_buf;
        len_net = htonl(tmp_priv_len);
        memcpy(buf_index, &len_net, prefix_len);
        buf_index += prefix_len;
        memcpy(buf_index, tmp_priv_char, tmp_priv_len);
        buf_index += tmp_priv_len;
        len_net = htonl(peer_tmp_pub_len);
        memcpy(buf_index, &len_net, prefix_len);
        buf_index += prefix_len;
        memcpy(buf_index, peer_tmp_pub_char, peer_tmp_pub_len);
        buf_index += peer_tmp_pub_len;
        len_net = htonl(peer_cert_pub_len);
        memcpy(buf_index, &len_net, prefix_len);
        buf_index += prefix_len;
        memcpy(buf_index, peer_cert_pub_char, peer_cert_pub_len);
        OPENSSL_free(tmp_priv_char);
        OPENSSL_free(peer_tmp_pub_char);
        OPENSSL_free(peer_cert_pub_char);

# ifndef OPENSSL_NO_KEYLESS
        if (s->keyless_ntls) {
            s->keyless_callback_param.data = tmp_buf;
            s->keyless_callback_param.len = tmp_priv_len + peer_tmp_pub_len
                                            + peer_cert_pub_len + 3 * prefix_len;
            s->keyless_callback_param.type = SSL_KEYLESS_TYPE_SM2DHE_GEN_MASTER_KEY;
            s->keyless_callback_param.cert_tag = SSL_ENC_CERT;

            keyless_ret = s->keyless_callback(s, &s->keyless_callback_param);

            OPENSSL_free(tmp_buf);
            if (keyless_ret == 1) {
                /* again or done */
                s->keyless_again = 1;
                return 0;
            } else if (keyless_ret == 0) {
keyless_recover:
                pmslen = s->keyless_result_len;
                if ((pms = OPENSSL_malloc(pmslen)) == NULL) {
                    SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                memcpy(pms, s->keyless_result, s->keyless_result_len);

                if (s->keyless_again)
                    s->keyless_again = 0;
            } else {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_SM2_DERIVE_NTLS,
                            SSL_R_KEYLESS_ERROR);
                goto end;
            }
        } else
# endif
# ifndef OPENSSL_NO_LURK
        if (s->lurk) {
            s->lurk_callback_param.data = tmp_buf;
            s->lurk_callback_param.len = tmp_priv_len + peer_tmp_pub_len
                                            + peer_cert_pub_len + 3 * prefix_len;
            s->lurk_callback_param.type = SSL_LURK_QUERY_SM2DHE_GEN_MASTER_KEY;
            s->lurk_callback_param.cert_tag = SSL_ENC_CERT;

            keyless_ret = s->lurk_callback(s, &s->lurk_callback_param);
            OPENSSL_free(tmp_buf);
            if (keyless_ret == 1) {
                /* again or done */
                s->lurk_again = 1;
                return 0;
            } else if (keyless_ret == 0) {
lurk_recover:
                pmslen = s->lurk_result_len;
                if ((pms = OPENSSL_malloc(pmslen)) == NULL) {
                    SSLerr(SSL_F_NTLS_SM2_DERIVE_NTLS, ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                memcpy(pms, s->lurk_result, s->lurk_result_len);

                if (s->lurk_again)
                    s->lurk_again = 0;
            } else {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_NTLS_SM2_DERIVE_NTLS,
                            SSL_R_KEYLESS_ERROR);
                goto end;
            }
        }
# else
        {
        }
# endif
    } else
#endif
    {
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
# ifndef OPENSSL_NO_KEYLESS
    /*
     * keyless processing has choosed verison before
     */
    if ((s->keyless || s->keyless_ntls) && s->keyless_again) {
        if (s->version == NTLS1_1_VERSION)
            return 1;
        else
            return 0;
    }
# endif
# ifndef OPENSSL_NO_LURK
    /*
     * keyless processing has choosed verison before
     */
    if (s->lurk && s->lurk_ntls && s->lurk_again) {
        if (s->version == NTLS1_1_VERSION)
            return 1;
        else
            return 0;
    }
# endif

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
