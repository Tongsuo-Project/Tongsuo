/*
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ocsp.h>
#include "ntls_ssl_local.h"
#include "ntls_statem_local.h"
#include "internal/cryptlib.h"

#define COOKIE_STATE_FORMAT_VERSION     0

/*
 * 2 bytes for packet length, 2 bytes for format version, 2 bytes for
 * protocol version, 2 bytes for group id, 2 bytes for cipher id, 1 byte for
 * key_share present flag, 4 bytes for timestamp, 2 bytes for the hashlen,
 * EVP_MAX_MD_SIZE for transcript hash, 1 byte for app cookie length, app cookie
 * length bytes, SHA256_DIGEST_LENGTH bytes for the HMAC of the whole thing.
 */
#define MAX_COOKIE_SIZE (2 + 2 + 2 + 2 + 2 + 1 + 4 + 2 + EVP_MAX_MD_SIZE + 1 \
                         + SSL_COOKIE_LENGTH + SHA256_DIGEST_LENGTH)

/*
 * Message header + 2 bytes for protocol version + number of random bytes +
 * + 1 byte for legacy session id length + number of bytes in legacy session id
 * + 2 bytes for ciphersuite + 1 byte for legacy compression
 * + 2 bytes for extension block length + 6 bytes for key_share extension
 * + 4 bytes for cookie extension header + the number of bytes in the cookie
 */
#define MAX_HRR_SIZE    (SSL3_HM_HEADER_LENGTH + 2 + SSL3_RANDOM_SIZE + 1 \
                         + SSL_MAX_SSL_SESSION_ID_LENGTH + 2 + 1 + 2 + 6 + 4 \
                         + MAX_COOKIE_SIZE)


/*-
 * The servername extension is treated as follows:
 *
 * - Only the hostname type is supported with a maximum length of 255.
 * - The servername is rejected if too long or if it contains zeros,
 *   in which case an fatal alert is generated.
 * - The servername field is maintained together with the session cache.
 * - When a session is resumed, the servername call back invoked in order
 *   to allow the application to position itself to the right context.
 * - The servername is acknowledged if it is new for a session or when
 *   it is identical to a previously used for the same session.
 *   Applications can control the behaviour.  They can at any time
 *   set a 'desirable' servername for a new SSL object. This can be the
 *   case for example with HTTPS when a Host: header field is received and
 *   a renegotiation is requested. In this case, a possible servername
 *   presented in the new client hello is only acknowledged if it matches
 *   the value of the Host: field.
 * - Applications must  use SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
 *   if they provide for changing an explicit servername context for the
 *   session, i.e. when the session has been established with a servername
 *   extension.
 * - On session reconnect, the servername extension may be absent.
 */
int tls_parse_ctos_server_name_ntls(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    unsigned int servname_type;
    PACKET sni, hostname;

    if (!PACKET_as_length_prefixed_2(pkt, &sni)
        /* ServerNameList must be at least 1 byte long. */
        || PACKET_remaining(&sni) == 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * Although the intent was for server_name to be extensible, RFC 4366
     * was not clear about it; and so OpenSSL among other implementations,
     * always and only allows a 'host_name' name types.
     * RFC 6066 corrected the mistake but adding new name types
     * is nevertheless no longer feasible, so act as if no other
     * SNI types can exist, to simplify parsing.
     *
     * Also note that the RFC permits only one SNI value per type,
     * i.e., we can only have a single hostname.
     */
    if (!PACKET_get_1(&sni, &servname_type)
        || servname_type != TLSEXT_NAMETYPE_host_name
        || !PACKET_as_length_prefixed_2(&sni, &hostname)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * In TLSv1.2 and below the SNI is associated with the session. In TLSv1.3
     * we always use the SNI value from the handshake.
     */
    if (!s->hit || SSL_IS_TLS13(s)) {
        if (PACKET_remaining(&hostname) > TLSEXT_MAXLEN_host_name) {
            SSLfatal_ntls(s, SSL_AD_UNRECOGNIZED_NAME, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (PACKET_contains_zero_byte(&hostname)) {
            SSLfatal_ntls(s, SSL_AD_UNRECOGNIZED_NAME, SSL_R_BAD_EXTENSION);
            return 0;
        }

        /*
         * Store the requested SNI in the SSL as temporary storage.
         * If we accept it, it will get stored in the SSL_SESSION as well.
         */
        OPENSSL_free(s->ext.hostname);
        s->ext.hostname = NULL;
        if (!PACKET_strndup(&hostname, &s->ext.hostname)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        s->servername_done = 1;
    } else {
        /*
         * In TLSv1.2 and below we should check if the SNI is consistent between
         * the initial handshake and the resumption. In TLSv1.3 SNI is not
         * associated with the session.
         */
        s->servername_done = (s->session->ext.hostname != NULL)
            && PACKET_equal(&hostname, s->session->ext.hostname,
                            strlen(s->session->ext.hostname));
    }

    return 1;
}

int tls_parse_ctos_maxfragmentlen_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    unsigned int value;

    if (PACKET_remaining(pkt) != 1 || !PACKET_get_1(pkt, &value)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* Received |value| should be a valid max-fragment-length code. */
    if (!IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * RFC 6066:  The negotiated length applies for the duration of the session
     * including session resumptions.
     * We should receive the same code as in resumed session !
     */
    if (s->hit && s->session->ext.max_fragment_len_mode != value) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * Store it in session, so it'll become binding for us
     * and we'll include it in a next Server Hello.
     */
    s->session->ext.max_fragment_len_mode = value;
    return 1;
}

int tls_parse_ctos_ec_pt_formats_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
    /* Ignore ec_point_formats */
    return 1;
}

int tls_parse_ctos_session_ticket_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ext.session_ticket_cb &&
            !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ext.session_ticket_cb_arg)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int tls_parse_ctos_sig_algs_cert_ntls(SSL *s, PACKET *pkt,
                                      ossl_unused unsigned int context,
                                      ossl_unused X509 *x,
									  ossl_unused size_t chainidx)
{
    /* Ignore signature_algorithms_cert */
    return 1;
}

int tls_parse_ctos_sig_algs_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    /* Ignore signature_algorithms */
    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_parse_ctos_status_request_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    PACKET responder_id_list, exts;

    /* We ignore this in a resumption handshake */
    if (s->hit)
        return 1;

    /* Not defined if we get one of these in a client Certificate */
    if (x != NULL)
        return 1;

    if (!PACKET_get_1(pkt, (unsigned int *)&s->ext.status_type)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp) {
        /*
         * We don't know what to do with any other type so ignore it.
         */
        s->ext.status_type = TLSEXT_STATUSTYPE_nothing;
        return 1;
    }

    if (!PACKET_get_length_prefixed_2 (pkt, &responder_id_list)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * We remove any OCSP_RESPIDs from a previous handshake
     * to prevent unbounded memory growth - CVE-2016-6304
     */
    sk_OCSP_RESPID_pop_free(s->ext.ocsp.ids, OCSP_RESPID_free);
    if (PACKET_remaining(&responder_id_list) > 0) {
        s->ext.ocsp.ids = sk_OCSP_RESPID_new_null();
        if (s->ext.ocsp.ids == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    } else {
        s->ext.ocsp.ids = NULL;
    }

    while (PACKET_remaining(&responder_id_list) > 0) {
        OCSP_RESPID *id;
        PACKET responder_id;
        const unsigned char *id_data;

        if (!PACKET_get_length_prefixed_2(&responder_id_list, &responder_id)
                || PACKET_remaining(&responder_id) == 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            return 0;
        }

        id_data = PACKET_data(&responder_id);
        id = d2i_OCSP_RESPID(NULL, &id_data,
                             (int)PACKET_remaining(&responder_id));
        if (id == NULL) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (id_data != PACKET_end(&responder_id)) {
            OCSP_RESPID_free(id);
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);

            return 0;
        }

        if (!sk_OCSP_RESPID_push(s->ext.ocsp.ids, id)) {
            OCSP_RESPID_free(id);
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);

            return 0;
        }
    }

    /* Read in request_extensions */
    if (!PACKET_as_length_prefixed_2(pkt, &exts)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (PACKET_remaining(&exts) > 0) {
        const unsigned char *ext_data = PACKET_data(&exts);

        sk_X509_EXTENSION_pop_free(s->ext.ocsp.exts,
                                   X509_EXTENSION_free);
        s->ext.ocsp.exts =
            d2i_X509_EXTENSIONS(NULL, &ext_data, (int)PACKET_remaining(&exts));
        if (s->ext.ocsp.exts == NULL || ext_data != PACKET_end(&exts)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            return 0;
        }
    }

    return 1;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_parse_ctos_npn_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /*
     * We shouldn't accept this extension on a
     * renegotiation.
     */
    if (SSL_IS_FIRST_HANDSHAKE(s))
        s->s3.npn_seen = 1;

    return 1;
}
#endif

/*
 * Save the ALPN extension in a ClientHello.|pkt| holds the contents of the ALPN
 * extension, not including type and length. Returns: 1 on success, 0 on error.
 */
int tls_parse_ctos_alpn_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx)
{
    PACKET protocol_list, save_protocol_list, protocol;

    if (!SSL_IS_FIRST_HANDSHAKE(s))
        return 1;

    if (!PACKET_as_length_prefixed_2(pkt, &protocol_list)
        || PACKET_remaining(&protocol_list) < 2) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    save_protocol_list = protocol_list;
    do {
        /* Protocol names can't be empty. */
        if (!PACKET_get_length_prefixed_1(&protocol_list, &protocol)
                || PACKET_remaining(&protocol) == 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            return 0;
        }
    } while (PACKET_remaining(&protocol_list) != 0);

    OPENSSL_free(s->s3.alpn_proposed);
    s->s3.alpn_proposed = NULL;
    s->s3.alpn_proposed_len = 0;
    if (!PACKET_memdup(&save_protocol_list,
                       &s->s3.alpn_proposed, &s->s3.alpn_proposed_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
int tls_parse_ctos_use_srtp_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *srvr;
    unsigned int ct, mki_len, id;
    int i, srtp_pref;
    PACKET subpkt;

    /* Ignore this if we have no SRTP profiles */
    if (SSL_get_srtp_profiles(s) == NULL)
        return 1;

    /* Pull off the length of the cipher suite list  and check it is even */
    if (!PACKET_get_net_2(pkt, &ct) || (ct & 1) != 0
            || !PACKET_get_sub_packet(pkt, &subpkt, ct)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
		              SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    srvr = SSL_get_srtp_profiles(s);
    s->srtp_profile = NULL;
    /* Search all profiles for a match initially */
    srtp_pref = sk_SRTP_PROTECTION_PROFILE_num(srvr);

    while (PACKET_remaining(&subpkt)) {
        if (!PACKET_get_net_2(&subpkt, &id)) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                          SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
            return 0;
        }

        /*
         * Only look for match in profiles of higher preference than
         * current match.
         * If no profiles have been have been configured then this
         * does nothing.
         */
        for (i = 0; i < srtp_pref; i++) {
            SRTP_PROTECTION_PROFILE *sprof =
                sk_SRTP_PROTECTION_PROFILE_value(srvr, i);

            if (sprof->id == id) {
                s->srtp_profile = sprof;
                srtp_pref = i;
                break;
            }
        }
    }

    /* Now extract the MKI value as a sanity check, but discard it for now */
    if (!PACKET_get_1(pkt, &mki_len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                      SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    if (!PACKET_forward(pkt, mki_len)
        || PACKET_remaining(pkt)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_SRTP_MKI_VALUE);
        return 0;
    }

    return 1;
}
#endif

int tls_parse_ctos_etm_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore encrypt-then-MAC */
    return 1;
}

int tls_parse_ctos_supported_groups_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                    X509 *x, size_t chainidx)
{
    /* Ignore supported_groups */
    return 1;
}

int tls_parse_ctos_ems_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore extended_master_secret */
    return 1;
}

EXT_RETURN tls_construct_stoc_server_name_ntls(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (s->servername_done != 1)
        return EXT_RETURN_NOT_SENT;

    /*
     * Prior to TLSv1.3 we ignore any SNI in the current handshake if resuming.
     * We just use the servername from the initial handshake.
     */
    if (s->hit && !SSL_IS_TLS13(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_server_name)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

/* Add/include the server's max fragment len extension into ServerHello */
EXT_RETURN tls_construct_stoc_maxfragmentlen_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (!USE_MAX_FRAGMENT_LENGTH_EXT(s->session))
        return EXT_RETURN_NOT_SENT;

    /*-
     * 4 bytes for this extension type and extension length
     * 1 byte for the Max Fragment Length code value.
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_max_fragment_length)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u8(pkt, s->session->ext.max_fragment_len_mode)
        || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_stoc_ec_pt_formats_ntls(SSL *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
    /* No ec_point_formats */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_stoc_supported_groups_ntls(SSL *s, WPACKET *pkt,
                                               unsigned int context, X509 *x,
                                               size_t chainidx)
{
    /* No supported_groups */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_stoc_session_ticket_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (!s->ext.ticket_expected || !tls_use_ticket(s)) {
        s->ext.ticket_expected = 0;
        return EXT_RETURN_NOT_SENT;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENSSL_NO_OCSP
EXT_RETURN tls_construct_stoc_status_request_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    /* We don't currently support this extension inside a CertificateRequest */
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)
        return EXT_RETURN_NOT_SENT;

    if (!s->ext.status_expected)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * In TLSv1.3 we include the certificate status itself. In <= TLSv1.2 we
     * send back an empty extension, with the certificate status appearing as a
     * separate message
     */
    if (!WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
EXT_RETURN tls_construct_stoc_next_proto_neg_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    const unsigned char *npa;
    unsigned int npalen;
    int ret;
    int npn_seen = s->s3.npn_seen;

    s->s3.npn_seen = 0;
    if (!npn_seen || s->ctx->ext.npn_advertised_cb == NULL)
        return EXT_RETURN_NOT_SENT;

    ret = s->ctx->ext.npn_advertised_cb(s, &npa, &npalen,
                                        s->ctx->ext.npn_advertised_cb_arg);
    if (ret == SSL_TLSEXT_ERR_OK) {
        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
                || !WPACKET_sub_memcpy_u16(pkt, npa, npalen)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        s->s3.npn_seen = 1;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_stoc_alpn_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx)
{
    if (s->s3.alpn_selected == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u8(pkt, s->s3.alpn_selected,
                                      s->s3.alpn_selected_len)
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifndef OPENSSL_NO_SRTP
EXT_RETURN tls_construct_stoc_use_srtp_ntls(SSL *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    if (s->srtp_profile == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u16(pkt, 2)
            || !WPACKET_put_bytes_u16(pkt, s->srtp_profile->id)
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_stoc_etm_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* No encrypt-then-MAC */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_stoc_ems_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* No extended_master_secret */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_stoc_supported_versions_ntls(SSL *s, WPACKET *pkt,
                                                 unsigned int context, X509 *x,
                                                 size_t chainidx)
{
    /* No supported_versions */
    return EXT_RETURN_NOT_SENT;
}
