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
#include "internal/cryptlib.h"
#include "ntls_statem_local.h"

EXT_RETURN tls_construct_ctos_server_name_ntls(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx)
{
    if (s->ext.hostname == NULL)
        return EXT_RETURN_NOT_SENT;

    /* Add TLS extension servername to the Client Hello message */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_server_name)
               /* Sub-packet for server_name extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for servername list (always 1 hostname)*/
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_NAMETYPE_host_name)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.hostname,
                                       strlen(s->ext.hostname))
            || !WPACKET_close(pkt)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

/* Push a Max Fragment Len extension into ClientHello */
EXT_RETURN tls_construct_ctos_maxfragmentlen_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    if (s->ext.max_fragment_len_mode == TLSEXT_max_fragment_length_DISABLED)
        return EXT_RETURN_NOT_SENT;

    /* Add Max Fragment Length extension if client enabled it. */
    /*-
     * 4 bytes for this extension type and extension length
     * 1 byte for the Max Fragment Length code value.
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_max_fragment_length)
            /* Sub-packet for Max Fragment Length extension (1 byte) */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, s->ext.max_fragment_len_mode)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_ctos_ec_pt_formats_ntls(SSL *s, WPACKET *pkt,
                                            unsigned int context, X509 *x,
                                            size_t chainidx)
{
    /* No ec_point_formats */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_ctos_supported_groups_ntls(SSL *s, WPACKET *pkt,
                                               unsigned int context, X509 *x,
                                               size_t chainidx)
{
    /* No supported_groups */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_ctos_session_ticket_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    size_t ticklen;

    if (!tls_use_ticket(s))
        return EXT_RETURN_NOT_SENT;

    if (!s->new_session && s->session != NULL
            && s->session->ext.tick != NULL
            && s->session->ssl_version != TLS1_3_VERSION) {
        ticklen = s->session->ext.ticklen;
    } else if (s->session && s->ext.session_ticket != NULL
               && s->ext.session_ticket->data != NULL) {
        ticklen = s->ext.session_ticket->length;
        s->session->ext.tick = OPENSSL_malloc(ticklen);
        if (s->session->ext.tick == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        memcpy(s->session->ext.tick,
               s->ext.session_ticket->data, ticklen);
        s->session->ext.ticklen = ticklen;
    } else {
        ticklen = 0;
    }

    if (ticklen == 0 && s->ext.session_ticket != NULL &&
            s->ext.session_ticket->data == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_session_ticket)
            || !WPACKET_sub_memcpy_u16(pkt, s->session->ext.tick, ticklen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

EXT_RETURN tls_construct_ctos_sig_algs_ntls(SSL *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    /* No signature_algorithms */
    return EXT_RETURN_NOT_SENT;
}

#ifndef OPENSSL_NO_OCSP
EXT_RETURN tls_construct_ctos_status_request_ntls(SSL *s, WPACKET *pkt,
                                             unsigned int context, X509 *x,
                                             size_t chainidx)
{
    int i;

    /* This extension isn't defined for client Certificates */
    if (x != NULL)
        return EXT_RETURN_NOT_SENT;

    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_status_request)
               /* Sub-packet for status request extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_put_bytes_u8(pkt, TLSEXT_STATUSTYPE_ocsp)
               /* Sub-packet for the ids */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    for (i = 0; i < sk_OCSP_RESPID_num(s->ext.ocsp.ids); i++) {
        unsigned char *idbytes;
        OCSP_RESPID *id = sk_OCSP_RESPID_value(s->ext.ocsp.ids, i);
        int idlen = i2d_OCSP_RESPID(id, NULL);

        if (idlen <= 0
                   /* Sub-packet for an individual id */
                || !WPACKET_sub_allocate_bytes_u16(pkt, idlen, &idbytes)
                || i2d_OCSP_RESPID(id, &idbytes) != idlen) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt)
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    if (s->ext.ocsp.exts) {
        unsigned char *extbytes;
        int extlen = i2d_X509_EXTENSIONS(s->ext.ocsp.exts, NULL);

        if (extlen < 0) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        if (!WPACKET_allocate_bytes(pkt, extlen, &extbytes)
                || i2d_X509_EXTENSIONS(s->ext.ocsp.exts, &extbytes)
                   != extlen) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
       }
    }
    if (!WPACKET_close(pkt) || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

#ifndef OPENSSL_NO_NEXTPROTONEG
EXT_RETURN tls_construct_ctos_npn_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ctx->ext.npn_select_cb == NULL || !SSL_IS_FIRST_HANDSHAKE(s))
        return EXT_RETURN_NOT_SENT;

    /*
     * The client advertises an empty extension to indicate its support
     * for Next Protocol Negotiation
     */
    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_next_proto_neg)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_alpn_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx)
{
    s->s3.alpn_sent = 0;

    if (s->ext.alpn == NULL || !SSL_IS_FIRST_HANDSHAKE(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt,
                TLSEXT_TYPE_application_layer_protocol_negotiation)
               /* Sub-packet ALPN extension */
            || !WPACKET_start_sub_packet_u16(pkt)
            || !WPACKET_sub_memcpy_u16(pkt, s->ext.alpn, s->ext.alpn_len)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }
    s->s3.alpn_sent = 1;

    return EXT_RETURN_SENT;
}


#ifndef OPENSSL_NO_SRTP
EXT_RETURN tls_construct_ctos_use_srtp_ntls(SSL *s, WPACKET *pkt,
                                       unsigned int context, X509 *x,
                                       size_t chainidx)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt = SSL_get_srtp_profiles(s);
    int i, end;

    if (clnt == NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_use_srtp)
               /* Sub-packet for SRTP extension */
            || !WPACKET_start_sub_packet_u16(pkt)
               /* Sub-packet for the protection profile list */
            || !WPACKET_start_sub_packet_u16(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    end = sk_SRTP_PROTECTION_PROFILE_num(clnt);
    for (i = 0; i < end; i++) {
        const SRTP_PROTECTION_PROFILE *prof =
            sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof == NULL || !WPACKET_put_bytes_u16(pkt, prof->id)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }
    if (!WPACKET_close(pkt)
               /* Add an empty use_mki value */
            || !WPACKET_put_bytes_u8(pkt, 0)
            || !WPACKET_close(pkt)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_etm_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* No encrypt-then-MAC */
    return EXT_RETURN_NOT_SENT;
}

#ifndef OPENSSL_NO_CT
EXT_RETURN tls_construct_ctos_sct_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ct_validation_callback == NULL)
        return EXT_RETURN_NOT_SENT;

    /* Not defined for client Certificates */
    if (x != NULL)
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_signed_certificate_timestamp)
            || !WPACKET_put_bytes_u16(pkt, 0)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}
#endif

EXT_RETURN tls_construct_ctos_ems_ntls(SSL *s, WPACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    /* No extended_master_secret */
    return EXT_RETURN_NOT_SENT;
}

EXT_RETURN tls_construct_ctos_supported_versions_ntls(SSL *s, WPACKET *pkt,
                                                 unsigned int context, X509 *x,
                                                 size_t chainidx)
{
    /* No supported_versions */
    return EXT_RETURN_NOT_SENT;
}

#define F5_WORKAROUND_MIN_MSG_LEN   0xff
#define F5_WORKAROUND_MAX_MSG_LEN   0x200

/*
 * PSK pre binder overhead =
 *  2 bytes for TLSEXT_TYPE_psk
 *  2 bytes for extension length
 *  2 bytes for identities list length
 *  2 bytes for identity length
 *  4 bytes for obfuscated_ticket_age
 *  2 bytes for binder list length
 *  1 byte for binder length
 * The above excludes the number of bytes for the identity itself and the
 * subsequent binder bytes
 */
#define PSK_PRE_BINDER_OVERHEAD (2 + 2 + 2 + 2 + 4 + 2 + 1)

EXT_RETURN tls_construct_ctos_padding_ntls(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx)
{
    unsigned char *padbytes;
    size_t hlen;

    if ((s->options & SSL_OP_TLSEXT_PADDING) == 0)
        return EXT_RETURN_NOT_SENT;

    /*
     * Add padding to workaround bugs in F5 terminators. See RFC7685.
     * This code calculates the length of all extensions added so far but
     * excludes the PSK extension (because that MUST be written last). Therefore
     * this extension MUST always appear second to last.
     */
    if (!WPACKET_get_total_written(pkt, &hlen)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    /*
     * If we're going to send a PSK then that will be written out after this
     * extension, so we need to calculate how long it is going to be.
     */
    if (s->session->ssl_version == TLS1_3_VERSION
            && s->session->ext.ticklen != 0
            && s->session->cipher != NULL) {
        const EVP_MD *md = ssl_md(s->ctx, s->session->cipher->algorithm2);

        if (md != NULL) {
            /*
             * Add the fixed PSK overhead, the identity length and the binder
             * length.
             */
            hlen +=  PSK_PRE_BINDER_OVERHEAD + s->session->ext.ticklen
                     + EVP_MD_get_size(md);
        }
    }

    if (hlen > F5_WORKAROUND_MIN_MSG_LEN && hlen < F5_WORKAROUND_MAX_MSG_LEN) {
        /* Calculate the amount of padding we need to add */
        hlen = F5_WORKAROUND_MAX_MSG_LEN - hlen;

        /*
         * Take off the size of extension header itself (2 bytes for type and
         * 2 bytes for length bytes), but ensure that the extension is at least
         * 1 byte long so as not to have an empty extension last (WebSphere 7.x,
         * 8.x are intolerant of that condition)
         */
        if (hlen > 4)
            hlen -= 4;
        else
            hlen = 1;

        if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_padding)
                || !WPACKET_sub_allocate_bytes_u16(pkt, hlen, &padbytes)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
        memset(padbytes, 0, hlen);
    }

    return EXT_RETURN_SENT;
}

/* Parse the server's max fragment len extension packet */
int tls_parse_stoc_maxfragmentlen_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    unsigned int value;

    if (PACKET_remaining(pkt) != 1 || !PACKET_get_1(pkt, &value)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* |value| should contains a valid max-fragment-length code. */
    if (!IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value)) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
		              SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /* Must be the same value as client-configured one who was sent to server */
    /*-
     * RFC 6066: if a client receives a maximum fragment length negotiation
     * response that differs from the length it requested, ...
     * It must abort with SSL_AD_ILLEGAL_PARAMETER alert
     */
    if (value != s->ext.max_fragment_len_mode) {
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER,
                 SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        return 0;
    }

    /*
     * Maximum Fragment Length Negotiation succeeded.
     * The negotiated Maximum Fragment Length is binding now.
     */
    s->session->ext.max_fragment_len_mode = value;

    return 1;
}

int tls_parse_stoc_server_name_ntls(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx)
{
    if (s->ext.hostname == NULL) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!s->hit) {
        if (s->session->ext.hostname != NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.hostname = OPENSSL_strdup(s->ext.hostname);
        if (s->session->ext.hostname == NULL) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

int tls_parse_stoc_ec_pt_formats_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx)
{
    /* Ignore ec_point_formats */
    return 1;
}

int tls_parse_stoc_session_ticket_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (s->ext.session_ticket_cb != NULL &&
        !s->ext.session_ticket_cb(s, PACKET_data(pkt),
                              PACKET_remaining(pkt),
                              s->ext.session_ticket_cb_arg)) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tls_use_ticket(s)) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION);
        return 0;
    }
    if (PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    s->ext.ticket_expected = 1;

    return 1;
}

#ifndef OPENSSL_NO_OCSP
int tls_parse_stoc_status_request_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx)
{
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        /* We ignore this if the server sends a CertificateRequest */
        return 1;
    }

    /*
     * MUST only be sent if we've requested a status
     * request message. In TLS <= 1.2 it must also be empty.
     */
    if (s->ext.status_type != TLSEXT_STATUSTYPE_ocsp) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION);
        return 0;
    }
    if (PACKET_remaining(pkt) > 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* Set flag to expect CertificateStatus message */
    s->ext.status_expected = 1;

    return 1;
}
#endif


#ifndef OPENSSL_NO_CT
int tls_parse_stoc_sct_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
        /* We ignore this if the server sends it in a CertificateRequest */
        return 1;
    }

    /*
     * Only take it if we asked for it - i.e if there is no CT validation
     * callback set, then a custom extension MAY be processing it, so we
     * need to let control continue to flow to that.
     */
    if (s->ct_validation_callback != NULL) {
        size_t size = PACKET_remaining(pkt);

        /* Simply copy it off for later processing */
        OPENSSL_free(s->ext.scts);
        s->ext.scts = NULL;

        s->ext.scts_len = (uint16_t)size;
        if (size > 0) {
            s->ext.scts = OPENSSL_malloc(size);
            if (s->ext.scts == NULL) {
			    s->ext.scts_len = 0;
				SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_MALLOC_FAILURE);
                return 0;
			}
            if (!PACKET_copy_bytes(pkt, s->ext.scts, size)) {
                SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    } else {
        ENDPOINT role = (context & SSL_EXT_TLS1_2_SERVER_HELLO) != 0
                        ? ENDPOINT_CLIENT : ENDPOINT_BOTH;

        /*
         * If we didn't ask for it then there must be a custom extension,
         * otherwise this is unsolicited.
         */
        if (custom_ext_find_ntls(&s->cert->custext, role,
                            TLSEXT_TYPE_signed_certificate_timestamp,
                            NULL) == NULL) {
            SSLfatal_ntls(s, TLS1_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (!custom_ext_parse_ntls(s, context,
                             TLSEXT_TYPE_signed_certificate_timestamp,
                             PACKET_data(pkt), PACKET_remaining(pkt),
                             x, chainidx)) {
            /* SSLfatal_ntls already called */
            return 0;
        }
    }

    return 1;
}
#endif


#ifndef OPENSSL_NO_NEXTPROTONEG
/*
 * ssl_next_proto_validate validates a Next Protocol Negotiation block. No
 * elements of zero length are allowed and the set of elements must exactly
 * fill the length of the block. Returns 1 on success or 0 on failure.
 */
static int ssl_next_proto_validate(SSL *s, PACKET *pkt)
{
    PACKET tmp_protocol;

    while (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_1(pkt, &tmp_protocol)
            || PACKET_remaining(&tmp_protocol) == 0) {
            SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
            return 0;
        }
    }

    return 1;
}

int tls_parse_stoc_npn_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    unsigned char *selected;
    unsigned char selected_len;
    PACKET tmppkt;

    /* Check if we are in a renegotiation. If so ignore this extension */
    if (!SSL_IS_FIRST_HANDSHAKE(s))
        return 1;

    /* We must have requested it. */
    if (s->ctx->ext.npn_select_cb == NULL) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* The data must be valid */
    tmppkt = *pkt;
    if (!ssl_next_proto_validate(s, &tmppkt)) {
        /* SSLfatal_ntls() already called */
        return 0;
    }
    if (s->ctx->ext.npn_select_cb(s, &selected, &selected_len,
                                  PACKET_data(pkt),
                                  PACKET_remaining(pkt),
                                  s->ctx->ext.npn_select_cb_arg) !=
                                  SSL_TLSEXT_ERR_OK
            || selected_len == 0) {
        SSLfatal_ntls(s, SSL_AD_HANDSHAKE_FAILURE, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * Could be non-NULL if server has sent multiple NPN extensions in
     * a single Serverhello
     */
    OPENSSL_free(s->ext.npn);
    s->ext.npn = OPENSSL_malloc(selected_len);
    if (s->ext.npn == NULL) {
        s->ext.npn_len = 0;
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(s->ext.npn, selected, selected_len);
    s->ext.npn_len = selected_len;
    s->s3.npn_seen = 1;

    return 1;
}
#endif

int tls_parse_stoc_alpn_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx)
{
    size_t len;
    PACKET confpkt, protpkt;
    int valid = 0;

    /* We must have requested it. */
    if (!s->s3.alpn_sent) {
        SSLfatal_ntls(s, SSL_AD_UNSUPPORTED_EXTENSION, SSL_R_BAD_EXTENSION);
        return 0;
    }
    /*-
     * The extension data consists of:
     *   uint16 list_length
     *   uint8 proto_length;
     *   uint8 proto[proto_length];
     */
    if (!PACKET_get_net_2_len(pkt, &len)
        || PACKET_remaining(pkt) != len || !PACKET_get_1_len(pkt, &len)
        || PACKET_remaining(pkt) != len) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* It must be a protocol that we sent */
    if (!PACKET_buf_init(&confpkt, s->ext.alpn, s->ext.alpn_len)) {
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    while (PACKET_get_length_prefixed_1(&confpkt, &protpkt)) {
        if (PACKET_remaining(&protpkt) != len)
            continue;
        if (memcmp(PACKET_data(pkt), PACKET_data(&protpkt), len) == 0) {
            /* Valid protocol found */
            valid = 1;
            break;
        }
    }

    if (!valid) {
        /* The protocol sent from the server does not match one we advertised */
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }

    OPENSSL_free(s->s3.alpn_selected);
    s->s3.alpn_selected = OPENSSL_malloc(len);
    if (s->s3.alpn_selected == NULL) {
        s->s3.alpn_selected_len = 0;
        SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!PACKET_copy_bytes(pkt, s->s3.alpn_selected, len)) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_BAD_EXTENSION);
        return 0;
    }
    s->s3.alpn_selected_len = len;

    if (s->session->ext.alpn_selected == NULL
            || s->session->ext.alpn_selected_len != len
            || memcmp(s->session->ext.alpn_selected, s->s3.alpn_selected, len)
               != 0) {
        /* ALPN not consistent with the old session so cannot use early_data */
        s->ext.early_data_ok = 0;
    }
    if (!s->hit) {
        /*
         * This is a new session and so alpn_selected should have been
         * initialised to NULL. We should update it with the selected ALPN.
         */
        if (!ossl_assert(s->session->ext.alpn_selected == NULL)) {
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.alpn_selected =
            OPENSSL_memdup(s->s3.alpn_selected, s->s3.alpn_selected_len);
        if (s->session->ext.alpn_selected == NULL) {
            s->session->ext.alpn_selected_len = 0;
            SSLfatal_ntls(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->session->ext.alpn_selected_len = s->s3.alpn_selected_len;
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
int tls_parse_stoc_use_srtp_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx)
{
    unsigned int id, ct, mki;
    int i;
    STACK_OF(SRTP_PROTECTION_PROFILE) *clnt;
    SRTP_PROTECTION_PROFILE *prof;

    if (!PACKET_get_net_2(pkt, &ct) || ct != 2
            || !PACKET_get_net_2(pkt, &id)
            || !PACKET_get_1(pkt, &mki)
            || PACKET_remaining(pkt) != 0) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
		              SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
        return 0;
    }

    if (mki != 0) {
        /* Must be no MKI, since we never offer one */
        SSLfatal_ntls(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_SRTP_MKI_VALUE);
        return 0;
    }

    /* Throw an error if the server gave us an unsolicited extension */
    clnt = SSL_get_srtp_profiles(s);
    if (clnt == NULL) {
        SSLfatal_ntls(s, SSL_AD_DECODE_ERROR, SSL_R_NO_SRTP_PROFILES);
        return 0;
    }

    /*
     * Check to see if the server gave us something we support (and
     * presumably offered)
     */
    for (i = 0; i < sk_SRTP_PROTECTION_PROFILE_num(clnt); i++) {
        prof = sk_SRTP_PROTECTION_PROFILE_value(clnt, i);

        if (prof->id == id) {
            s->srtp_profile = prof;
            return 1;
        }
    }

    SSLfatal_ntls(s, SSL_AD_DECODE_ERROR,
                  SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
    return 0;
}
#endif

int tls_parse_stoc_etm_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore encrypt-then-MAC */
    return 1;
}

int tls_parse_stoc_ems_ntls(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx)
{
    /* Ignore extended_master_secret */
    return 1;
}

int tls_parse_stoc_supported_versions_ntls(SSL *s, PACKET *pkt, unsigned int context,
                                      X509 *x, size_t chainidx)
{
    /* Ignore supported_versions */
    return 1;
}
