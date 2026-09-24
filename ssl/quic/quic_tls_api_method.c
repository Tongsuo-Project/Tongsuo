/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include "internal/ssl_unwrap.h"
#include "internal/quic_tls.h"
#include "../ssl_local.h"

static int quic_api_method_crypto_send_cb(SSL *s, const unsigned char *buf, size_t buf_len,
                                          size_t *consumed, void *arg)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    SSL_QUIC_API_INFO *quic_api_info;

    if (sc == NULL || arg == NULL || sc->quic_api_method == NULL)
        return 0;
    if (sc->quic_api_method->add_handshake_data == NULL)
        return 0;

    quic_api_info = (SSL_QUIC_API_INFO *)arg;

    if (sc->quic_api_method->add_handshake_data(s, quic_api_info->quic_write_level, buf, buf_len) == 1) {
        *consumed = buf_len;
        return 1;
    } else
        return 0;
}

/* This function should deal with different encryption_level */
static int quic_api_method_crypto_recv_rcd_cb(SSL *s, const unsigned char **buf,
                                              size_t *bytes_read, void *arg)
{
    int quic_read_level;
    size_t rcd_start_index, rcd_end_index;

    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL || arg == NULL || sc->quic_api_method == NULL)
        return 0;
    
    api_info = (SSL_QUIC_API_INFO *)arg;

    quic_read_level = (int)api_info->quic_read_level;
    rcd_start_index = api_info->level_start_index[quic_read_level];
    rcd_end_index = api_info->level_end_index[quic_read_level];

    /* 
     * quic_next_record_start != 0 means at least one complete handshake
     * message has been parsed and is available to read. 
     */
    if (api_info->quic_next_record_start != 0 && api_info->quic_buf != NULL) {
        *buf = (unsigned char *)(api_info->quic_buf->data + rcd_start_index);
        *bytes_read = (rcd_end_index - rcd_start_index);
        api_info->level_start_index[quic_read_level] = rcd_end_index;
    } else {
        *bytes_read = 0;
    }

    return 1;
}

static int quic_api_method_crypto_release_rcd_cb(SSL *s, size_t bytes_read, void *arg)
{
    int i;

    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL || arg == NULL || sc->quic_api_method == NULL)
        return 0;

    api_info = (SSL_QUIC_API_INFO *)arg;

    /* We should never release more data than we have buffered */
    if ((api_info->quic_buf == NULL && bytes_read > 0)
        || api_info->quic_buf->length < api_info->quic_buf_released + bytes_read) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    api_info->quic_buf_released += bytes_read;

     /* All data has been released, we can free the buffer */
    if (api_info->quic_buf->length == api_info->quic_buf_released) {
        BUF_MEM_free(api_info->quic_buf);
        api_info->quic_buf = NULL;
        api_info->quic_buf_released = 0;
        api_info->quic_next_record_start = 0;
        for (i = 0; i < OSSL_ENCRYPTION_LEVEL_NUM; ++i) {
            api_info->level_start_index[i] = 0;
            api_info->level_end_index[i] = 0;
        }
    }
   
    return 1;
}

static int quic_api_method_crypto_yield_secret_cb(SSL *s, uint32_t prot_level, int direction,
                                                  const unsigned char *secret, size_t secret_len, void *arg)
{
    int ret = 0;

    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL || arg == NULL || sc->quic_api_method == NULL)
        return 0;
    
    api_info = (SSL_QUIC_API_INFO *)arg;

    if (sc->quic_api_method->set_read_secret == NULL
        || sc->quic_api_method->set_write_secret == NULL)
        return 0;

    if (prot_level < OSSL_RECORD_PROTECTION_LEVEL_EARLY
        || prot_level > OSSL_RECORD_PROTECTION_LEVEL_APPLICATION)
        return 0;

    switch (direction) {
    case 0: /* read */
        api_info->quic_read_level = (OSSL_ENCRYPTION_LEVEL)prot_level;
        ret = sc->quic_api_method->set_read_secret(s, api_info->quic_read_level, 
                                                   SSL_get_current_cipher(s), secret, secret_len);
        break;
    case 1: /* write */
        api_info->quic_write_level = (OSSL_ENCRYPTION_LEVEL)prot_level;
        ret = sc->quic_api_method->set_write_secret(s, api_info->quic_write_level, 
                                                   SSL_get_current_cipher(s), secret, secret_len);
        break;
    default:
        return 0;
    }

    return ret;
}

static int quic_api_method_crypto_got_transport_params_cb(SSL *s, const unsigned char *params, 
                                                          size_t params_len, void *arg)
{
    BUF_MEM *buf = NULL;

    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL || arg == NULL || sc->quic_api_method == NULL)
        return 0;
    
    api_info = (SSL_QUIC_API_INFO *)arg;

    if (api_info->quic_transport_params_buf != NULL) {
        BUF_MEM_free(api_info->quic_transport_params_buf);
        api_info->quic_transport_params_buf = NULL;
    }

    if ((buf = BUF_MEM_new()) == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!BUF_MEM_grow(buf, params_len)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        BUF_MEM_free(buf);
        return 0;
    }

    api_info->quic_transport_params_buf = buf;
    buf = NULL;

    memcpy(api_info->quic_transport_params_buf->data, params, params_len);

    return 1;
}

static int quic_api_method_crypto_alert_cb(SSL *s, unsigned char alert_code, void *arg)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL || arg == NULL || sc->quic_api_method == NULL)
        return 0;

    if (sc->quic_api_method->send_alert == NULL)
        return 0;
    
    api_info = (SSL_QUIC_API_INFO *)arg;

    return sc->quic_api_method->send_alert(s, api_info->quic_write_level, alert_code);
}

OSSL_ENCRYPTION_LEVEL SSL_quic_read_level(const SSL *s) 
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);
    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL)
        return 0;

    if (!SSL_IS_QUIC_HANDSHAKE(sc) 
        || sc->quic_api_method == NULL 
        || sc->qtarg == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    api_info = (SSL_QUIC_API_INFO *)sc->qtarg;

    return api_info->quic_read_level;
}

OSSL_ENCRYPTION_LEVEL SSL_quic_write_level(const SSL *s)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);
    SSL_QUIC_API_INFO *api_info;

    if (sc == NULL)
        return 0;

    if (!SSL_IS_QUIC_HANDSHAKE(sc) 
        || sc->quic_api_method == NULL 
        || sc->qtarg == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    api_info = (SSL_QUIC_API_INFO *)sc->qtarg;

    return api_info->quic_write_level;
}

void SSL_set_quic_use_legacy_codepoint(SSL *s, int use_legacy)
{
    /* 
        Empty implementation for the compatibility with XQUIC.
        TODO: Remove this function, since RFC 9000 has been published.
     */
    (void)s;
    (void)use_legacy;
}

int SSL_set_quic_method(SSL *s, const SSL_QUIC_METHOD *quic_api_method)
{
    OSSL_DISPATCH quic_api_method_cbs[] = {
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, 
         (void (*)(void))quic_api_method_crypto_send_cb},
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD,
         (void (*)(void))quic_api_method_crypto_recv_rcd_cb},
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD,
         (void (*)(void))quic_api_method_crypto_release_rcd_cb},
        {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET,
         (void (*)(void))quic_api_method_crypto_yield_secret_cb},
        {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS,
         (void (*)(void))quic_api_method_crypto_got_transport_params_cb},
        {OSSL_FUNC_SSL_QUIC_TLS_ALERT, 
         (void (*)(void))quic_api_method_crypto_alert_cb},
        {0, NULL}
    };

    SSL_QUIC_API_INFO *quic_api_method_info;

    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);

    if (sc == NULL)
        return 0;

    /* This is de-allocated by ossl_ssl_connection_free when sc->quic_api_method != NULL. */
    if ((quic_api_method_info = OPENSSL_zalloc(sizeof(SSL_QUIC_API_INFO))) == NULL )
        return 0;

    if (SSL_set_quic_tls_cbs(s, quic_api_method_cbs, quic_api_method_info) != 1){
        OPENSSL_free(quic_api_method_info);
        return 0;
    }

    sc->quic_api_method = quic_api_method;
    return 1;
}

int SSL_provide_quic_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                          const uint8_t *data, size_t len)
{
    size_t offset, l;
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);
    SSL_QUIC_API_INFO * api_info;

    if (sc == NULL)
        return 0;

    if (!SSL_IS_QUIC_HANDSHAKE(sc) 
        || sc->quic_api_method == NULL 
        || sc->qtarg == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (len == 0)
        return 1;

    api_info = (SSL_QUIC_API_INFO *)sc->qtarg;

    if (level < ssl_encryption_initial || level > ssl_encryption_application) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (level < api_info->quic_read_level || level < api_info->quic_latest_level_received) {
        ERR_raise(ERR_LIB_SSL, SSL_R_QUIC_PROTOCOL_ERROR);
        return 0;
    }
        
    if (api_info->quic_buf == NULL) {
        BUF_MEM *buf;
        if ((buf = BUF_MEM_new()) == NULL) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
            ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
            BUF_MEM_free(buf);
            return 0;
        }
        api_info->quic_buf = buf;
        api_info->quic_buf->length = 0;
        api_info->quic_buf_released = 0;
        api_info->quic_next_record_start = 0;

        api_info->level_start_index[api_info->quic_read_level] = 0;
        api_info->level_end_index[api_info->quic_read_level] = 0;

        buf = NULL;
    }

    /*  A TLS message must not cross an encryption level boundary */
    if (api_info->quic_buf->length != api_info->quic_next_record_start 
       && level != api_info->quic_latest_level_received) {
        ERR_raise(ERR_LIB_SSL, SSL_R_QUIC_PROTOCOL_ERROR);
        return 0;
    }

    offset = api_info->quic_buf->length;
    /* 
     * Update the latest received record's encryption level
     * The current message is a new one.
     */
    if (level > api_info->quic_latest_level_received) {
        api_info->quic_latest_level_received = level;
        api_info->level_start_index[level] = offset;
        api_info->level_end_index[level] = offset;
    }

    if (!BUF_MEM_grow(api_info->quic_buf, offset + len)) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(api_info->quic_buf->data + offset, data, len);

    /* Split on handshake message boundaries */
    while(api_info->quic_buf->length > api_info->quic_next_record_start 
                                       + SSL3_HM_HEADER_LENGTH) {
        const uint8_t *p;

        /* TLS Handshake message header has 1-byte type and 3-byte length. */
        p = (const uint8_t *)api_info->quic_buf->data + api_info->quic_next_record_start + 1; 
        n2l3(p, l);
        l += SSL3_HM_HEADER_LENGTH;

        /* Don't allocate a new quic record if we don't have a full handshake message */
        if (l > (api_info->quic_buf->length - api_info->quic_next_record_start))
            break;
        
        api_info->level_end_index[level] += l;
        api_info->quic_next_record_start += l;
    }

    return 1;
}

int SSL_process_quic_post_handshake(SSL *ssl)
{
    int ret = 0;
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);
    SSL_QUIC_API_INFO * api_info;

    if (sc == NULL || SSL_in_init(ssl))
        return 0;

    if (!SSL_IS_QUIC_HANDSHAKE(sc) 
        || sc->quic_api_method == NULL 
        || sc->qtarg == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    api_info = (SSL_QUIC_API_INFO *)sc->qtarg;

    /* 
     * Another approach: process a single post-handshake message with "if" 
     * rather than while which may raise the problem of infinite loop.
     * However, such modification changes the syntax of original
     * SSL_process_quic_post_handshake which processes multiple messages per call.
     */
    while (api_info->quic_buf != NULL) {
        ossl_statem_set_in_init(sc, 1);
        ret = sc->handshake_func(ssl);
        ossl_statem_set_in_init(sc, 0);

        if (ret <= 0)
            return 0;
    }

    return 1;
}

void SSL_set_quic_early_data_enabled(SSL *ssl, int enabled)
{
    /* Almost the same with ossl_quic_tls_set_early_data_enabled (quic_tls.c) */
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (sc == NULL || !SSL_IS_QUIC_HANDSHAKE(sc) || !SSL_in_before(ssl))
        return;

    if (!enabled) {
        sc->max_early_data = 0;
        sc->early_data_state = SSL_EARLY_DATA_NONE;
        return;
    }

    if (sc->server) {
        sc->max_early_data = 0xffffffff;
        sc->early_data_state = SSL_EARLY_DATA_ACCEPTING;
        return;
    }

    if ((sc->session == NULL || sc->session->ext.max_early_data != 0xffffffff)
        && sc->psk_use_session_cb == NULL){
        return;
    }
    sc->early_data_state = SSL_EARLY_DATA_CONNECTING;
}

int SSL_set_quic_early_data_context(SSL *ssl, const uint8_t *context,
                                    size_t context_len)
{
    uint8_t *tmp;
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (sc == NULL)
        return 0;

    if (context == NULL || context_len == 0) {
        tmp = NULL;
        context_len = 0;
    } else {
        tmp = OPENSSL_memdup(context, context_len);
        if (tmp == NULL)
            return 0;
    }

    OPENSSL_free(sc->quic_early_data_context);
    sc->quic_early_data_context = tmp;
    sc->quic_early_data_context_len = context_len;

    return 1;
}

int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
                                  size_t params_len)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);
    if (sc == NULL || params == NULL || params_len == 0)
        return 0;

    OPENSSL_free(sc->quic_api_method_transport_params);
    sc->quic_api_method_transport_params = OPENSSL_memdup(params, params_len);
    sc->quic_api_method_transport_params_len = params_len;

    return SSL_set_quic_tls_transport_params(ssl, sc->quic_api_method_transport_params,
                                             sc->quic_api_method_transport_params_len);
}

void SSL_get_peer_quic_transport_params(const SSL *ssl, const uint8_t **out_params, 
                                        size_t *out_params_len)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(ssl);

    SSL_QUIC_API_INFO * api_info;

    if (sc == NULL)
        return;

    if (!SSL_IS_QUIC_HANDSHAKE(sc) 
        || sc->quic_api_method == NULL 
        || sc->qtarg == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return;
    }

    api_info = (SSL_QUIC_API_INFO *)sc->qtarg;

    if (api_info->quic_transport_params_buf != NULL) {
        *out_params = (const uint8_t *)api_info->quic_transport_params_buf->data;
        *out_params_len = api_info->quic_transport_params_buf->length;
    } else {
        *out_params = NULL;
        *out_params_len = 0;
    }

    return;
}
