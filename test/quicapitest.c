/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * We need access to the deprecated low level HMAC APIs for legacy purposes
 * when the deprecated calls are not hidden
 */
#ifndef OPENSSL_NO_DEPRECATED_3_0
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>
#include <openssl/txt_db.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/param_build.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/nelem.h"
#include "internal/ktls.h"
#include "../ssl/ssl_local.h"
#include "filterprov.h"

#undef OSSL_NO_USABLE_TLS1_3
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
# define OSSL_NO_USABLE_TLS1_3
#endif

static char *cert = NULL;
static char *privkey = NULL;

#if !defined(OPENSSL_NO_QUIC) && !defined(OSSL_NO_USABLE_TLS1_3)

static SSL_SESSION *clientpsk = NULL;
static SSL_SESSION *serverpsk = NULL;
static const char *pskid = "Identity";
static const char *srvid;

static char *certsdir = NULL;
static uint8_t default_quic_early_data_ctx[2] = {1, 2};

static int use_session_cb_cnt = 0;
static int find_session_cb_cnt = 0;

static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
                          size_t *idlen, SSL_SESSION **sess);
static int find_session_cb(SSL *ssl, const unsigned char *identity,
                           size_t identity_len, SSL_SESSION **sess);

static SSL_SESSION *create_a_psk(SSL *ssl);

static int use_session_cb(SSL *ssl, const EVP_MD *md, const unsigned char **id,
                          size_t *idlen, SSL_SESSION **sess)
{
    switch (++use_session_cb_cnt) {
    case 1:
        /* The first call should always have a NULL md */
        if (md != NULL)
            return 0;
        break;

    case 2:
        /* The second call should always have an md */
        if (md == NULL)
            return 0;
        break;

    default:
        /* We should only be called a maximum of twice */
        return 0;
    }

    if (clientpsk != NULL)
        SSL_SESSION_up_ref(clientpsk);

    *sess = clientpsk;
    *id = (const unsigned char *)pskid;
    *idlen = strlen(pskid);

    return 1;
}

static int find_session_cb(SSL *ssl, const unsigned char *identity,
                           size_t identity_len, SSL_SESSION **sess)
{
    find_session_cb_cnt++;

    /* We should only ever be called a maximum of twice per connection */
    if (find_session_cb_cnt > 2)
        return 0;

    if (serverpsk == NULL)
        return 0;

    /* Identity should match that set by the client */
    if (strlen(srvid) != identity_len
            || strncmp(srvid, (const char *)identity, identity_len) != 0) {
        /* No PSK found, continue but without a PSK */
        *sess = NULL;
        return 1;
    }

    SSL_SESSION_up_ref(serverpsk);
    *sess = serverpsk;

    return 1;
}

# define TLS13_AES_256_GCM_SHA384_BYTES  ((const unsigned char *)"\x13\x02")

static SSL_SESSION *create_a_psk(SSL *ssl)
{
    const SSL_CIPHER *cipher = NULL;
    const unsigned char key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f
    };
    SSL_SESSION *sess = NULL;

    cipher = SSL_CIPHER_find(ssl, TLS13_AES_256_GCM_SHA384_BYTES);
    sess = SSL_SESSION_new();
    if (!TEST_ptr(sess)
            || !TEST_ptr(cipher)
            || !TEST_true(SSL_SESSION_set1_master_key(sess, key,
                                                      sizeof(key)))
            || !TEST_true(SSL_SESSION_set_cipher(sess, cipher))
            || !TEST_true(
                    SSL_SESSION_set_protocol_version(sess,
                                                     TLS1_3_VERSION))) {
        SSL_SESSION_free(sess);
        return NULL;
    }
    return sess;
}

static int test_quic_set_read_secret(SSL *ssl,
                                     OSSL_ENCRYPTION_LEVEL level,
                                     const SSL_CIPHER *cipher,
                                     const uint8_t *secret,
                                     size_t secret_len)
{
    test_printf_stderr("test_quic_set_read_secret() %s, lvl=%d, len=%zd\n",
                       ssl->server ? "server" : "client", level, secret_len);
    return 1;
}

static int test_quic_set_write_secret(SSL *ssl,
                                      OSSL_ENCRYPTION_LEVEL level,
                                      const SSL_CIPHER *cipher,
                                      const uint8_t *secret,
                                      size_t secret_len)
{
    test_printf_stderr("test_quic_set_write_secret() %s, lvl=%d, len=%zd\n",
                       ssl->server ? "server" : "client", level, secret_len);
    return 1;
}

static int test_quic_add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                        const uint8_t *data, size_t len)
{
    SSL *peer = (SSL*)SSL_get_app_data(ssl);

    TEST_info("quic_add_handshake_data() %s, lvl=%d, *data=0x%02X, len=%zd\n",
              ssl->server ? "server" : "client", level, (int)*data, len);
    if (!TEST_ptr(peer))
        return 0;

    /* We're called with what is locally written; this gives it to the peer */
    if (!TEST_true(SSL_provide_quic_data(peer, level, data, len))) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    return 1;
}
static int test_quic_flush_flight(SSL *ssl)
{
    test_printf_stderr("quic_flush_flight() %s\n", ssl->server ? "server" : "client");
    return 1;
}
static int test_quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
    test_printf_stderr("quic_send_alert() %s, lvl=%d, alert=%d\n",
                       ssl->server ? "server" : "client", level, alert);
    return 1;
}

static SSL_QUIC_METHOD quic_method = {
        test_quic_set_read_secret,
        test_quic_set_write_secret,
        test_quic_add_handshake_data,
        test_quic_flush_flight,
        test_quic_send_alert,
};

static int test_quic_api_set_versions(SSL *ssl, int ver)
{
    SSL_set_quic_transport_version(ssl, ver);
    return 1;
}

static int test_quic_api_version(int clnt, int srvr)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    static const char *server_str = "SERVER";
    static const char *client_str = "CLIENT";
    const uint8_t *peer_str;
    size_t peer_str_len;

    TEST_info("original clnt=0x%X, srvr=0x%X\n", clnt, srvr);

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_quic_method(sctx, &quic_method))
        || !TEST_true(SSL_CTX_set_quic_method(cctx, &quic_method))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                         &clientssl, NULL, NULL))
        || !TEST_true(SSL_set_quic_transport_params(serverssl,
                                                    (unsigned char*)server_str,
                                                    strlen(server_str)+1))
        || !TEST_true(SSL_set_quic_transport_params(clientssl,
                                                    (unsigned char*)client_str,
                                                    strlen(client_str)+1))
        || !TEST_true(SSL_set_app_data(serverssl, clientssl))
        || !TEST_true(SSL_set_app_data(clientssl, serverssl))
        || !TEST_true(test_quic_api_set_versions(clientssl, clnt))
        || !TEST_true(test_quic_api_set_versions(serverssl, srvr))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE))
        || !TEST_true(SSL_version(serverssl) == TLS1_3_VERSION)
        || !TEST_true(SSL_version(clientssl) == TLS1_3_VERSION)
        || !(TEST_int_eq(SSL_quic_read_level(clientssl), ssl_encryption_application))
        || !(TEST_int_eq(SSL_quic_read_level(serverssl), ssl_encryption_application))
        || !(TEST_int_eq(SSL_quic_write_level(clientssl), ssl_encryption_application))
        || !(TEST_int_eq(SSL_quic_write_level(serverssl), ssl_encryption_application)))
        goto end;

    SSL_get_peer_quic_transport_params(serverssl, &peer_str, &peer_str_len);
    if (!TEST_mem_eq(peer_str, peer_str_len, client_str, strlen(client_str)+1))
        goto end;
    SSL_get_peer_quic_transport_params(clientssl, &peer_str, &peer_str_len);
    if (!TEST_mem_eq(peer_str, peer_str_len, server_str, strlen(server_str)+1))
        goto end;

    /* Deal with two NewSessionTickets */
    if (!TEST_true(SSL_process_quic_post_handshake(clientssl)))
        goto end;

    /* Dummy handshake call should succeed */
    if (!TEST_true(SSL_do_handshake(clientssl)))
        goto end;
    /* Test that we (correctly) fail to send KeyUpdate */
    if (!TEST_true(SSL_key_update(clientssl, SSL_KEY_UPDATE_NOT_REQUESTED))
        || !TEST_int_le(SSL_do_handshake(clientssl), 0))
        goto end;
    if (!TEST_true(SSL_key_update(serverssl, SSL_KEY_UPDATE_NOT_REQUESTED))
        || !TEST_int_le(SSL_do_handshake(serverssl), 0))
        goto end;

    TEST_info("original clnt=0x%X, srvr=0x%X\n", clnt, srvr);
    if (srvr == 0 && clnt == 0)
        srvr = clnt = TLSEXT_TYPE_quic_transport_parameters;
    else if (srvr == 0)
        srvr = clnt;
    else if (clnt == 0)
        clnt = srvr;
    TEST_info("expected clnt=0x%X, srvr=0x%X\n", clnt, srvr);
    if (!TEST_int_eq(SSL_get_peer_quic_transport_version(serverssl), clnt))
        goto end;
    if (!TEST_int_eq(SSL_get_peer_quic_transport_version(clientssl), srvr))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_quic_api(int tst)
{
    SSL_CTX *sctx = NULL;
    SSL *serverssl = NULL;
    int testresult = 0;
    static int clnt_params[] = { 0,
                                 TLSEXT_TYPE_quic_transport_parameters_draft,
                                 TLSEXT_TYPE_quic_transport_parameters,
                                 0,
                                 TLSEXT_TYPE_quic_transport_parameters_draft,
                                 TLSEXT_TYPE_quic_transport_parameters,
                                 0,
                                 TLSEXT_TYPE_quic_transport_parameters_draft,
                                 TLSEXT_TYPE_quic_transport_parameters };
    static int srvr_params[] = { 0,
                                 0,
                                 0,
                                 TLSEXT_TYPE_quic_transport_parameters_draft,
                                 TLSEXT_TYPE_quic_transport_parameters_draft,
                                 TLSEXT_TYPE_quic_transport_parameters_draft,
                                 TLSEXT_TYPE_quic_transport_parameters,
                                 TLSEXT_TYPE_quic_transport_parameters,
                                 TLSEXT_TYPE_quic_transport_parameters };
    static int results[] = { 1, 1, 1, 1, 1, 0, 1, 0, 1 };

    /* Failure cases:
     * test 6/[5] clnt = parameters, srvr = draft
     * test 8/[7] clnt = draft, srvr = parameters
     */

    if (!TEST_ptr(sctx = SSL_CTX_new(TLS_server_method()))
        || !TEST_true(SSL_CTX_set_quic_method(sctx, &quic_method))
        || !TEST_ptr(sctx->quic_method)
        || !TEST_ptr(serverssl = SSL_new(sctx))
        || !TEST_true(SSL_IS_QUIC(serverssl))
        || !TEST_true(SSL_set_quic_method(serverssl, NULL))
        || !TEST_false(SSL_IS_QUIC(serverssl))
        || !TEST_true(SSL_set_quic_method(serverssl, &quic_method))
        || !TEST_true(SSL_IS_QUIC(serverssl)))
        goto end;

    if (!TEST_int_eq(test_quic_api_version(clnt_params[tst], srvr_params[tst]), results[tst]))
        goto end;

    testresult = 1;

end:
    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_free(serverssl);
    serverssl = NULL;
    return testresult;
}

/*
 * Helper method to setup objects for QUIC early data test. Caller
 * frees objects on error.
 */
static int quic_setupearly_data_test(SSL_CTX **cctx, SSL_CTX **sctx,
                                     SSL **clientssl, SSL **serverssl,
                                     SSL_SESSION **sess, int idx)
{
    static const char *server_str = "SERVER";
    static const char *client_str = "CLIENT";

    if (*sctx == NULL
        && (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                           TLS_client_method(),
                                           TLS1_3_VERSION, 0,
                                           sctx, cctx, cert, privkey))
            || !TEST_true(SSL_CTX_set_quic_method(*sctx, &quic_method))
            || !TEST_true(SSL_CTX_set_quic_method(*cctx, &quic_method))
            || !TEST_true(SSL_CTX_set_max_early_data(*sctx, 0xffffffffu))))
        return 0;

    if (idx == 1) {
        /* When idx == 1 we repeat the tests with read_ahead set */
        SSL_CTX_set_read_ahead(*cctx, 1);
        SSL_CTX_set_read_ahead(*sctx, 1);
    } else if (idx == 2) {
        /* When idx == 2 we are doing early_data with a PSK. Set up callbacks */
        SSL_CTX_set_psk_use_session_callback(*cctx, use_session_cb);
        SSL_CTX_set_psk_find_session_callback(*sctx, find_session_cb);
        use_session_cb_cnt = 0;
        find_session_cb_cnt = 0;
        srvid = pskid;
    }

    if (!TEST_true(create_ssl_objects(*sctx, *cctx, serverssl, clientssl,
                                      NULL, NULL))
        || !TEST_true(SSL_set_quic_transport_params(*serverssl,
                                                    (unsigned char*)server_str,
                                                    strlen(server_str)+1))
        || !TEST_true(SSL_set_quic_transport_params(*clientssl,
                                                    (unsigned char*)client_str,
                                                    strlen(client_str)+1))
        || !TEST_true(SSL_set_quic_early_data_context(*serverssl,
                                                      default_quic_early_data_ctx,
                                                      sizeof(default_quic_early_data_ctx)))
        || !TEST_true(SSL_set_app_data(*serverssl, *clientssl))
        || !TEST_true(SSL_set_app_data(*clientssl, *serverssl)))
        return 0;

    /*
     * For one of the run throughs (doesn't matter which one), we'll try sending
     * some SNI data in the initial ClientHello. This will be ignored (because
     * there is no SNI cb set up by the server), so it should not impact
     * early_data.
     */
    if (idx == 1
        && !TEST_true(SSL_set_tlsext_host_name(*clientssl, "localhost")))
        return 0;

    if (idx == 2) {
        clientpsk = create_a_psk(*clientssl);
        if (!TEST_ptr(clientpsk)
            || !TEST_true(SSL_SESSION_set_max_early_data(clientpsk,
                                                         0xffffffffu))
            || !TEST_true(SSL_SESSION_up_ref(clientpsk))) {
            SSL_SESSION_free(clientpsk);
            clientpsk = NULL;
            return 0;
        }

        if ((*serverssl)->quic_early_data_context) {
            clientpsk->quic_early_data_context =
                    OPENSSL_memdup((*serverssl)->quic_early_data_context,
                                   (*serverssl)->quic_early_data_context_len);
            if (!TEST_ptr(clientpsk->quic_early_data_context)) {
                SSL_SESSION_free(clientpsk);
                clientpsk = NULL;
                return 0;
            }

            clientpsk->quic_early_data_context_len =
                    (*serverssl)->quic_early_data_context_len;
        }

        serverpsk = clientpsk;

        if (sess != NULL) {
            if (!TEST_true(SSL_SESSION_up_ref(clientpsk))) {
                SSL_SESSION_free(clientpsk);
                SSL_SESSION_free(serverpsk);
                clientpsk = serverpsk = NULL;
                return 0;
            }
            *sess = clientpsk;
        }

        SSL_set_quic_early_data_enabled(*serverssl, 1);
        SSL_set_quic_early_data_enabled(*clientssl, 1);

        return 1;
    }

    if (sess == NULL)
        return 1;

    if (!TEST_true(create_ssl_connection(*serverssl, *clientssl,
                                         SSL_ERROR_NONE)))
        return 0;

    /* Deal with two NewSessionTickets */
    if (!TEST_true(SSL_process_quic_post_handshake(*clientssl)))
        return 0;

    *sess = SSL_get1_session(*clientssl);
    SSL_shutdown(*clientssl);
    SSL_shutdown(*serverssl);
    SSL_free(*serverssl);
    SSL_free(*clientssl);
    *serverssl = *clientssl = NULL;

    if (!TEST_true(create_ssl_objects(*sctx, *cctx, serverssl,
                                      clientssl, NULL, NULL))
        || !TEST_true(SSL_set_session(*clientssl, *sess))
        || !TEST_true(SSL_set_quic_transport_params(*serverssl,
                                                    (unsigned char*)server_str,
                                                    strlen(server_str)+1))
        || !TEST_true(SSL_set_quic_transport_params(*clientssl,
                                                    (unsigned char*)client_str,
                                                    strlen(client_str)+1))
        || !TEST_true(SSL_set_app_data(*serverssl, *clientssl))
        || !TEST_true(SSL_set_app_data(*clientssl, *serverssl)))
        return 0;

    SSL_set_quic_early_data_enabled(*serverssl, 1);
    SSL_set_quic_early_data_enabled(*clientssl, 1);

    return 1;
}

/*
 * TEST 0: quic early data
 * TEST 1: quic early data with read_ahead set
 * TEST 2: quic early data, client use session cb, server find session cb
 * TEST 3: quic early data context not compatible, reject early data
 */
static int test_quic_early_data(int tst)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    SSL_SESSION *sess = NULL;
    uint8_t quic_early_data_ctx[2] = {8, 8};

    if (!TEST_true(quic_setupearly_data_test(&cctx, &sctx, &clientssl,
                                             &serverssl, &sess, tst)))
        goto end;

    if (tst < 3) {
        if (!TEST_true(SSL_set_quic_early_data_context(serverssl,
                                                      default_quic_early_data_ctx,
                                                      sizeof(default_quic_early_data_ctx))))
            goto end;
    } else {
        if (!TEST_true(SSL_set_quic_early_data_context(serverssl,
                                                       quic_early_data_ctx,
                                                       sizeof(quic_early_data_ctx))))
            goto end;
    }

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (tst < 3) {
        if (!TEST_int_eq(SSL_get_early_data_status(serverssl),
                     SSL_EARLY_DATA_ACCEPTED))
            goto end;
    } else {
        if (!TEST_int_eq(SSL_get_early_data_status(serverssl),
                         SSL_EARLY_DATA_REJECTED))
            goto end;
    }

    testresult = 1;

end:
    SSL_SESSION_free(sess);
    SSL_SESSION_free(clientpsk);
    SSL_SESSION_free(serverpsk);
    clientpsk = serverpsk = NULL;
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

#if !defined(OPENSSL_NO_QUIC) && !defined(OSSL_NO_USABLE_TLS1_3)
    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        return 0;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL) {
        OPENSSL_free(cert);
        return 0;
    }

    ADD_ALL_TESTS(test_quic_api, 9);
    ADD_ALL_TESTS(test_quic_early_data, 4);
#endif

    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    bio_s_mempacket_test_free();
    bio_s_always_retry_free();
}
