/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>
#include <openssl/txt_db.h>
#include <openssl/aes.h>
#ifdef __linux__
# include <arpa/inet.h>
#endif

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/nelem.h"
#include "../ssl/ssl_local.h"
# ifndef OPENSSL_NO_EC
#  include "crypto/ec/ec_local.h"
# endif

#undef OSSL_NO_USABLE_TLS1_3
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
# define OSSL_NO_USABLE_TLS1_3
#endif

static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;

static int dummy_cert_cb(SSL *s, void *arg)
{
    return 1;
}

static int test_babassl_get_master_key(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int master_key_len;
    unsigned char *master_key = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    if (SSL_get_master_key(serverssl, &master_key, &master_key_len), 0)
        goto end;

    if (!TEST_int_eq(master_key_len, 48))
        goto end;

    if (!TEST_ptr_ne(master_key, NULL))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_debug(void)
{
    int testresult = 0;
    size_t len;
    FILE *fp;
    SSL_CTX *ctx = NULL;
    SSL *s = NULL;

    ctx = SSL_CTX_new(TLS_method());
    if (!TEST_ptr(ctx))
        goto end;

    s = SSL_new(ctx);
    if (!TEST_ptr(s))
        goto end;

    fflush(stdout);
    setvbuf(stdout, NULL, _IONBF, 0);
    fp = freopen("BABASSL_debug.log", "w", stdout);
    BABASSL_debug(s, (unsigned char *)"BABASSL_debug",
                  sizeof("BABASSL_debug") - 1);
    fseek(fp, 0, SEEK_END);

    len = 30;
#ifdef _WIN32
    /* \n -> \r\n on Windows */
    len += 2;
#endif
    if(!TEST_int_eq(ftell(fp), len))
        goto end;
    fclose(fp);
#ifdef OPENSSL_SYS_MSDOS
# define DEV_TTY "con"
#else
# define DEV_TTY "/dev/tty"
#endif
    fp = freopen(DEV_TTY, "w", stdout);
    remove("BABASSL_debug.log");

    testresult = 1;
end:
    SSL_CTX_free(ctx);
    SSL_free(s);
    return testresult;
}

static int test_babassl_cipher_get(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    const SSL_CIPHER *cipher;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    cipher = SSL_get_current_cipher(serverssl);
    if (cipher == NULL)
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_mkey(cipher), cipher->algorithm_mkey))
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_mac(cipher), cipher->algorithm_mac))
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_enc(cipher), cipher->algorithm_enc))
        goto end;

    if (!TEST_long_eq(SSL_CIPHER_get_auth(cipher), cipher->algorithm_auth))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_session_get_ref(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;


    if (!TEST_int_eq(SSL_SESSION_get_ref(SSL_get_session(serverssl)), 1))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_get_use_certificate(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    if (!TEST_ptr_eq(SSL_get_use_certificate(serverssl),
                     SSL_get_certificate(serverssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_get_cert_cb(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_cert_cb(sctx, dummy_cert_cb, (void *)0x99);

    if (SSL_CTX_get_cert_cb(sctx) != dummy_cert_cb
            || !TEST_ptr_eq(SSL_CTX_get_cert_cb_arg(sctx), (void *)0x99))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    if (SSL_get_cert_cb(serverssl) != dummy_cert_cb
            || !TEST_ptr_eq(SSL_get_cert_cb_arg(serverssl), (void *)0x99))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_get0_alpn_proposed(void)
{
    int testresult = 0;
    unsigned int len;
    const unsigned char *data;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_int_eq(SSL_CTX_set_alpn_protos(cctx, (u_char *) "\x02h2", 3),
                        0)
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    SSL_get0_alpn_proposed(serverssl, &data, &len);
    if (!TEST_int_eq(len, 3))
        goto end;

    if (memcmp(data, "\x02h2", len) != 0)
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_get0_wbio(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    if (!TEST_ptr_eq(SSL_get0_wbio(serverssl), serverssl->wbio))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_ctx_certs_clear(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    SSL_CTX_certs_clear(sctx);

    SSL_free(serverssl);
    serverssl = NULL;
    SSL_free(clientssl);
    clientssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_babassl_set_session_ctx(void)
{
    int testresult = 0;
    SSL_CTX *cctx1 = NULL, *cctx2 = NULL, *sctx1 = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx1, &cctx1, cert, privkey))
        || !TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                          TLS_client_method(),
                                          TLS1_VERSION, 0,
                                          &sctx2, &cctx2, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx1, cctx1, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_ptr_eq(serverssl->session_ctx, sctx1)
        || !TEST_ptr(SSL_set_SESSION_CTX(serverssl, sctx2))
        || !TEST_ptr_eq(serverssl->session_ctx, sctx2))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx1);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(cctx1);
    SSL_CTX_free(cctx2);
    return testresult;
}

#ifndef OPENSSL_NO_TLS1_2
static int client_hello_callback(SSL *s, int *al, void *arg) {
    int *exts;
    const int expected_extensions[] = {
# ifndef OPENSSL_NO_EC
        11, 10,
# endif
        35, 22, 23, 13};
    size_t len;

    if (!SSL_client_hello_get1_extensions(s, &exts, &len))
        return SSL_CLIENT_HELLO_ERROR;
    if (len != OSSL_NELEM(expected_extensions) ||
        memcmp(exts, expected_extensions, len * sizeof(*exts)) != 0) {
        OPENSSL_free(exts);
        return SSL_CLIENT_HELLO_ERROR;
    }

    OPENSSL_free(exts);
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int test_babassl_client_hello_get1_extensions(void)
{
    int testresult = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    SSL_CTX_set_client_hello_cb(sctx, client_hello_callback, NULL);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                         NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif

#ifndef OPENSSL_NO_OCSP
static int ocsp_server_called = 0;

static int ocsp_server_cb(SSL *s, void *arg)
{
    if (!TEST_int_eq(SSL_check_tlsext_status(s), TLSEXT_STATUSTYPE_ocsp))
        return SSL_TLSEXT_ERR_ALERT_FATAL;

    ocsp_server_called = 1;

    return SSL_TLSEXT_ERR_OK;
}

static int test_babassl_tlsext_status(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, TLS1_3_VERSION,
                             &sctx, &cctx, cert, privkey))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_int_ne(SSL_check_tlsext_status(serverssl),
                            TLSEXT_STATUSTYPE_ocsp)
            || !TEST_false(ocsp_server_called))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);
    serverssl = NULL;
    clientssl = NULL;

    if (!SSL_CTX_set_tlsext_status_type(cctx, TLSEXT_STATUSTYPE_ocsp))
        goto end;

    SSL_CTX_set_tlsext_status_cb(sctx, ocsp_server_cb);
    SSL_CTX_set_tlsext_status_arg(sctx, NULL);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl,
                                      &clientssl, NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE))
            || !TEST_int_eq(SSL_check_tlsext_status(serverssl),
                            TLSEXT_STATUSTYPE_ocsp)
            || !TEST_true(ocsp_server_called))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_TLS1_2
# ifdef SSL_client_hello_get1_extensions
static int babassl_cb = 0;
# endif

static int babassl_client_hello_callback(SSL *s, int *al, void *arg)
{
    SSL_CTX *sctx2 = arg;

# ifdef SSL_client_hello_get1_extensions
    int *exts = NULL;
    size_t  len, i;
    /* We only configure two ciphers, but the SCSV is added automatically. */
    const int expected_extensions[] = {
#   ifndef OPENSSL_NO_EC
                                       11, 10,
#   endif
                                       35, 16, 22, 23, 13};

    if (!SSL_client_hello_get1_extensions(s, &exts, &len))
        return SSL_CLIENT_HELLO_ERROR;

    babassl_cb++;

    if (babassl_cb == 3 && (!TEST_int_eq(len, OSSL_NELEM(expected_extensions)) ||
        !TEST_int_eq(memcmp(exts, expected_extensions, len * sizeof(*exts)), 0))) {
        printf("ClientHello callback expected extensions mismatch\n");
        printf("exts: ");
        for (i = 0; i < len; i++) {
            printf("%d ", exts[i]);
        }
        printf("\n");
        OPENSSL_free(exts);
        return SSL_CLIENT_HELLO_ERROR;
    }

    OPENSSL_free(exts);
# endif

    SSL_set_SSL_CTX(s, sctx2);

    SSL_set_options(s, SSL_CTX_get_options(sctx2));

    return SSL_CLIENT_HELLO_SUCCESS;
}
#endif

static int test_babassl_set_ssl_ctx(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), NULL,
                                       TLS1_VERSION, 0,
                                       &sctx2, NULL, cert, privkey)))
        goto end;

    SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(sctx2, SSL_OP_NO_SSLv3);

#ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_set_client_hello_cb(sctx, babassl_client_hello_callback, sctx2);
#endif

    /* The gimpy cipher list we configure can't do TLS 1.3. */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    if (!TEST_int_eq(SSL_CTX_set_alpn_protos(cctx, (u_char *) "\x02h2", 3), 0))
        goto end;
#endif

    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(cctx, SSL_OP_NO_SSLv3);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_NONE)))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

#ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_clear_options(cctx, SSL_OP_NO_TLSv1_2);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;
#endif

    fflush(stdout);
    setvbuf(stdout, NULL, _IONBF, 0);

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx2);

    return testresult;
}

#if !defined(OPENSSL_NO_SESSION_LOOKUP) && (!defined(OPENSSL_NO_TLS1_2) \
                                            || !defined(OPENSSL_NO_TLS1_1) \
                                            || !defined(OPENSSL_NO_TLS1))
static int new_called = 0, get_called = 0;

static int new_session_cb(SSL *ssl, SSL_SESSION *sess)
{
    new_called++;
    /*
     * sess has been up-refed for us, but we don't actually need it so free it
     * immediately.
     */
    SSL_SESSION_free(sess);
    return 1;
}

static SSL_SESSION *get_sess_val = NULL;

static SSL_SESSION *get_session_cb(SSL *ssl, const unsigned char *id, int len,
                                   int *copy)
{
    *copy = 0;
    if (get_called++ == 0)
        return SSL_magic_pending_session_ptr();

    return get_sess_val;
}

static int test_babassl_session_lookup(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl1 = NULL, *serverssl1 = NULL;
    SSL *clientssl2 = NULL, *serverssl2 = NULL;
    SSL_SESSION *sess1 = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, TLS1_2_VERSION,
                                       &sctx, &cctx, cert, privkey))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx, "DEFAULT:@SECLEVEL=0"))
            || !TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0")))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(sctx,
                                   SSL_SESS_CACHE_SERVER
                                   | SSL_SESS_CACHE_NO_INTERNAL_STORE);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl1, clientssl1,
                                                SSL_ERROR_NONE))
            || !TEST_ptr(sess1 = SSL_get1_session(clientssl1)))
        goto end;

    get_sess_val = sess1;

    SSL_CTX_sess_set_get_cb(sctx, get_session_cb);
    SSL_CTX_sess_set_new_cb(sctx, new_session_cb);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl2,
                                      &clientssl2, NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl2, sess1))
            || !TEST_false(create_ssl_connection(serverssl2, clientssl2,
                                                 SSL_ERROR_WANT_SESSION_LOOKUP))
            || !TEST_true(create_ssl_connection(serverssl2, clientssl2,
                                                SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl2)))
        goto end;

    if (!TEST_ptr(SSL_magic_pending_session_ptr()))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_DYNAMIC_CIPHERS

# ifndef OPENSSL_NO_TLS1_2
static STACK_OF(SSL_CIPHER)       *cipher_list = NULL;
static STACK_OF(SSL_CIPHER)       *cipher_list_by_id = NULL;
static int dynamic_ciphers_cb_count = 0;

static int babassl_dynamic_ciphers_client_hello_callback(SSL *s, int *al, void *arg)
{
    if (dynamic_ciphers_cb_count == 0) {
        if (!TEST_true(SSL_set_cipher_list(s, "AES128-SHA")))
            return 0;

        cipher_list = SSL_dup_ciphers(s);
        cipher_list_by_id = SSL_dup_ciphers_by_id(s);
    }

    if (cipher_list) {
        SSL_set_ciphers(s, cipher_list);
        SSL_set_ciphers_by_id(s, cipher_list_by_id);
    }

    dynamic_ciphers_cb_count++;

    return 1;
}

static int test_babassl_dynamic_ciphers(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, TLS1_2_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_client_hello_cb(sctx, babassl_dynamic_ciphers_client_hello_callback,
                                sctx);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "AES256-GCM-SHA384")))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x002f))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x002f))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (cipher_list)
        sk_SSL_CIPHER_free(cipher_list);

    if (cipher_list_by_id)
        sk_SSL_CIPHER_free(cipher_list_by_id);

    cipher_list = SSL_CTX_get_ciphers(sctx);
    cipher_list_by_id = SSL_CTX_get_ciphers_by_id(sctx);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x009d))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), NULL,
                                       TLS1_VERSION, TLS1_2_VERSION,
                                       &sctx2, NULL, cert, privkey)))
        goto end;

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx2, "AES128-SHA256")))
        goto end;

    cipher_list = SSL_CTX_get_ciphers(sctx2);
    cipher_list_by_id = SSL_CTX_get_ciphers_by_id(sctx2);

    SSL_CTX_set_ciphers(sctx, cipher_list);
    SSL_CTX_set_ciphers_by_id(sctx, cipher_list_by_id);

    cipher_list = NULL;
    cipher_list_by_id = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0x003C))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
# endif
#endif

#ifndef OPENSSL_NO_VERIFY_SNI
static int test_babassl_verify_cert_with_sni(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_verify_cert_with_sni(sctx, 1);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "badservername.example"))
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                             SSL_ERROR_NONE)))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    if (!TEST_true(SSL_set_tlsext_host_name(clientssl, "server.example"))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                            SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CTX_get_verify_cert_with_sni(sctx),
                     sctx->verify_mode & SSL_VERIFY_FAIL_IF_SNI_NOT_MATCH_CERT))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_SESSION_REUSED_TYPE
static int test_babassl_session_reused_type(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl1 = NULL, *serverssl1 = NULL;
    SSL *clientssl2 = NULL, *serverssl2 = NULL;
    SSL_SESSION *sess1 = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx, "DEFAULT:@SECLEVEL=0"))
            || !TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0")))
        goto end;

    SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION);
    SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_SERVER);

# ifndef OSSL_NO_USABLE_TLS1_3
    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl1, clientssl1,
                                                SSL_ERROR_NONE))
            || !TEST_ptr(sess1 = SSL_get1_session(clientssl1)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl2,
                                      &clientssl2, NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl2, sess1))
            || !TEST_true(create_ssl_connection(serverssl2, clientssl2,
                                                SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl2))
            || !TEST_int_eq(SSL_get_session_reused_type(serverssl2),
                                                SSL_SESSION_REUSED_TYPE_TICKET))
        goto end;

    SSL_SESSION_free(sess1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
    SSL_free(serverssl1);
    SSL_free(clientssl1);

    sess1 = NULL;
    serverssl2 = NULL;
    clientssl2 = NULL;
    serverssl1 = NULL;
    clientssl1 = NULL;
# endif

# ifndef OPENSSL_NO_TLS1_2
    SSL_CTX_set_min_proto_version(cctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl1, clientssl1,
                                                SSL_ERROR_NONE))
            || !TEST_ptr(sess1 = SSL_get1_session(clientssl1))
            || !TEST_int_eq(SSL_get_session_reused_type(serverssl1),
                                                SSL_SESSION_REUSED_TYPE_NOCACHE))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl2,
                                      &clientssl2, NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl2, sess1))
            || !TEST_true(create_ssl_connection(serverssl2, clientssl2,
                                                SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl2))
            || !TEST_int_eq(SSL_get_session_reused_type(serverssl2),
                                                SSL_SESSION_REUSED_TYPE_CACHE))
        goto end;

    SSL_SESSION_free(sess1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    sess1 = NULL;
    serverssl2 = NULL;
    clientssl2 = NULL;
    serverssl1 = NULL;
    clientssl1 = NULL;
    sctx = NULL;
    cctx = NULL;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, TLS1_2_VERSION,
                                       &sctx, &cctx, cert, privkey))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx, "DEFAULT:@SECLEVEL=0"))
            || !TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0")))
        goto end;

    SSL_CTX_set_min_proto_version(cctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_CLIENT);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl1, clientssl1,
                                                SSL_ERROR_NONE))
            || !TEST_ptr(sess1 = SSL_get1_session(clientssl1)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl2,
                                      &clientssl2, NULL, NULL))
            || !TEST_true(SSL_set_session(clientssl2, sess1))
            || !TEST_true(create_ssl_connection(serverssl2, clientssl2,
                                                SSL_ERROR_NONE))
            || !TEST_true(SSL_session_reused(clientssl2))
            || !TEST_int_eq(SSL_get_session_reused_type(serverssl2),
                                                SSL_SESSION_REUSED_TYPE_TICKET))
        goto end;
# endif

    testresult = 1;

end:
    SSL_SESSION_free(sess1);
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#if !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305) && !defined(OPENSSL_NO_EC)
static int test_babassl_optimize_chacha_choose(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
                                       TLS1_VERSION, TLS1_2_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_PRIORITIZE_CHACHA);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    if (!TEST_true(SSL_CTX_set_cipher_list(sctx,
                            "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384"))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx,
                            "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305")))
        goto end;

    SSL_CTX_set_options(sctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

# ifndef OPENSSL_NO_OPTIMIZE_CHACHA_CHOOSE
    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0xc030))
# else
    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0xcca8))
# endif
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    if (!TEST_true(SSL_CTX_set_cipher_list(cctx,
                            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305")))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_CIPHER_get_protocol_id(SSL_get_current_cipher(serverssl)),
                     0xcca8))
        goto end;

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#if !defined(OPENSSL_NO_STATUS) && !defined(OPENSSL_NO_EC)

# ifndef SSLV2_CIPHER_LEN
#  define SSLV2_CIPHER_LEN      3
# endif

typedef struct {
    unsigned char              *buf;
    unsigned int                len;
    unsigned int                offset;
    unsigned char               cipher_suite_len;
    unsigned int                client_cipher_len;
    unsigned int                client_cipher_offset;
    unsigned int                ecc_curve_name;/*two bytes*/
    unsigned int                ecc_pubkeylen;
    unsigned int                ecc_pubkey_offset;
    unsigned int                rsa_pmaster_len;
    unsigned int                rsa_pmaster_offset;
    unsigned int                dh_pkey_len;
    unsigned int                dh_pkey_offset;
    unsigned int                client_session_len;
    unsigned int                client_session_offset;
    unsigned int                ellipticcurvelist_length;
    unsigned int                ellipticcurvelist_offset;
    unsigned int                srv_hello_time;
} ssl_status_t;

static int status_callback(unsigned char *p, unsigned int len, SSL_status *param)
{
    unsigned char                 type, m;
    ssl_status_t                 *status;
    unsigned int                  i, off;
# ifndef OPENSSL_NO_DH
    BIGNUM                       *pub = NULL;
# endif

    if (param == NULL || param->arg == NULL)
        return -1;

    type = param->type;
    status = (ssl_status_t*)param->arg;
    off = status->offset;

    if (type != SSL_CLIENT_RPOTOCOL && off + len > status->len) {
        status->buf = (unsigned char*)realloc(status->buf, status->len + len);
        if (status->buf == NULL) {
            status->len = 0;
            return  -1;
        }
        status->len += len;
    }

    if (type == SSL_CLIENT_RPOTOCOL) {
        if (status->len < 2)  {
            if (status->buf != NULL)
                return -1;

            status->buf = (unsigned char*)malloc(2);
            if (status->buf == NULL)
                return(-1);

            status->len = 2;
            status->offset = 2;
            if ((p[3] == 0x00) && (p[4] == 0x02)) {
                status->buf[0] = p[3];
                status->buf[1] = p[4];
            } else {
                status->buf[0] = p[9];
                status->buf[1] = p[10];
            }
        }
    } else if(type == SSL_CLIENT_V2_CIPHER) {
        if (len > 0) {
            status->client_cipher_len = 0;
            status->client_cipher_offset = off;
            status->cipher_suite_len = 2;
            for (i = 0; i < len; i += SSLV2_CIPHER_LEN) {
                if (p[i] != 0)
                    continue;

                status->buf[off++] = p[i+1];
                status->buf[off++] = p[i+2];
                status->client_cipher_len += 2;
            }
            status->offset = off;
        }
    } else if (type == SSL_CLIENT_CIPHER) {
        m = *((int*)(param->parg));
        if (m == 0 || len % m != 0)
            return -1;

        if (len > 0) {
            status->client_cipher_offset = off;
            status->client_cipher_len = len;
            status->cipher_suite_len = m;
            memcpy(status->buf + off, p, len);
            status->offset += len;
        }
    } else if (type == SSL_SERVER_EXCHANGE_PUBKEY) {
        if (len > 0) {
            status->ecc_pubkeylen = len;
            status->ecc_pubkey_offset = off;
            /*curve_name*/
            status->ecc_curve_name = *(p-2);
            /*ecc pubkey*/
            memcpy(status->buf + off, p, len);
            status->offset += len;
        }
    } else if (type == SSL_CLIENT_RSA_EXCHANGE) {
        if (len > 0) {
            status->rsa_pmaster_len = len;
            status->rsa_pmaster_offset = off;
            memcpy(status->buf + off, p, len);
            status->offset += len;
        }
    } else if (type == SSL_SERVER_DH_PUBKEY) {
# ifndef OPENSSL_NO_DH
        if (len > 0) {
            pub =  (BIGNUM*)param->parg;
            status->dh_pkey_len = len;
            status->dh_pkey_offset = off;
            BN_bn2bin(pub, status->buf + off);
            status->offset += len;
        }
# endif
    } else if (type == SSL_CLIENT_SESSION_ID) {
        if (len > 0) {
            status->client_session_len = len;
            status->client_session_offset = off;
            memcpy(status->buf + off, p, len);
            status->offset += len;
        }
    } else if (type == SSL_CLIENT_ECC_CURVES) {
# ifndef OPENSSL_NO_EC
        if (len > 0) {
            status->ellipticcurvelist_length = len;
            status->ellipticcurvelist_offset = off;
            memcpy(status->buf + off, p, len);
            status->offset += len;
        }
# endif
    } else {
        return -1;
    }

    return 1;
}

static int test_babassl_status(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl1 = NULL, *serverssl1 = NULL;
    SSL *clientssl2 = NULL, *serverssl2 = NULL;
    int testresult = 0;
    ssl_status_t status;
    SSL_SESSION *sess1 = NULL;
    unsigned int ellipticcurvelist_length;

    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, 0, &sctx, &cctx, cert, privkey))
        return 0;

    SSL_CTX_set_options(sctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);
    SSL_CTX_set_session_cache_mode(sctx, SSL_SESS_CACHE_SERVER);

    if (!TEST_true(SSL_CTX_set_cipher_list(sctx, "ECDHE-RSA-AES256-GCM-SHA384"))
            || !TEST_true(SSL_CTX_set_cipher_list(cctx,
                                            "ECDHE-RSA-AES256-GCM-SHA384")))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl1, &clientssl1,
                                      NULL, NULL)))
        goto end;

    memset(&status, 0, sizeof(status));
    SSL_set_status_callback(serverssl1, status_callback, 1, &status);

    if (!TEST_true(create_ssl_connection(serverssl1, clientssl1, SSL_ERROR_NONE))
        || !TEST_ptr(sess1 = SSL_get1_session(clientssl1)))
        goto end;

    if (!TEST_true(SSL_get_status_callback(serverssl1) == status_callback))
        goto end;

    ellipticcurvelist_length = status.ellipticcurvelist_length;

    if (!TEST_int_eq(clientssl1->session->kex_group, status.ecc_curve_name)
        || !TEST_int_eq(status.cipher_suite_len, 2)
        || !TEST_int_eq(htons(*(uint16_t *)(status.buf+status.client_cipher_offset)),
                        0xc030)
        || !TEST_int_gt(ellipticcurvelist_length, 0))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl2, &clientssl2,
                                      NULL, NULL))
        || !TEST_true(SSL_set_session(clientssl2, sess1)))
        goto end;

    memset(&status, 0, sizeof(status));
    SSL_set_status_callback(serverssl2, status_callback, 1, &status);

    if (!TEST_true(create_ssl_connection(serverssl2, clientssl2,
                                         SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(clientssl2)))
        goto end;

    if (!TEST_int_eq(clientssl2->session->kex_group, 29)
        || !TEST_int_eq(status.ecc_curve_name, 0)
        || !TEST_mem_eq(serverssl2->session->session_id,
                        serverssl2->session->session_id_length,
                        status.buf + status.client_session_offset,
                        status.client_session_len)
        || !TEST_int_eq(status.cipher_suite_len, 2)
        || !TEST_int_eq(htons(*(uint16_t *)(status.buf+status.client_cipher_offset)),
                        0xc030)
        || !TEST_int_eq(ellipticcurvelist_length, status.ellipticcurvelist_length))
        goto end;

    testresult = 1;

end:
    SSL_SESSION_free(sess1);
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}
#endif

#ifndef OPENSSL_NO_CRYPTO_MDEBUG_COUNT
static int test_babassl_crypto_mdebug_count(void)
{
    int testresult = 0, count1 = 0, count2 = 0;
    size_t size1 = 0, size2 = 0;
    void *p = NULL;

    CRYPTO_get_mem_counts(&count1, &size1);

    if (!TEST_int_gt(count1, 0)
        || !TEST_int_gt((int)size1, 0))
        goto err;

    /* Test malloc count and size records */
    p = OPENSSL_malloc(1234);
    if (!TEST_ptr(p))
        goto err;

    CRYPTO_get_mem_counts(&count2, &size2);

    if (!TEST_int_eq(count2, count1 + 1)
        || !TEST_int_ge((int)size2, (int)size1))
        goto err;

    /* Test free count and size records */
    OPENSSL_free(p);
    p = NULL;

    CRYPTO_get_mem_counts(&count2, &size2);

    if (!TEST_int_eq(count2, count1)
        || !TEST_int_eq((int)size2, (int)size1))
        goto err;

    /* Test realloc count and size records */
    p = OPENSSL_malloc(1234);
    p = OPENSSL_realloc(p, 2345);
    if (!TEST_ptr(p))
        goto err;

    CRYPTO_get_mem_counts(&count2, &size2);

    if (!TEST_int_eq(count2, count1 + 1)
        || !TEST_int_ge((int)size2, (int)size1))
        goto err;

    /* Test free count and size records */
    OPENSSL_free(p);
    p = NULL;

    CRYPTO_get_mem_counts(&count2, &size2);

    if (!TEST_int_eq(count2, count1)
        || !TEST_int_eq((int)size2, (int)size1))
        goto err;

    testresult = 1;

err:
    OPENSSL_free(p);
    return testresult;
}
#endif

#if !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_1)
static int test_babassl_ssl_ctx_dup(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL, *sctx2 = NULL, *sctx3 = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION, 0,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(), NULL,
                                       TLS1_VERSION, 0,
                                       &sctx2, NULL, cert, privkey))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(sctx, "DEFAULT:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(sctx2, "DEFAULT:@SECLEVEL=0")))
        goto end;

    SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_options(sctx2, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(sctx2, SSL_OP_NO_SSLv3);

    sctx3 = SSL_CTX_dup(sctx2);

    SSL_CTX_set_client_hello_cb(sctx, babassl_client_hello_callback, sctx3);

    /* The gimpy cipher list we configure can't do TLS 1.3. */
    SSL_CTX_set_max_proto_version(cctx, TLS1_2_VERSION);

    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1_2);
    SSL_CTX_set_options(cctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(cctx, SSL_OP_NO_SSLv3);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_false(create_ssl_connection(serverssl, clientssl,
                                                 SSL_ERROR_NONE)))
        goto end;

    SSL_free(serverssl);
    SSL_free(clientssl);

    serverssl = NULL;
    clientssl = NULL;

    SSL_CTX_clear_options(sctx3, SSL_OP_NO_TLSv1_1);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL))
            || !TEST_true(create_ssl_connection(serverssl, clientssl,
                                                SSL_ERROR_NONE)))
        goto end;

    fflush(stdout);
    setvbuf(stdout, NULL, _IONBF, 0);

    testresult = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx2);
    SSL_CTX_free(sctx3);

    return testresult;
}

static int test_babassl_ssl_ctx_dup_mem(void)
{
    int ret = 0;
    SSL_CTX *ctx1 = NULL, *ctx2 = NULL;
    X509_LOOKUP *lookup;

    if (!TEST_ptr(ctx1 = SSL_CTX_new(TLS_method()))
        || !TEST_true(SSL_CTX_set_default_verify_file(ctx1)))
        goto err;

    if (!TEST_ptr(lookup = X509_STORE_add_lookup(ctx1->cert_store, X509_LOOKUP_file())))
        goto err;

    X509_LOOKUP_load_file(lookup, cert, X509_FILETYPE_PEM);

    if (!TEST_ptr(ctx2 = SSL_CTX_dup(ctx1)))
        goto err;

    ret = 1;

err:
    SSL_CTX_free(ctx1);
    SSL_CTX_free(ctx2);
    return ret;
}

#endif

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

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

    ADD_TEST(test_babassl_debug);
    ADD_TEST(test_babassl_get_master_key);
    ADD_TEST(test_babassl_cipher_get);
    ADD_TEST(test_babassl_session_get_ref);
    ADD_TEST(test_babassl_get_use_certificate);
    ADD_TEST(test_babassl_get_cert_cb);
    ADD_TEST(test_babassl_get0_alpn_proposed);
    ADD_TEST(test_babassl_get0_wbio);
    ADD_TEST(test_babassl_ctx_certs_clear);
    ADD_TEST(test_babassl_set_session_ctx);
#ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_babassl_client_hello_get1_extensions);
#endif
#ifndef OPENSSL_NO_OCSP
    ADD_TEST(test_babassl_tlsext_status);
#endif
    ADD_TEST(test_babassl_set_ssl_ctx);
#if !defined(OPENSSL_NO_SESSION_LOOKUP) && (!defined(OPENSSL_NO_TLS1_2) \
                                            || !defined(OPENSSL_NO_TLS1_1) \
                                            || !defined(OPENSSL_NO_TLS1))
    ADD_TEST(test_babassl_session_lookup);
#endif
#ifndef OPENSSL_NO_DYNAMIC_CIPHERS
# ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_babassl_dynamic_ciphers);
# endif
#endif
#ifndef OPENSSL_NO_VERIFY_SNI
    ADD_TEST(test_babassl_verify_cert_with_sni);
#endif
#ifndef OPENSSL_NO_SESSION_REUSED_TYPE
    ADD_TEST(test_babassl_session_reused_type);
#endif
#if !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305) && !defined(OPENSSL_NO_EC)
    ADD_TEST(test_babassl_optimize_chacha_choose);
#endif
#if !defined(OPENSSL_NO_STATUS) && !defined(OPENSSL_NO_EC)
    ADD_TEST(test_babassl_status);
#endif
#ifndef OPENSSL_NO_CRYPTO_MDEBUG_COUNT
    ADD_TEST(test_babassl_crypto_mdebug_count);
#endif
#if !defined(OPENSSL_NO_TLS1_2) && !defined(OPENSSL_NO_TLS1_1)
    ADD_TEST(test_babassl_ssl_ctx_dup);
    ADD_TEST(test_babassl_ssl_ctx_dup_mem);
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
