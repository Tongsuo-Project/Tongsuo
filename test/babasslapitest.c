#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/srp.h>
#include <openssl/txt_db.h>
#include <openssl/aes.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/nelem.h"
#include "../ssl/ssl_local.h"

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

int setup_tests(void)
{
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
    return 1;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    bio_s_mempacket_test_free();
    bio_s_always_retry_free();
}
