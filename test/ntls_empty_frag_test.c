/*
 * Copyright 2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Empty-fragment ("known-IV countermeasure") record-count tests.
 *
 * The record layer prepends an empty application-data fragment to
 * application-data writes for cipher versions vulnerable to the known-IV
 * problem.  The decision is based on the numeric record version, and the
 * NTLS/TLCP version (0x0101) sorts below TLS1_VERSION, so the countermeasure
 * must be restricted to CBC ciphers or AEAD suites such as SM4-GCM emit a
 * useless extra empty record per write.  Record counts are taken by parsing
 * the wire records from memory BIOs, so they do not depend on TCP packet
 * boundaries.
 *
 * Covered:
 *  - NTLS ECC-SM2-SM4-GCM-SM3: one 17-byte SSL_write() produces exactly one
 *    application-data record (both directions), echo matches, close_notify
 *    works both ways;
 *  - NTLS ECC-SM2-SM4-CBC-SM3: the same write produces two application-data
 *    records, the first one being the (smaller) empty fragment;
 *  - SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS suppresses the empty fragment for
 *    both GCM and CBC;
 *  - TLS 1.0 AES128-SHA keeps its empty fragment, TLS 1.2 AES128-SHA (with
 *    explicit IVs) never gets one;
 *  - 1 byte / max record / record-boundary-crossing writes with fragmented
 *    reads round-trip byte exact.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>

#include "testutil.h"
#include "internal/nelem.h"

/* Maximum number of records inspected for a single SSL_write() */
#define MAX_RECS 8

typedef struct {
    SSL_CTX *cctx;
    SSL_CTX *sctx;
    SSL *cli;
    SSL *srv;
    BIO *c2s_w;                     /* client wbio, i.e. the C -> S wire */
    BIO *c2s_r;                     /* server rbio */
    BIO *s2c_w;                     /* server wbio, i.e. the S -> C wire */
    BIO *s2c_r;                     /* client rbio */
} SSL_PAIR;

typedef struct {
    int num;                        /* records seen */
    int num_app;                    /* application-data records seen */
    unsigned int app_len[MAX_RECS]; /* their length fields */
} REC_INFO;

static const char *ntls_sign_cert;
static const char *ntls_sign_key;
static const char *ntls_enc_cert;
static const char *ntls_enc_key;
static const char *tls_cert_file;
static const char *tls_key_file;

/* 17 bytes: the small write all record-count assertions use */
static const char msg17[] = "empty-frag-checks";

/* Move all bytes buffered in "from" (a write side) to "to" (peer read side) */
static int move_wire(BIO *from, BIO *to)
{
    unsigned char buf[2048];
    int n;

    while ((n = BIO_read(from, buf, sizeof(buf))) > 0) {
        int off = 0;

        while (off < n) {
            int w = BIO_write(to, buf + off, n - off);

            if (w <= 0)
                return 0;
            off += w;
        }
    }
    return 1;
}

/* Parse TLS/TLCP records, tracking application-data records and lengths */
static int parse_records(const unsigned char *p, size_t len, REC_INFO *ri)
{
    size_t off = 0;

    memset(ri, 0, sizeof(*ri));
    while (off < len) {
        unsigned int reclen;

        if (len - off < SSL3_RT_HEADER_LENGTH || ri->num >= MAX_RECS)
            return 0;
        reclen = ((unsigned int)p[off + 3] << 8) | p[off + 4];
        if (p[off] == SSL3_RT_APPLICATION_DATA) {
            ri->app_len[ri->num_app] = reclen;
            ri->num_app++;
        }
        ri->num++;
        off += SSL3_RT_HEADER_LENGTH + reclen;
    }
    return 1;
}

/* SSL_write() on "snd" (whose wbio is "wire") and collect the records it
 * produced.  "wire" must be empty before the call, so the buffer contents are
 * exactly the records of this write. */
static int write_and_parse(SSL *snd, BIO *wire, const void *buf, int len,
                           REC_INFO *ri)
{
    char *p = NULL;
    long total;

    if (!TEST_size_t_eq(BIO_ctrl_pending(wire), 0))
        return 0;
    if (!TEST_int_eq(SSL_write(snd, buf, len), len))
        return 0;
    total = BIO_get_mem_data(wire, &p);
    if (!TEST_long_ge(total, 0) || !TEST_ptr(p))
        return 0;
    return TEST_true(parse_records((const unsigned char *)p,
                                   (size_t)total, ri));
}

/* Check the record count of one direction's SSL_write().  With empty_first
 * the smaller countermeasure record must precede the payload record. */
static int check_records(const REC_INFO *ri, int expect, int empty_first,
                         const char *who)
{
    int i;

    if (!TEST_int_eq(ri->num_app, expect)) {
        TEST_info("%s: got %d app-data records, expected %d; lengths:",
                  who, ri->num_app, expect);
        for (i = 0; i < ri->num_app; i++)
            TEST_info("%s: record %d length %u", who, i, ri->app_len[i]);
        return 0;
    }
    if (!TEST_int_eq(ri->num, ri->num_app)) {
        TEST_info("%s: unexpected non-application-data record after handshake",
                  who);
        return 0;
    }
    if (empty_first && !TEST_int_lt(ri->app_len[0], ri->app_len[1]))
        return 0;
    return 1;
}

/* Drive both state machines over the memory BIOs until established */
static int do_handshake(SSL_PAIR *sp)
{
    int i;

    for (i = 0; i < 100; i++) {
        int rc = SSL_do_handshake(sp->cli);

        if (rc != 1) {
            int e = SSL_get_error(sp->cli, rc);

            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                TEST_info("client handshake failed, error %d", e);
                ERR_print_errors_fp(stderr);
                return 0;
            }
        }
        if (!TEST_true(move_wire(sp->c2s_w, sp->c2s_r)))
            return 0;
        rc = SSL_do_handshake(sp->srv);
        if (rc != 1) {
            int e = SSL_get_error(sp->srv, rc);

            if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) {
                TEST_info("server handshake failed, error %d", e);
                ERR_print_errors_fp(stderr);
                return 0;
            }
        }
        if (!TEST_true(move_wire(sp->s2c_w, sp->s2c_r)))
            return 0;
        if (SSL_is_init_finished(sp->cli) && SSL_is_init_finished(sp->srv))
            return 1;
    }
    TEST_info("handshake did not complete");
    return 0;
}

/* One application-data exchange: the client writes "msg" (len bytes), the
 * server reads and echoes it, the client reads it back.  "expect" and
 * "empty_first" pin the record counts of both SSL_write() calls. */
static int echo_round(SSL_PAIR *sp, const void *msg, int len, int expect,
                      int empty_first)
{
    unsigned char buf[512];
    REC_INFO ri;
    int n;

    if (!write_and_parse(sp->cli, sp->c2s_w, msg, len, &ri))
        return 0;
    if (!check_records(&ri, expect, empty_first, "client"))
        return 0;
    if (!TEST_true(move_wire(sp->c2s_w, sp->c2s_r)))
        return 0;
    n = SSL_read(sp->srv, buf, sizeof(buf));
    if (!TEST_int_eq(n, len) || !TEST_mem_eq(buf, n, msg, len))
        return 0;

    if (!write_and_parse(sp->srv, sp->s2c_w, buf, n, &ri))
        return 0;
    if (!check_records(&ri, expect, empty_first, "server"))
        return 0;
    if (!TEST_true(move_wire(sp->s2c_w, sp->s2c_r)))
        return 0;
    n = SSL_read(sp->cli, buf, sizeof(buf));
    if (!TEST_int_eq(n, len) || !TEST_mem_eq(buf, n, msg, len))
        return 0;
    return 1;
}

/* Bidirectional close_notify */
static int do_close(SSL_PAIR *sp)
{
    unsigned char b;
    int n, r;

    r = SSL_shutdown(sp->cli);
    if (!TEST_int_ge(r, 0))
        return 0;
    if (!TEST_true(move_wire(sp->c2s_w, sp->c2s_r)))
        return 0;
    /* The server must observe the close_notify (zero return) */
    n = SSL_read(sp->srv, &b, sizeof(b));
    if (!TEST_int_le(n, 0)
            || !TEST_int_eq(SSL_get_error(sp->srv, n), SSL_ERROR_ZERO_RETURN))
        return 0;
    r = SSL_shutdown(sp->srv);
    if (!TEST_int_eq(r, 1))
        return 0;
    if (!TEST_true(move_wire(sp->s2c_w, sp->s2c_r)))
        return 0;
    r = SSL_shutdown(sp->cli);
    if (!TEST_int_eq(r, 1))
        return 0;
    if (!TEST_true((SSL_get_shutdown(sp->cli) & SSL_RECEIVED_SHUTDOWN) != 0))
        return 0;
    if (!TEST_true((SSL_get_shutdown(sp->srv) & SSL_RECEIVED_SHUTDOWN) != 0))
        return 0;
    return 1;
}

/* Configure the CTX pair.  Certificates and the NTLS mode must be set on
 * the CTXs before the SSL objects are instantiated (SSL_new snapshots both),
 * so object creation is a separate step. */
static int prepare_ctx_pair(SSL_PAIR *sp, const SSL_METHOD *cmeth,
                            const SSL_METHOD *smeth, const char *cipher,
                            long options, int minver, int maxver)
{
    memset(sp, 0, sizeof(*sp));
    sp->cctx = SSL_CTX_new(cmeth);
    sp->sctx = SSL_CTX_new(smeth);
    if (!TEST_ptr(sp->cctx) || !TEST_ptr(sp->sctx))
        return 0;
    if (minver > 0) {
        SSL_CTX_set_min_proto_version(sp->cctx, minver);
        SSL_CTX_set_min_proto_version(sp->sctx, minver);
    }
    if (maxver > 0) {
        SSL_CTX_set_max_proto_version(sp->cctx, maxver);
        SSL_CTX_set_max_proto_version(sp->sctx, maxver);
    }
    SSL_CTX_set_verify(sp->cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(sp->sctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_options(sp->cctx, options);
    SSL_CTX_set_options(sp->sctx, options);
    if (!TEST_true(SSL_CTX_set_cipher_list(sp->cctx, cipher))
            || !TEST_true(SSL_CTX_set_cipher_list(sp->sctx, cipher)))
        return 0;
    return 1;
}

/* Instantiate the SSL objects and the memory-BIO channels */
static int make_ssl_pair(SSL_PAIR *sp)
{
    sp->c2s_w = BIO_new(BIO_s_mem());
    sp->c2s_r = BIO_new(BIO_s_mem());
    sp->s2c_w = BIO_new(BIO_s_mem());
    sp->s2c_r = BIO_new(BIO_s_mem());
    if (!TEST_ptr(sp->c2s_w) || !TEST_ptr(sp->c2s_r)
            || !TEST_ptr(sp->s2c_w) || !TEST_ptr(sp->s2c_r))
        return 0;
    sp->cli = SSL_new(sp->cctx);
    sp->srv = SSL_new(sp->sctx);
    if (!TEST_ptr(sp->cli) || !TEST_ptr(sp->srv))
        return 0;
    SSL_set_bio(sp->cli, sp->s2c_r, sp->c2s_w);
    SSL_set_bio(sp->srv, sp->c2s_r, sp->s2c_w);
    SSL_set_connect_state(sp->cli);
    SSL_set_accept_state(sp->srv);
    return 1;
}

static void free_pair(SSL_PAIR *sp)
{
    /* The BIOs are owned and freed by the SSL objects */
    SSL_free(sp->cli);
    SSL_free(sp->srv);
    SSL_CTX_free(sp->cctx);
    SSL_CTX_free(sp->sctx);
    memset(sp, 0, sizeof(*sp));
}

#if !defined(OPENSSL_NO_NTLS) && !defined(OPENSSL_NO_SM2) \
    && !defined(OPENSSL_NO_SM3) && !defined(OPENSSL_NO_SM4)
/* Load the NTLS double certificate (sign + enc) on the server side */
static int load_ntls_certs(SSL_CTX *sctx)
{
    return TEST_int_eq(SSL_CTX_use_sign_certificate_file(sctx, ntls_sign_cert,
                                                         SSL_FILETYPE_PEM), 1)
        && TEST_int_eq(SSL_CTX_use_sign_PrivateKey_file(sctx, ntls_sign_key,
                                                        SSL_FILETYPE_PEM), 1)
        && TEST_int_eq(SSL_CTX_use_enc_certificate_file(sctx, ntls_enc_cert,
                                                        SSL_FILETYPE_PEM), 1)
        && TEST_int_eq(SSL_CTX_use_enc_PrivateKey_file(sctx, ntls_enc_key,
                                                       SSL_FILETYPE_PEM), 1);
}

/* Full lifecycle (handshake, one counted echo round, close) over NTLS */
static int run_ntls(const char *cipher, long options, int expect,
                    int empty_first)
{
    SSL_PAIR sp;
    int ok = 0;

    if (!TEST_true(prepare_ctx_pair(&sp, NTLS_client_method(),
                                    NTLS_server_method(), cipher, options,
                                    0, 0)))
        goto end;
    /* NTLS needs the dedicated NTLS state machine on both ends */
    SSL_CTX_enable_ntls(sp.cctx);
    SSL_CTX_enable_ntls(sp.sctx);
    if (!TEST_true(load_ntls_certs(sp.sctx)))
        goto end;
    if (!TEST_true(make_ssl_pair(&sp)))
        goto end;
    if (!TEST_true(do_handshake(&sp)))
        goto end;
    if (!TEST_true(echo_round(&sp, msg17, (int)sizeof(msg17) - 1, expect,
                              empty_first)))
        goto end;
    ok = do_close(&sp);
 end:
    free_pair(&sp);
    return ok;
}

static int test_ntls_gcm(void)
{
    return run_ntls(NTLS_TXT_ECC_SM2_SM4_GCM_SM3, 0, 1, 0);
}

static int test_ntls_cbc(void)
{
    return run_ntls(NTLS_TXT_ECC_SM2_SM4_CBC_SM3, 0, 2, 1);
}

static int test_ntls_gcm_dont_insert(void)
{
    return run_ntls(NTLS_TXT_ECC_SM2_SM4_GCM_SM3,
                    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, 1, 0);
}

static int test_ntls_cbc_dont_insert(void)
{
    return run_ntls(NTLS_TXT_ECC_SM2_SM4_CBC_SM3,
                    SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS, 1, 0);
}
#endif /* NTLS and SM2/SM3/SM4 enabled */

#if !defined(OPENSSL_NO_TLS1) || !defined(OPENSSL_NO_TLS1_2)
static int load_tls_certs(SSL_CTX *sctx)
{
    return TEST_int_eq(SSL_CTX_use_certificate_chain_file(sctx,
                                                          tls_cert_file), 1)
        && TEST_int_eq(SSL_CTX_use_PrivateKey_file(sctx, tls_key_file,
                                                   SSL_FILETYPE_PEM), 1);
}

/* Full lifecycle over classic TLS pinned to "ver" */
static int run_tls(int ver, const char *cipher, long options, int expect,
                   int empty_first)
{
    SSL_PAIR sp;
    int ok = 0;

    if (!TEST_true(prepare_ctx_pair(&sp, TLS_client_method(),
                                    TLS_server_method(), cipher, options,
                                    ver, ver)))
        goto end;
    if (!TEST_true(load_tls_certs(sp.sctx)))
        goto end;
    if (!TEST_true(make_ssl_pair(&sp)))
        goto end;
    if (!TEST_true(do_handshake(&sp)))
        goto end;
    if (!TEST_true(echo_round(&sp, msg17, (int)sizeof(msg17) - 1, expect,
                              empty_first)))
        goto end;
    ok = do_close(&sp);
 end:
    free_pair(&sp);
    return ok;
}
#endif

#ifndef OPENSSL_NO_TLS1
static int test_tls10_cbc(void)
{
    return run_tls(TLS1_VERSION, "AES128-SHA@SECLEVEL=0", 0, 2, 1);
}
#endif

#ifndef OPENSSL_NO_TLS1_2
static int test_tls12_cbc(void)
{
    return run_tls(TLS1_2_VERSION, "AES128-SHA@SECLEVEL=0", 0, 1, 0);
}
#endif

/* Sizes exercising the record layer boundaries; no record-count assertions
 * here, only byte-exact fragmented echo round-trips. */
static const size_t frag_lens[] = {
    1, SSL3_RT_MAX_PLAIN_LENGTH, SSL3_RT_MAX_PLAIN_LENGTH + 1
};

static int fragmented_round(SSL_PAIR *sp, size_t len)
{
    static unsigned char out[SSL3_RT_MAX_PLAIN_LENGTH + 2];
    static unsigned char in[SSL3_RT_MAX_PLAIN_LENGTH + 2];
    static unsigned char back[SSL3_RT_MAX_PLAIN_LENGTH + 2];
    size_t got, i;
    int n;

    for (i = 0; i < len; i++)
        out[i] = (unsigned char)(i * 7 + 3);

    if (!TEST_int_eq(SSL_write(sp->cli, out, (int)len), (int)len))
        return 0;
    if (!TEST_true(move_wire(sp->c2s_w, sp->c2s_r)))
        return 0;
    for (got = 0; got < len; got += (size_t)n) {
        n = SSL_read(sp->srv, in + got, 777);
        if (!TEST_int_gt(n, 0))
            return 0;
    }
    if (!TEST_size_t_eq(got, len) || !TEST_mem_eq(in, got, out, got))
        return 0;

    if (!TEST_int_eq(SSL_write(sp->srv, in, (int)len), (int)len))
        return 0;
    if (!TEST_true(move_wire(sp->s2c_w, sp->s2c_r)))
        return 0;
    for (got = 0; got < len; got += (size_t)n) {
        n = SSL_read(sp->cli, back + got, 1001);
        if (!TEST_int_gt(n, 0))
            return 0;
    }
    if (!TEST_size_t_eq(got, len) || !TEST_mem_eq(back, got, out, got))
        return 0;
    return 1;
}

#if !defined(OPENSSL_NO_NTLS) && !defined(OPENSSL_NO_SM2) \
    && !defined(OPENSSL_NO_SM3) && !defined(OPENSSL_NO_SM4)
static int run_ntls_fragmented(const char *cipher)
{
    SSL_PAIR sp;
    size_t i;
    int ok = 0;

    if (!TEST_true(prepare_ctx_pair(&sp, NTLS_client_method(),
                                    NTLS_server_method(), cipher, 0, 0, 0)))
        goto end;
    SSL_CTX_enable_ntls(sp.cctx);
    SSL_CTX_enable_ntls(sp.sctx);
    if (!TEST_true(load_ntls_certs(sp.sctx)))
        goto end;
    if (!TEST_true(make_ssl_pair(&sp)))
        goto end;
    if (!TEST_true(do_handshake(&sp)))
        goto end;
    for (i = 0; i < OSSL_NELEM(frag_lens); i++) {
        if (!TEST_true(fragmented_round(&sp, frag_lens[i])))
            goto end;
    }
    ok = do_close(&sp);
 end:
    free_pair(&sp);
    return ok;
}

static int test_ntls_gcm_fragmented(void)
{
    return run_ntls_fragmented(NTLS_TXT_ECC_SM2_SM4_GCM_SM3);
}

static int test_ntls_cbc_fragmented(void)
{
    return run_ntls_fragmented(NTLS_TXT_ECC_SM2_SM4_CBC_SM3);
}
#endif /* NTLS and SM2/SM3/SM4 enabled */

#if !defined(OPENSSL_NO_TLS1) || !defined(OPENSSL_NO_TLS1_2)
static int run_tls_fragmented(int ver, const char *cipher)
{
    SSL_PAIR sp;
    size_t i;
    int ok = 0;

    if (!TEST_true(prepare_ctx_pair(&sp, TLS_client_method(),
                                    TLS_server_method(), cipher, 0, ver,
                                    ver)))
        goto end;
    if (!TEST_true(load_tls_certs(sp.sctx)))
        goto end;
    if (!TEST_true(make_ssl_pair(&sp)))
        goto end;
    if (!TEST_true(do_handshake(&sp)))
        goto end;
    for (i = 0; i < OSSL_NELEM(frag_lens); i++) {
        if (!TEST_true(fragmented_round(&sp, frag_lens[i])))
            goto end;
    }
    ok = do_close(&sp);
 end:
    free_pair(&sp);
    return ok;
}
#endif

#ifndef OPENSSL_NO_TLS1
static int test_tls10_cbc_fragmented(void)
{
    return run_tls_fragmented(TLS1_VERSION, "AES128-SHA@SECLEVEL=0");
}
#endif

#ifndef OPENSSL_NO_TLS1_2
static int test_tls12_cbc_fragmented(void)
{
    return run_tls_fragmented(TLS1_2_VERSION, "AES128-SHA@SECLEVEL=0");
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(ntls_sign_cert = test_get_argument(0))
            || !TEST_ptr(ntls_sign_key = test_get_argument(1))
            || !TEST_ptr(ntls_enc_cert = test_get_argument(2))
            || !TEST_ptr(ntls_enc_key = test_get_argument(3))
            || !TEST_ptr(tls_cert_file = test_get_argument(4))
            || !TEST_ptr(tls_key_file = test_get_argument(5))) {
        TEST_note("usage: ntls_empty_frag_test ntls-sign-cert ntls-sign-key"
                  " ntls-enc-cert ntls-enc-key tls-cert tls-key");
        return 0;
    }

#if !defined(OPENSSL_NO_NTLS) && !defined(OPENSSL_NO_SM2) \
    && !defined(OPENSSL_NO_SM3) && !defined(OPENSSL_NO_SM4)
    ADD_TEST(test_ntls_gcm);
    ADD_TEST(test_ntls_cbc);
    ADD_TEST(test_ntls_gcm_dont_insert);
    ADD_TEST(test_ntls_cbc_dont_insert);
    ADD_TEST(test_ntls_gcm_fragmented);
    ADD_TEST(test_ntls_cbc_fragmented);
#endif
#ifndef OPENSSL_NO_TLS1
    ADD_TEST(test_tls10_cbc);
    ADD_TEST(test_tls10_cbc_fragmented);
#endif
#ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_tls12_cbc);
    ADD_TEST(test_tls12_cbc_fragmented);
#endif
    return 1;
}
