/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include <string.h>

#include "apps.h"
#include "progs.h"
#include <stdio.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/sm3.h>
#include "internal/smtc_names.h"
#include "../providers/smtc/smtckey.h"

#define PASSWD_BUF_SIZE 1024
#define BUFSIZE         4096

typedef struct {
    const char *section;
    const char *module_path;
#ifndef OPENSSL_NO_SMTC_DEBUG
    int verify_pass;
#endif
    int show_selftest;
    unsigned char admin_salt[SM3_DIGEST_LENGTH];
    unsigned char admin_pass[SM3_DIGEST_LENGTH];
    unsigned char module_mac[EVP_MAX_MD_SIZE];
    size_t module_mac_len;
} SMTC_CONF;

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_TEST,
    OPT_MODULE,
    OPT_PROV_NAME,
    OPT_SECTION_NAME,
    OPT_OUT,
    OPT_SHOW_SELFTEST,
#ifndef OPENSSL_NO_SMTC_DEBUG
    OPT_NO_PASS,
#endif
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS mod_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"test", OPT_TEST, '-', "Self test"},
    {"module", OPT_MODULE, '<', "File name of the provider module"},
    {"provider_name", OPT_PROV_NAME, 's', "SMTC provider name"},
    {"section_name",
     OPT_SECTION_NAME,
     's',
     "SMTC Provider config section name (optional)"},
     {"show_selftest", OPT_SHOW_SELFTEST, '-', "Show self test"},
#ifndef OPENSSL_NO_SMTC_DEBUG
    {"no_pass", OPT_NO_PASS, '-', "Do not setup password"},
#endif
    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output config file, used when generating"},

    {NULL}};

static int setup_password(unsigned char *admin_salt, unsigned char *admin_pass)
{
    int ret = 0;
    char passwd[PASSWD_BUF_SIZE];
    EVP_MD_CTX *mctx = NULL;

    if (EVP_read_pw_string(passwd, sizeof(passwd), "Setup password: ", 1) != 0)
        goto end;

    if (RAND_bytes(admin_salt, SM3_DIGEST_LENGTH) <= 0)
        goto end;

    if ((mctx = EVP_MD_CTX_new()) == NULL
        || !EVP_DigestInit_ex(mctx, EVP_sm3(), NULL)
        || !EVP_DigestUpdate(mctx, admin_salt, SM3_DIGEST_LENGTH)
        || !EVP_DigestUpdate(mctx, passwd, strlen(passwd))
        || !EVP_DigestFinal_ex(mctx, admin_pass, NULL))
        goto end;

    ret = 1;
end:
    EVP_MD_CTX_free(mctx);
    return ret;
}

static int do_mac(EVP_MAC_CTX *ctx, unsigned char *tmp, BIO *in,
                  unsigned char *out, size_t *out_len)
{
    int ret = 0;
    int i;
    size_t outsz = *out_len;

    if (!EVP_MAC_init(ctx, NULL, 0, NULL))
        goto err;
    if (EVP_MAC_CTX_get_mac_size(ctx) > outsz)
        goto end;
    while ((i = BIO_read(in, (char *)tmp, BUFSIZE)) != 0) {
        if (i < 0 || !EVP_MAC_update(ctx, tmp, i))
            goto err;
    }
end:
    if (!EVP_MAC_final(ctx, out, out_len, outsz))
        goto err;
    ret = 1;
err:
    return ret;
}

static int write_config_header(BIO *out, const char *prov_name,
                               const char *section)
{
    return BIO_printf(out, "openssl_conf = openssl_init\n\n")
           && BIO_printf(out, "[openssl_init]\n")
           && BIO_printf(out, "providers = provider_section\n\n")
           && BIO_printf(out, "[provider_section]\n")
           && BIO_printf(out, "%s = %s\n\n", prov_name, section);
}

static int print_hex(BIO *bio, const char *label, const unsigned char *val,
                     size_t len)
{
    int ret;
    char *hexstr = NULL;

    hexstr = OPENSSL_buf2hexstr(val, (long)len);
    if (hexstr == NULL)
        return 0;
    ret = BIO_printf(bio, "%s = %s\n", label, hexstr);
    OPENSSL_free(hexstr);
    return ret;
}

/*
 * Outputs a smtc related config file.
 * Returns 1 if the config file is written otherwise it returns 0 on error.
 */
static int write_config_smtc_section(BIO *out, SMTC_CONF *sc)
{
    int ret = 0;

    if (BIO_printf(out, "[%s]\n", sc->section) <= 0
        || BIO_printf(out, "activate = 1\n") <= 0
        || BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_MODULE_PATH,
                      sc->module_path) <= 0
        || !print_hex(out, OSSL_PROV_SMTC_PARAM_MODULE_MAC, sc->module_mac,
                      sc->module_mac_len))
        goto end;

    if (sc->show_selftest) {
        if (BIO_printf(out, "%s = 1\n", OSSL_PROV_SMTC_PARAM_SHOW_SELFTEST)
                <= 0)
            goto end;
    } else {
        if (BIO_printf(out, "%s = 0\n", OSSL_PROV_SMTC_PARAM_SHOW_SELFTEST)
                <= 0)
            goto end;
    }

#ifndef OPENSSL_NO_SMTC_DEBUG
    if (sc->verify_pass == 0) {
        if (BIO_printf(out, "%s = 0\n", OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_PASS)
                <= 0)
            goto end;
    } else {
#endif
        if (!print_hex(out, OSSL_PROV_SMTC_PARAM_ADMIN_SALT, sc->admin_salt,
                        sizeof(sc->admin_salt))
            || !print_hex(out, OSSL_PROV_SMTC_PARAM_ADMIN_PASS,
                            sc->admin_pass, sizeof(sc->admin_pass)))
        goto end;
#ifndef OPENSSL_NO_SMTC_DEBUG
    }
#endif

    ret = 1;
end:
    return ret;
}

static CONF *generate_config_and_load(const char *prov_name, SMTC_CONF *sc)
{
    BIO *mem_bio = NULL;
    CONF *conf = NULL;

    mem_bio = BIO_new(BIO_s_mem());
    if (mem_bio == NULL)
        return 0;
    if (!write_config_header(mem_bio, prov_name, sc->section) ||
        !write_config_smtc_section(mem_bio, sc))
        goto end;

    conf = app_load_config_bio(mem_bio, NULL);
    if (conf == NULL)
        goto end;

    if (CONF_modules_load(conf, NULL, 0) <= 0)
        goto end;
    BIO_free(mem_bio);
    return conf;
end:
    NCONF_free(conf);
    BIO_free(mem_bio);
    return NULL;
}

int mod_main(int argc, char **argv)
{
    int ret = 1;
#ifndef OPENSSL_NO_SMTC_DEBUG
    int no_pass = 0;
#endif
    char *prog;
    OPTION_CHOICE o;
    int self_test = 0;
    BIO *module_bio = NULL, *fout = NULL;
    char *out_fname = NULL;
    EVP_MAC *mac = NULL;
    const char *mac_name = "HMAC";
    const char *prov_name = "smtc";
    SMTC_CONF sc = {
        .section = "smtc_sect",
        .show_selftest = 0,
#ifndef OPENSSL_NO_SMTC_DEBUG
        .verify_pass = 1,
#endif
    };
    STACK_OF(OPENSSL_STRING) *opts = NULL;
    unsigned char *read_buffer = NULL;
    EVP_MAC_CTX *ctx = NULL, *ctx2 = NULL;
    CONF *conf = NULL;

    if ((opts = sk_OPENSSL_STRING_new_null()) == NULL)
        goto end;

    prog = opt_init(argc, argv, mod_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
        opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto cleanup;
        case OPT_HELP:
            opt_help(mod_options);
            ret = 0;
            goto end;
        case OPT_TEST:
            self_test = 1;
            break;
        case OPT_PROV_NAME:
            prov_name = opt_arg();
            break;
        case OPT_MODULE:
            sc.module_path = opt_arg();
            break;
        case OPT_SECTION_NAME:
            sc.section = opt_arg();
            break;
        case OPT_SHOW_SELFTEST:
            sc.show_selftest = 1;
            break;
#ifndef OPENSSL_NO_SMTC_DEBUG
        case OPT_NO_PASS:
            no_pass = 1;
            sc.verify_pass = 0;
            break;
#endif
        case OPT_OUT:
            out_fname = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (self_test) {
        if (OSSL_PROVIDER_available(app_get0_libctx(), "smtc")) {
            OSSL_PROVIDER *prov = OSSL_PROVIDER_load(app_get0_libctx(), "smtc");
            if (prov == NULL) {
                BIO_printf(bio_err, "Failed to load SMTC provider\n");
                goto end;
            }

            if (OSSL_PROVIDER_self_test(prov) != 1) {
                OSSL_PROVIDER_unload(prov);
                BIO_printf(bio_err, "SMTC provider self test failed\n");
                goto end;
            }

            OSSL_PROVIDER_unload(prov);

            ret = 0;
            goto end;
        } else {
            BIO_printf(bio_err, "SMTC provider not available\n");
            goto end;
        }
    }

#ifndef OPENSSL_NO_SMTC_DEBUG
    if (!no_pass)
#endif
        if (!setup_password(sc.admin_salt, sc.admin_pass))
            goto end;

    if (sc.module_path == NULL)
        goto opthelp;

    if (!sk_OPENSSL_STRING_push(opts, "digest:SM3"))
        goto end;
    if (!sk_OPENSSL_STRING_push(opts, "hexkey:" SMTC_KEY_STRING))
        goto end;

    module_bio = bio_open_default(sc.module_path, 'r', FORMAT_BINARY);
    if (module_bio == NULL) {
        BIO_printf(bio_err, "Failed to open module file\n");
        goto end;
    }

    read_buffer = app_malloc(BUFSIZE, "I/O buffer");
    if (read_buffer == NULL)
        goto end;

    mac = EVP_MAC_fetch(app_get0_libctx(), mac_name, app_get0_propq());
    if (mac == NULL) {
        BIO_printf(bio_err, "Unable to get MAC of type %s\n", mac_name);
        goto end;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for module check\n");
        goto end;
    }

    if (opts != NULL) {
        int ok = 1;
        OSSL_PARAM *params
            = app_params_new_from_opts(opts, EVP_MAC_settable_ctx_params(mac));

        if (params == NULL)
            goto end;

        if (!EVP_MAC_CTX_set_params(ctx, params)) {
            BIO_printf(bio_err, "MAC parameter error\n");
            ERR_print_errors(bio_err);
            ok = 0;
        }
        app_params_free(params);
        if (!ok)
            goto end;
    }

    ctx2 = EVP_MAC_CTX_dup(ctx);
    if (ctx2 == NULL) {
        BIO_printf(bio_err, "Unable to create MAC CTX for install indicator\n");
        goto end;
    }

    sc.module_mac_len = sizeof(sc.module_mac);
    if (!do_mac(ctx, read_buffer, module_bio, sc.module_mac, &sc.module_mac_len))
        goto end;

    conf = generate_config_and_load(prov_name, &sc);
    if (conf == NULL)
        goto end;

    fout = out_fname == NULL ? dup_bio_out(FORMAT_TEXT)
                             : bio_open_default(out_fname, 'w', FORMAT_TEXT);
    if (fout == NULL) {
        BIO_printf(bio_err, "Failed to open file\n");
        goto end;
    }
    if (!write_config_smtc_section(fout, &sc))
        goto end;

    BIO_printf(bio_err, "INSTALL PASSED\n");

    ret = 0;
end:
    if (ret == 1)
        ERR_print_errors(bio_err);

cleanup:
    BIO_free(fout);
    BIO_free(module_bio);
    sk_OPENSSL_STRING_free(opts);
    EVP_MAC_free(mac);
    EVP_MAC_CTX_free(ctx2);
    EVP_MAC_CTX_free(ctx);
    OPENSSL_free(read_buffer);
    if (conf != NULL) {
        NCONF_free(conf);
        CONF_modules_unload(1);
    }
    return ret;
}
