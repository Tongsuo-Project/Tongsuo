/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include "internal/deprecated.h"

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "apps.h"
#include "progs.h"
#include <stdio.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/sm3.h>
#include "internal/smtc_names.h"
#include "../providers/smtc/smtckey.h"

#define BUFSIZE             4096
#define SMTC_AUTH_PASSWD_MAX_LEN 64
#define SMTC_AUTH_KEY_LEN   64
#define SMTC_AUTH_SALT_LEN  64

typedef struct {
    const char *section;
    const char *module_path;
    char *sig;
    const char *kek;
    const char *eng;
    const char *syslog;
    char *key;
    char *salt;
    const char *rand_poweron_test;
#ifndef OPENSSL_NO_SMTC_DEBUG
    const char *verify_sig;
    const char *verify_pass;
#endif
} SMTC_CONF;

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_TEST,
    OPT_RESET,
    OPT_MODULE,
    OPT_PROV_NAME,
    OPT_SIGFILE,
    OPT_STATUS,
    OPT_INSTALL,
    OPT_KEK,
    OPT_ENGINE,
    OPT_PASS,
    OPT_OUT,
#ifndef OPENSSL_NO_SMTC_DEBUG
    OPT_NO_VERIFY,
    OPT_NO_AUTH,
    OPT_NO_RAND_POWERON_TEST,
#endif
} OPTION_CHOICE;

const OPTIONS mod_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"install", OPT_INSTALL, '-', "Install module, generate config file"},
    {"test", OPT_TEST, '-', "Self test"},
    {"status", OPT_STATUS, '-', "Display the status of the module"},
    {"reset", OPT_RESET, '-', "Reset module, clear salt and password"},
    {"module", OPT_MODULE, 's', "File path of the module"},
    {"provider_name", OPT_PROV_NAME, 's', "Provider name"},
    {"pass", OPT_PASS, '-', "Setup password"},
    {"kek", OPT_KEK, 's', "The key for encrypting HMAC key"},
    {"engine", OPT_ENGINE, 's', "Use the engine e, possibly a hardware device"},
#ifndef OPENSSL_NO_SMTC_DEBUG
    {"no_verify", OPT_NO_VERIFY, '-', "Do not verify the integrity of the software"},
    {"no_auth", OPT_NO_AUTH, '-', "No authentication required for user login"},
    {"no_rand_poweron_test", OPT_NO_RAND_POWERON_TEST, '-', "No random poweron test"},
#endif

    OPT_SECTION("Input"),
    {"sigfile", OPT_SIGFILE, '<', "Signature file"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output config file, used when generating"},
    {NULL}};

static int check_passwd(const char *passwd, size_t len)
{
    size_t i;
    int upper = 0, lower = 0, digit = 0;

    if (len < 8 || len > 64)
        return 0;

    for (i = 0; i < len; i++) {
        if (isupper(passwd[i]))
            upper = 1;
        else if (islower(passwd[i]))
            lower = 1;
        else if (isdigit(passwd[i]))
            digit = 1;
        else
            return 0;
    }

    if ((upper & lower & digit) == 0)
        return 0;

    return 1;
}


static int setup_password(EVP_PKEY *kek, unsigned char *auth_salt,
                          unsigned char **auth_key, size_t *auth_key_len)
{
    int ok = 0;
    EVP_PKEY_CTX *ctx = NULL;
    char passwd[SMTC_AUTH_PASSWD_MAX_LEN + 1] = {0};
    unsigned char key[SMTC_AUTH_KEY_LEN];
    unsigned char *enc_key = NULL;
    size_t outlen;

    if (EVP_read_pw_string_min(passwd, 8, sizeof(passwd) - 1,
                               "Setup password: ", 1) != 0)
        goto end;

    if (!check_passwd(passwd, strlen(passwd))) {
        BIO_printf(bio_err, "Passwords should be 8-64 characters in length and"
                   "must contain number, uppercase and lowercase letter\n");
        goto end;
    }

    if (RAND_bytes(auth_salt, SMTC_AUTH_SALT_LEN) != 1)
        goto end;

    if (PKCS5_PBKDF2_HMAC(passwd, strlen(passwd), auth_salt, SMTC_AUTH_SALT_LEN,
                          10000, EVP_sm3(), SMTC_AUTH_KEY_LEN, key) != 1)
        goto end;

    if (kek) {
        ctx = EVP_PKEY_CTX_new(kek, NULL);
        if (ctx == NULL)
            goto end;

        if (EVP_PKEY_encrypt_init(ctx) != 1)
            goto end;

        if (EVP_PKEY_encrypt(ctx, NULL, &outlen, key, SMTC_AUTH_KEY_LEN) != 1)
            goto end;

        enc_key = OPENSSL_malloc(outlen);

        if (EVP_PKEY_encrypt(ctx, enc_key, &outlen, key, SMTC_AUTH_KEY_LEN) != 1
            ) {
            BIO_printf(bio_err, "Failed to encrypt auth key\n");
            goto end;
        }

        *auth_key = enc_key;
        enc_key = NULL;
        *auth_key_len = outlen;
    }

    ok = 1;
    OSSL_syslog(LOG_NOTICE, "Setup password success\n");
end:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(enc_key);
    return ok;
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
        || BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_MODULE_SIG,
                      sc->sig) <= 0)
        goto end;

    if (sc->kek && BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_AUTH_KEK,
                              sc->kek) <= 0)
        goto end;

    if (sc->eng && BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_ENGINE,
                              sc->eng) <= 0)
        goto end;

    if (sc->key && BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_AUTH_KEY,
                              sc->key) <= 0)
        goto end;

    if (sc->salt && BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_AUTH_SALT,
                              sc->salt) <= 0)
        goto end;

    if (sc->syslog && BIO_printf(out, "%s = %s\n", OSSL_PROV_SMTC_PARAM_SYSLOG,
                                 sc->syslog) <= 0)
        goto end;

    if (sc->rand_poweron_test
        && BIO_printf(out, "%s = %s\n",
                      OSSL_PROV_SMTC_PARAM_RANDOMNESS_POWERON_TEST,
                      sc->rand_poweron_test) <= 0)
        goto end;

#ifndef OPENSSL_NO_SMTC_DEBUG
    if (sc->verify_sig && BIO_printf(out, "%s = %s\n",
                                     OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_SIG,
                                     sc->verify_sig) <= 0)
        goto end;

    if (sc->verify_pass && BIO_printf(out, "%s = %s\n",
                                     OSSL_PROV_SMTC_PARAM_MODULE_VERIFY_PASS,
                                     sc->verify_pass) <= 0)
        goto end;
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
    int ret = 1, ok = 0, reset = 0, i, install = 0, pass = 0;
    char *prog;
    unsigned char *sig = NULL, *auth_key = NULL;
    int siglen = 0;
    const char *sigfile = NULL, *kek_file = NULL;
    OPTION_CHOICE o;
    unsigned char buf[BUFSIZE];
    int self_test = 0, get_status = 0, status = 0;
    BIO *module_bio = NULL, *fout = NULL, *kek_bio = NULL;
#ifndef OPENSSL_NO_ATF_SLIBCE
    const char *eng_name = "atf_slibce";
#else
    const char *eng_name = NULL;
#endif
    const char *prov_name = "smtc", *sec_name = "smtc_sect";
    const char *conf_file = OPENSSL_info(OPENSSL_INFO_SMTC_MODULE_CONF);
    const char *auth_kek = OPENSSL_info(OPENSSL_INFO_SMTC_AUTH_KEK);
    SMTC_CONF sc;
    CONF *conf = NULL;
    long eline;
    EVP_PKEY *kek = NULL;
    ENGINE *engine = NULL;
    unsigned char auth_salt[SMTC_AUTH_SALT_LEN];
    size_t auth_key_len;
    OSSL_PROVIDER *prov = NULL;
#ifndef OPENSSL_NO_SMTC_DEBUG
    int no_verify = 0, no_auth = 0, no_rand_poweron_test = 0;
#endif

    memset(&sc, 0, sizeof(sc));
    sc.section = sec_name;
    sc.syslog = "1";

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
        case OPT_STATUS:
            get_status = 1;
            break;
        case OPT_RESET:
            reset = 1;
            break;
        case OPT_PROV_NAME:
            prov_name = opt_arg();
            break;
        case OPT_MODULE:
            sc.module_path = opt_arg();
            break;
        case OPT_PASS:
            pass = 1;
            break;
        case OPT_SIGFILE:
            sigfile = opt_arg();
            break;
        case OPT_INSTALL:
            install = 1;
            break;
        case OPT_OUT:
            conf_file = opt_arg();
            break;
        case OPT_KEK:
            kek_file = opt_arg();
            break;
        case OPT_ENGINE:
            eng_name = opt_arg();
            engine = setup_engine(eng_name, 1);
            break;
#ifndef OPENSSL_NO_SMTC_DEBUG
        case OPT_NO_VERIFY:
            no_verify = 1;
            break;
        case OPT_NO_AUTH:
            no_auth = 1;
            break;
        case OPT_NO_RAND_POWERON_TEST:
            no_rand_poweron_test = 1;
            break;
#endif
        }
    }

    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (reset || self_test || get_status) {
        prov = OSSL_PROVIDER_load(app_get0_libctx(), "smtc");
        if (prov == NULL) {
            BIO_printf(bio_err, "Failed to load SMTC provider\n");
            goto end;
        }

        if (reset) {
            if (OSSL_PROVIDER_reset(prov) != 1) {
                BIO_printf(bio_err, "Failed to reset SMTC provider\n");
                goto end;
            }
        }

        if (self_test) {
            if (OSSL_PROVIDER_self_test(prov) != 1) {
                BIO_printf(bio_err, "self test failed\n");
                goto end;
            }

            BIO_printf(bio_out, "self test success\n");
        }

        if (get_status) {
            status = OSSL_PROVIDER_status(prov);

            BIO_printf(bio_out, "status: %sactive\n", status ? "" : "in");
        }

        ok = 1;
        goto end;
    }

    if (install) {
        if (sigfile) {
            BIO *sigbio = BIO_new_file(sigfile, "rb");

            if (sigbio == NULL) {
                BIO_printf(bio_err, "Can't open signature file %s\n", sigfile);
                goto end;
            }
            siglen = bio_to_mem(&sig, 4096, sigbio);
            BIO_free(sigbio);

            if (siglen < 0) {
                BIO_printf(bio_err, "Error reading signature data\n");
                goto end;
            }

            sc.sig = OPENSSL_buf2hexstr(sig, siglen);
            if (sc.sig == NULL)
                goto end;
        }

#ifndef OPENSSL_NO_SMTC_DEBUG
        if (no_verify)
            sc.verify_sig = "0";

        if (no_auth)
            sc.verify_pass = "0";

        if (no_rand_poweron_test)
            sc.rand_poweron_test = "0";
#endif
        sc.eng = eng_name;

        if (sc.module_path == NULL)
            goto opthelp;

        if (kek_file) {
            kek_bio = bio_open_default(kek_file, 'r', FORMAT_TEXT);
            if (kek_bio == NULL) {
                BIO_printf(bio_err, "Failed to open file %s\n", kek_file);
                goto end;
            }

            fout = bio_open_default(auth_kek, 'w', FORMAT_TEXT);
            if (fout == NULL) {
                BIO_printf(bio_err, "Failed to open file %s\n", auth_kek);
                goto end;
            }

            while (BIO_pending(kek_bio) || !BIO_eof(kek_bio)) {
                ret = BIO_read(kek_bio, buf, BUFSIZE);

                if (ret < 0) {
                    BIO_printf(bio_err, "Read Error in '%s'\n", kek_file);
                    ERR_print_errors(bio_err);
                    goto end;
                }
                if (ret == 0)
                    break;

                if (BIO_write(fout, buf, ret) != ret) {
                    BIO_printf(bio_err, "Write Error in '%s'\n", auth_kek);
                    ERR_print_errors(bio_err);
                    goto end;
                }
            }

            sc.kek = auth_kek;
        }

        conf = generate_config_and_load(prov_name, &sc);
        if (conf == NULL)
            goto end;

        fout = bio_open_default(conf_file, 'w', FORMAT_TEXT);
        if (fout == NULL) {
            BIO_printf(bio_err, "Failed to open file\n");
            goto end;
        }
        if (!write_config_smtc_section(fout, &sc))
            goto end;

        BIO_printf(bio_err, "INSTALL PASSED\n");

        ok = 1;
        goto end;
    }

    if (pass) {
        conf = NCONF_new(NCONF_default());

        if (NCONF_load(conf, conf_file, &eline) != 1) {
            BIO_printf(bio_err, "Failed to load config file %s\n", conf_file);
            goto end;
        }

        STACK_OF(CONF_VALUE) *sect = NCONF_get_section(conf, sec_name);
        for (i = 0; i < sk_CONF_VALUE_num(sect); i++) {
            CONF_VALUE *cv = sk_CONF_VALUE_value(sect, i);

            if (strcmp(cv->name, OSSL_PROV_SMTC_PARAM_MODULE_PATH) == 0)
                sc.module_path = cv->value;
            else if (strcmp(cv->name, OSSL_PROV_SMTC_PARAM_MODULE_SIG) == 0)
                sc.sig = cv->value;
            else if (strcmp(cv->name, OSSL_PROV_SMTC_PARAM_AUTH_KEK) == 0)
                sc.kek = cv->value;
            else if (strcmp(cv->name, OSSL_PROV_SMTC_PARAM_ENGINE) == 0)
                sc.eng = cv->value;
            else if (strcmp(cv->name, OSSL_PROV_SMTC_PARAM_SYSLOG) == 0)
                sc.syslog = cv->value;
            else if (strcmp(cv->name,
                            OSSL_PROV_SMTC_PARAM_RANDOMNESS_POWERON_TEST) == 0)
                sc.rand_poweron_test = cv->value;
        }

        if (sc.eng) {
            engine = ENGINE_by_id(sc.eng);
            if (engine == NULL) {
                BIO_printf(bio_err, "Failed to load engine %s\n", sc.eng);
                goto end;
            }
        }

        kek = load_key(sc.kek, FORMAT_PEM, 0, NULL, engine,
                       "key encryption key");
        if (kek == NULL)
            goto end;

        if (!setup_password(kek, auth_salt, &auth_key, &auth_key_len)) {
            BIO_printf(bio_err, "Failed to setup password!\n");
            goto end;
        }

        sc.key = OPENSSL_buf2hexstr(auth_key, auth_key_len);
        if (sc.key == NULL)
            goto end;

        sc.salt = OPENSSL_buf2hexstr(auth_salt, sizeof(auth_salt));
        if (sc.salt == NULL)
            goto end;

        fout = bio_open_default(conf_file, 'w', FORMAT_TEXT);
        if (fout == NULL) {
            BIO_printf(bio_err, "Failed to open file %s\n", conf_file);
            goto end;
        }

        if (!write_config_smtc_section(fout, &sc)) {
            BIO_printf(bio_err, "Failed to write config file %s\n", conf_file);
            goto end;
        }
    }

    ok = 1;
end:
    if (ok == 0) {
        ERR_print_errors(bio_err);
        ret = 1;
    } else {
        /* Exit the process after reset module */
        if (reset)
            ret = -1;
        else
            ret = 0;
    }

cleanup:
    if (install)
        OPENSSL_free(sc.sig);

    if (prov)
        OSSL_PROVIDER_unload(prov);

    release_engine(engine);
    EVP_PKEY_free(kek);
    OPENSSL_free(auth_key);
    OPENSSL_free(sig);
    OPENSSL_free(sc.key);
    OPENSSL_free(sc.salt);
    BIO_free(fout);
    BIO_free(module_bio);
    BIO_free(kek_bio);

    if (conf != NULL) {
        NCONF_free(conf);
        CONF_modules_unload(1);
    }

    return ret;
}
