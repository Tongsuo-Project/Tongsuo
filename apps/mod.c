/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
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
#include <openssl/rand_drbg.h>

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_PASS,
    OPT_RESET,
    OPT_TEST,
    OPT_R_ENUM
} OPTION_CHOICE;

const OPTIONS mod_options[] = {
    {"help", OPT_HELP, '-', "Display this summary"},
    {"pass", OPT_PASS, '-', "Set password"},
    {"reset", OPT_RESET, '-', "Reset crypto module"},
    {"test", OPT_TEST, 's', "Self test random/sm2/sm3/sm4/integrity/all"},
    OPT_R_OPTIONS,
    {NULL}
};

int mod_main(int argc, char **argv)
{
    int ret = 1;
    char *prog;
    OPTION_CHOICE o;
    int set_pass = 0;
    int reset = 0;
    char *arg = NULL;
    int test_random = 0;
    int test_sm2 = 0;
    int test_sm3 = 0;
    int test_sm4 = 0;
    int test_integrity = 0;

    prog = opt_init(argc, argv, mod_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(mod_options);
            ret = 0;
            goto end;
        case OPT_PASS:
            set_pass = 1;
            break;
        case OPT_RESET:
            reset = 1;
            break;
        case OPT_TEST:
            arg = opt_arg();
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        }
    }
    argc = opt_num_rest();
    argv = opt_rest();

    if (set_pass) {
        if (!Tongsuo_setup_password())
            goto end;

        ret = 0;
        goto end;
    }

    if (reset) {
        (void)remove(Tongsuo_get_default_passwd_file());
        /* return EXIT_THE_PROGRAM(-1) */
        ret = -1;
        goto end;
    }

    if (arg) {
        if (!strcasecmp(arg, "random"))
            test_random = 1;
        else if (!strcasecmp(arg, "sm2"))
            test_sm2 = 1;
        else if (!strcasecmp(arg, "sm3"))
            test_sm3 = 1;
        else if (!strcasecmp(arg, "sm4"))
            test_sm4 = 1;
        else if (!strcasecmp(arg, "integrity"))
            test_integrity = 1;
        else if (!strcasecmp(arg, "all"))
            test_random = test_sm2 = test_sm3 = test_sm4 = test_integrity = 1;
        else {
            fprintf(stderr, "Error: invalid test item\n");
            goto end;
        }

        if (test_random)
            Tongsuo_self_test_rand_single();

        if (test_sm2) {
            Tongsuo_self_test_sm2_sign();
            Tongsuo_self_test_sm2_verify();
            Tongsuo_self_test_sm2_encrypt();
            Tongsuo_self_test_sm2_decrypt();
        }

        if (test_sm3)
            Tongsuo_self_test_sm3();

        if (test_sm4) {
            Tongsuo_self_test_sm4_encrypt();
            Tongsuo_self_test_sm4_decrypt();
        }

        if (test_integrity)
            Tongsuo_self_test_integrity();
    }

    ret = 0;
end:
    return ret;
}
