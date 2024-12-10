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
#include "internal/cryptlib.h"
#include "../crypto/rand/rand_local.h"


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
    {"test", OPT_TEST, 's', "Self test, include random/sm2/sm3/sm4/all"},
    OPT_R_OPTIONS,
    {NULL}
};

int mod_main(int argc, char **argv)
{
    int ret = 1;
    char *prog;
    OPTION_CHOICE o;
    BIO *out = NULL;
    int set_pass = 0;
    int reset = 0;
    char *arg = NULL;
    int test_random = 0;
    int test_sm2 = 0;
    int test_sm3 = 0;
    int test_sm4 = 0;

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
        if (!scm_setup_password())
            goto end;

        ret = 0;
        goto end;
    }

    if (reset) {
        (void)remove(OPENSSL_get_default_passwd_file());
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
        else if (!strcasecmp(arg, "all"))
            test_random = test_sm2 = test_sm3 = test_sm4 = 1;
        else {
            fprintf(stderr, "Error: invalid test item\n");
            goto end;
        }

        if (test_random)
            scm_self_test_sm3_drbg();

        if (test_sm2) {
            scm_self_test_sm2_sign();
            scm_self_test_sm2_verify();
        }

        if (test_sm3)
            scm_self_test_sm3();

        if (test_sm4) {
            scm_self_test_sm4_encrypt();
            scm_self_test_sm4_decrypt();
        }
    }

    ret = 0;
end:
    BIO_free(out);
    return ret;
}
