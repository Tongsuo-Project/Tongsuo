/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/opensslconf.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/bulletproofs.h>
#include <openssl/ec.h>
#include <crypto/ec.h>
#include <internal/cryptlib.h>

#define MAX_NUM                             64
#define BULLETPROOFS_BITS_DEFAULT           32
#define BULLETPROOFS_AGG_MAX_DEFAULT        1
#define BULLETPROOFS_CURVE_DEFAULT          "secp256k1"
#define _STR(x)                             #x
#define STR(x)                              _STR(x)

static int verbose = 0, noout = 0;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_PPGEN, OPT_PP, OPT_CURVE_NAME, OPT_BITS, OPT_AGG_MAX,
    OPT_PROOF, OPT_PROVE, OPT_VERIFY,
    OPT_IN, OPT_PP_IN, OPT_OUT, OPT_NOOUT,
    OPT_TEXT, OPT_VERBOSE,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS bulletproofs_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [action options] [input/output options] [arg1] [arg2]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Action"),
    {"ppgen", OPT_PPGEN, '-', "Generate a bulletproofs public parameter, usage: -ppgen -curve_name secp256k1 -bits 32 -agg_max 8"},
    {"pp", OPT_PP, '-', "Display/Parse a bulletproofs public parameter"},
    {"proof", OPT_PROOF, '-', "Display/Parse a bulletproofs proof"},
    {"prove", OPT_PROVE, '-', "Bulletproofs prove operation: proof of generating at least one number with bulletproofs public parameters, "
                               "usage: -prove secret1 secret2 ... secret64, secretx is an example number"},
    {"verify", OPT_VERIFY, '-', "Bulletproofs verify operation: verifies that the supplied proof is a valid proof, "
                                "usage: -verify -in file, file is the proof file path"},

    OPT_SECTION("PPGEN"),
    {"curve_name", OPT_CURVE_NAME, 's', "The curve name of the bulletproofs public parameter, default: " STR(BULLETPROOFS_CURVE_DEFAULT) ""},
    {"bits", OPT_BITS, 'N', "The range bits that support verification, default: " STR(BULLETPROOFS_BITS_DEFAULT) ""},
    {"agg_max", OPT_AGG_MAX, 'N', "The number of the aggregate range proofs, default: " STR(BULLETPROOFS_AGG_MAX_DEFAULT) ""},

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input file"},
    {"pp_in", OPT_PP_IN, 's', "Input is a bulletproofs public parameter file used to generate proof or verify proof"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output the bulletproofs key to specified file"},
    {"noout", OPT_NOOUT, '-', "Don't print bulletproofs key out"},
    {"text", OPT_TEXT, '-', "Print the bulletproofs key in text"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output"},

    OPT_PARAMETERS(),
    {"arg...", 0, 0, "Additional parameters for bulletproofs operations"},

    {NULL}
};

static int bulletproofs_pub_param_gen(int curve_id, int bits, int agg_max,
                                      char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;
    BULLET_PROOF_PUB_PARAM *pp = NULL;

    if (!(pp = BULLET_PROOF_PUB_PARAM_new(curve_id, bits, agg_max)))
        goto err;

    if (!(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BULLET_PROOF_PUB_PARAM_print(bio, pp, 0))
        goto err;

    if (!PEM_write_bio_BULLETPROOFS_PublicParam(bio, pp))
        goto err;

    ret = 1;

err:
    BIO_free(bio);
    BULLET_PROOF_PUB_PARAM_free(pp);
    return ret;
}

static int bulletproofs_pub_param_print(BULLET_PROOF_PUB_PARAM *pp,
                                        char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (pp == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BULLET_PROOF_PUB_PARAM_print(bio, pp, 0))
        goto err;

    if (!noout) {
        if (!PEM_write_bio_BULLETPROOFS_PublicParam(bio, pp))
            goto err;
    }

    ret = 1;

err:
    BIO_free(bio);
    return ret;
}

static int bulletproofs_proof_print(BULLET_PROOF *proof, char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (proof == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BULLET_PROOF_print(bio, proof, 0))
        goto err;

    if (!noout) {
        if (!PEM_write_bio_BULLETPROOFS_Proof(bio, proof))
            goto err;
    }

    ret = 1;

err:
    BIO_free(bio);
    return ret;
}

static int bulletproofs_prove(BULLET_PROOF_PUB_PARAM *pp, int64_t secrets[],
                              size_t len, char *out_file, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    BULLET_PROOF_CTX *ctx = NULL;
    BULLET_PROOF_WITNESS *witness = NULL;
    BULLET_PROOF *proof = NULL;

    if (pp == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (!(ctx = BULLET_PROOF_CTX_new(pp, NULL)))
        goto err;

    if (!(witness = BULLET_PROOF_WITNESS_new(ctx, secrets, len)))
        goto err;

    if (!(proof = BULLET_PROOF_new(ctx)))
        goto err;

    if (!BULLET_PROOF_prove(ctx, witness, proof))
        goto err;

    ret = bulletproofs_proof_print(proof, out_file, text);
err:
    BULLET_PROOF_free(proof);
    BULLET_PROOF_WITNESS_free(witness);
    BULLET_PROOF_CTX_free(ctx);
    BIO_free(bio);
    return ret;
}

static int bulletproofs_verify(BULLET_PROOF_PUB_PARAM *pp, BULLET_PROOF *proof,
                               char *out_file)
{
    BIO *bio = NULL;
    int ret = 0;
    BULLET_PROOF_CTX *ctx = NULL;

    if (pp == NULL || proof == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (!(ctx = BULLET_PROOF_CTX_new(pp, NULL)))
        goto err;

    if (BULLET_PROOF_verify(ctx, proof))
        BIO_puts(bio, "The proof is valid\n");
    else
        BIO_puts(bio, "The proof is invalid\n");

    ret = 1;

err:
    BULLET_PROOF_CTX_free(ctx);
    BIO_free(bio);
    return ret;
}

int bulletproofs_main(int argc, char **argv)
{
    BIO *pp_bio = NULL, *in_bio = NULL;
    BULLET_PROOF_PUB_PARAM *bp_pp = NULL;
    BULLET_PROOF *bp_proof = NULL;
    int ret = 1, actions = 0, text = 0, secret, i, curve_id;
    int bits = BULLETPROOFS_BITS_DEFAULT, agg_max = BULLETPROOFS_AGG_MAX_DEFAULT;
    int ppgen = 0, pp = 0, proof = 0, prove = 0, verify = 0;
    int64_t secrets[MAX_NUM];
    char *pp_file = NULL, *in_file = NULL, *out_file = NULL;
    char *arg, *prog, *curve_name = BULLETPROOFS_CURVE_DEFAULT;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, bulletproofs_options);
    if ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp1:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto err;
        case OPT_HELP:
            ret = 0;
            opt_help(bulletproofs_options);
            goto err;
        case OPT_PPGEN:
            ppgen = 1;
            break;
        case OPT_PP:
            pp = 1;
            break;
        case OPT_PROOF:
            proof = 1;
            break;
        case OPT_PROVE:
            prove = 1;
            break;
        case OPT_VERIFY:
            verify = 1;
            break;
        default:
            goto opthelp1;
        }
    }

    actions = ppgen + pp + proof + prove + verify;
    if (actions == 0) {
        BIO_printf(bio_err, "No action parameter specified.\n");
        goto opthelp1;
    } else if (actions != 1) {
        BIO_printf(bio_err, "Only one action parameter must be specified.\n");
        goto opthelp1;
    }

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp2:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto err;
        case OPT_HELP:
            ret = 0;
            opt_help(bulletproofs_options);
            goto err;
        case OPT_CURVE_NAME:
            curve_name = opt_arg();
            break;
        case OPT_BITS:
            bits = opt_int_arg();
            break;
        case OPT_AGG_MAX:
            agg_max = opt_int_arg();
            break;
        case OPT_IN:
            in_file = opt_arg();
            break;
        case OPT_PP_IN:
            pp_file = opt_arg();
            break;
        case OPT_OUT:
            out_file = opt_arg();
            break;
        case OPT_NOOUT:
            noout = 1;
            break;
        case OPT_TEXT:
            text = 1;
            break;
        case OPT_VERBOSE:
            verbose = 1;
            break;
        default:
            goto opthelp2;
            break;
        }
    }

    /* One optional argument, the bitsize. */
    argc = opt_num_rest();
    argv = opt_rest();

    if (prove) {
        if (argc > MAX_NUM) {
            BIO_printf(bio_err, "The number of parameters has exceeded %d.\n", MAX_NUM);
            goto opthelp2;
        }

        for (i = 0; i < argc; i++) {
            arg = argv[i];
            if (*arg == '_')
                arg++;

            if (!opt_int(arg, &secret))
                goto err;

            if (*argv[i] == '_')
                secret = -secret;

            secrets[i] = (int64_t)secret;
        }
    } else {
        if (argc > 0) {
            BIO_printf(bio_err, "Extra arguments given.\n");
            goto opthelp2;
        }
    }

    if (!app_RAND_load())
        goto err;

    if (ppgen) {
        if ((curve_id = ossl_ec_curve_name2nid(curve_name)) == NID_undef) {
            BIO_printf(bio_err, "Error: -curve_name is invalid.\n");
            goto opthelp2;
        }

        ret = bulletproofs_pub_param_gen(curve_id, bits, agg_max, out_file, text);
        goto err;
    }

    if (in_file) {
        in_bio = bio_open_default(in_file, 'r', FORMAT_PEM);
        if (in_bio == NULL) {
            BIO_printf(bio_err, "File %s failed to read.\n", in_file);
            goto err;
        }
    }

    if (pp_file) {
        pp_bio = bio_open_default(pp_file, 'r', FORMAT_PEM);
        if (pp_bio == NULL) {
            BIO_printf(bio_err, "File %s failed to read.\n", pp_file);
            goto err;
        }
    }

    if (proof || verify) {
        if (in_bio == NULL) {
            BIO_printf(bio_err, "Error: -in is not specified.\n");
            goto opthelp2;
        }

        if (!(bp_proof = PEM_read_bio_BULLETPROOFS_Proof(in_bio, NULL, NULL, NULL)))
            goto err;

        if (proof && bp_proof) {
            ret = bulletproofs_proof_print(bp_proof, out_file, text);
            goto err;
        }
    }

    if (pp_bio) {
        if (!(bp_pp = PEM_read_bio_BULLETPROOFS_PublicParam(pp_bio, NULL, NULL, NULL)))
            goto err;
    }

    if (!bp_pp && in_bio) {
        if (!(bp_pp = PEM_read_bio_BULLETPROOFS_PublicParam(in_bio, NULL, NULL, NULL)))
            goto err;
    }

    if (bp_pp == NULL) {
        BIO_printf(bio_err, "Error: -pp_in is not specified.\n");
        goto opthelp2;
    }

    if (pp)
        ret = bulletproofs_pub_param_print(bp_pp, out_file, text);
    else if (prove)
        ret = bulletproofs_prove(bp_pp, secrets, argc, out_file, text);
    else if (verify)
        ret = bulletproofs_verify(bp_pp, bp_proof, out_file);

 err:
    ret = ret ? 0 : 1;
    BIO_free_all(in_bio);
    BIO_free_all(pp_bio);
    BULLET_PROOF_free(bp_proof);
    BULLET_PROOF_PUB_PARAM_free(bp_pp);
    if (ret != 0) {
        BIO_printf(bio_err, "May be extra arguments error, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}
