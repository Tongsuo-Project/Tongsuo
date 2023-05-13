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
    OPT_PPGEN, OPT_PP, OPT_CURVE_NAME, OPT_GENS_CAPACITY, OPT_PARTY_CAPACITY,
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
    {"ppgen", OPT_PPGEN, '-', "Generate a bulletproofs public parameter, usage: -ppgen -curve_name secp256k1 -gens_capacity 32 -party_capacity 8"},
    {"pp", OPT_PP, '-', "Display/Parse a bulletproofs public parameter"},
    {"proof", OPT_PROOF, '-', "Display/Parse a bulletproofs proof"},
    {"prove", OPT_PROVE, '-', "Bulletproofs prove operation: proof of generating at least one number with bulletproofs public parameters, "
                               "usage: -prove secret1 secret2 ... secret64, secretx is an example number"},
    {"verify", OPT_VERIFY, '-', "Bulletproofs verify operation: verifies that the supplied proof is a valid proof, "
                                "usage: -verify -in file, file is the proof file path"},

    OPT_SECTION("PPGEN"),
    {"curve_name", OPT_CURVE_NAME, 's', "The curve name of the bulletproofs public parameter, default: " STR(BULLETPROOFS_CURVE_DEFAULT) ""},
    {"gens_capacity", OPT_GENS_CAPACITY, 'N', "The number of generators to precompute for each party. "
                                              "For range_proof, it is the maximum bitsize of the range_proof,"
                                              "maximum value is 64. For r1cs_proof, the capacity must be greater "
                                              "than the number of multipliers, rounded up to the next power of two."
                                              ", default: " STR(BULLETPROOFS_GENS_CAPACITY_DEFAULT) ""},
    {"party_capacity", OPT_PARTY_CAPACITY, 'N', "The maximum number of parties that can produce on aggregated range proof."
                                                "For r1cs_proof, set to 1. default: 1"},

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input file"},
    {"pp_in", OPT_PP_IN, 's', "Input is a bulletproofs public parameter file used to generate proof or verify proof"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output the bulletproofs key to specified file"},
    {"noout", OPT_NOOUT, '-', "Don't print bulletproofs action result"},
    {"text", OPT_TEXT, '-', "Print the bulletproofs key in text"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output"},

    OPT_PARAMETERS(),
    {"arg...", 0, 0, "Additional parameters for bulletproofs operations"},

    {NULL}
};

static int bulletproofs_pub_param_gen(const char *curve_name, int gens_capacity,
                                      int party_capacity, char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;
    BP_PUB_PARAM *pp = NULL;

    if (!(pp = BP_PUB_PARAM_new_by_curve_name(curve_name, gens_capacity, party_capacity)))
        goto err;

    if (!(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;
if (text && !BP_PUB_PARAM_print(bio, pp, 0))
        goto err;

    if (!PEM_write_bio_BULLETPROOFS_PublicParam(bio, pp))
        goto err;

    ret = 1;

err:
    BIO_free(bio);
    BP_PUB_PARAM_free(pp);
    return ret;
}

static int bulletproofs_pub_param_print(BP_PUB_PARAM *pp, char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (pp == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BP_PUB_PARAM_print(bio, pp, 0))
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

static int bulletproofs_range_proof_print(BP_RANGE_PROOF *proof, char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (proof == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BP_RANGE_PROOF_print(bio, proof, 0))
        goto err;

    if (!noout) {
        if (!PEM_write_bio_BULLETPROOFS_RangeProof(bio, proof))
            goto err;
    }

    ret = 1;

err:
    BIO_free(bio);
    return ret;
}

static int bulletproofs_range_prove(BP_PUB_PARAM *pp, int64_t secrets[], int len,
                                    char *out_file, int text)
{
    int ret = 0, i;
    BP_TRANSCRIPT *transcript = NULL;
    BP_WITNESS *witness = NULL;
    BP_RANGE_CTX *ctx = NULL;
    BP_RANGE_PROOF *proof = NULL;
    BIGNUM *v;

    if (pp == NULL)
        return ret;

    if (!(v = BN_new()))
        return ret;

    if (!(transcript = BP_TRANSCRIPT_new(BP_TRANSCRIPT_METHOD_sha256(),
                                         "bulletproofs_app")))
        goto err;

    if (!(witness = BP_WITNESS_new(pp)))
        goto err;

    for (i = 0; i < len; i++) {
        if (!BN_lebin2bn((const unsigned char *)&secrets[i], sizeof(secrets[i]), v))
            goto err;

        if (!BP_WITNESS_commit(witness, NULL, v))
            goto err;
    }

    if (!(ctx = BP_RANGE_CTX_new(pp, witness, transcript)))
        goto err;

    if (!(proof = BP_RANGE_PROOF_new_prove(ctx)))
        goto err;

    ret = bulletproofs_range_proof_print(proof, out_file, text);
err:
    BP_RANGE_PROOF_free(proof);
    BP_RANGE_CTX_free(ctx);
    BP_WITNESS_free(witness);
    BP_TRANSCRIPT_free(transcript);
    BN_free(v);
    return ret;
}

static int bulletproofs_range_verify(BP_PUB_PARAM *pp, BP_RANGE_PROOF *proof,
                                     BP_WITNESS *witness, char *out_file)
{
    BIO *bio = NULL;
    int ret = 0;
    BP_TRANSCRIPT *transcript = NULL;
    BP_RANGE_CTX *ctx = NULL;

    if (pp == NULL || proof == NULL || witness == NULL || !(bio = bio_open_owner(out_file, FORMAT_TEXT, 1)))
        goto err;

    if (!(transcript = BP_TRANSCRIPT_new(BP_TRANSCRIPT_METHOD_sha256(),
                                         "bulletproofs_app")))
        goto err;

    if (!(ctx = BP_RANGE_CTX_new(pp, witness, transcript)))
        goto err;

    if (BP_RANGE_PROOF_verify(ctx, proof))
        BIO_puts(bio, "The proof is valid\n");
    else
        BIO_puts(bio, "The proof is invalid\n");

    ret = 1;

err:
    BP_RANGE_CTX_free(ctx);
    BP_TRANSCRIPT_free(transcript);
    BIO_free(bio);
    return ret;
}

int bulletproofs_main(int argc, char **argv)
{
    BIO *pp_bio = NULL, *in_bio = NULL;
    BP_PUB_PARAM *bp_pp = NULL;
    BP_WITNESS *bp_witness = NULL;
    BP_RANGE_PROOF *bp_proof = NULL;
    int ret = 1, actions = 0, text = 0, secret, i;
    int gens_capacity = BULLETPROOFS_BITS_DEFAULT, party_capacity = 1;
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
        case OPT_GENS_CAPACITY:
            gens_capacity = opt_int_arg();
            break;
        case OPT_PARTY_CAPACITY:
            party_capacity = opt_int_arg();
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
        ret = bulletproofs_pub_param_gen(curve_name, gens_capacity, party_capacity, out_file, text);
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

        if (!(bp_proof = PEM_read_bio_BULLETPROOFS_RangeProof(in_bio, NULL, NULL, NULL)))
            goto err;

        if (proof && bp_proof) {
            ret = bulletproofs_range_proof_print(bp_proof, out_file, text);
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
        ret = bulletproofs_range_prove(bp_pp, secrets, argc, out_file, text);
    else if (verify)
        ret = bulletproofs_range_verify(bp_pp, bp_proof, bp_witness, out_file);

 err:
    ret = ret ? 0 : 1;
    BIO_free_all(in_bio);
    BIO_free_all(pp_bio);
    BP_RANGE_PROOF_free(bp_proof);
    BP_PUB_PARAM_free(bp_pp);
    if (ret != 0) {
        BIO_printf(bio_err, "May be extra arguments error, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}
