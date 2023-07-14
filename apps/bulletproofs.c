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
    OPT_PPGEN, OPT_PP, OPT_WITNESS, OPT_PROOF, OPT_PROVE, OPT_VERIFY,
    OPT_CURVE_NAME, OPT_GENS_CAPACITY, OPT_PARTY_CAPACITY, OPT_R1CS, OPT_R1CS_CONSTRAINT,
    OPT_IN, OPT_PP_IN, OPT_WITNESS_IN, OPT_OUT, OPT_NOOUT,
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
    {"witness", OPT_WITNESS, '-', "Generate/Display a bulletproofs witness"},
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

    OPT_SECTION("R1CS Witness"),
    {"r1cs", OPT_R1CS, '-', "Switch for R1CS witness."},

    OPT_SECTION("R1CS Prove/Verify"),
    {"r1cs_constraint", OPT_R1CS_CONSTRAINT, 's', "R1CS constraint"},

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input file"},
    {"pp_in", OPT_PP_IN, 's', "Input is a bulletproofs public parameter file used to generate proof or verify proof"},
    {"witness_in", OPT_WITNESS_IN, 's', "Input is a bulletproofs witness file used to generate proof or verify proof"},

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
                                      int party_capacity, const char *out_file,
                                      int text)
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

static int bulletproofs_pub_param_print(const BP_PUB_PARAM *pp,
                                        ZKP_TRANSCRIPT *transcript,
                                        const char *out_file, int text)
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

static int bulletproofs_range_proof_print(const BP_RANGE_PROOF *proof,
                                          const char *out_file, int text)
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

static int bulletproofs_r1cs_proof_print(const BP_R1CS_PROOF *proof,
                                         const char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (proof == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BP_R1CS_PROOF_print(bio, proof, 0))
        goto err;

    if (!noout) {
        if (!PEM_write_bio_BULLETPROOFS_R1CSProof(bio, proof))
            goto err;
    }

    ret = 1;

err:
    BIO_free(bio);
    return ret;
}

static int bulletproofs_long_witness_print(const BP_WITNESS *witness,
                                           const char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (witness == NULL || !(bio = bio_open_owner(out_file, FORMAT_PEM, 1)))
        goto err;

    if (text && !BP_WITNESS_print(bio, witness, 0, 1))
        goto err;

    if (!noout) {
        if (!PEM_write_bio_BULLETPROOFS_LongWitness(bio, witness))
            goto err;
    }

    ret = 1;

err:
    BIO_free(bio);
    return ret;
}

static int bulletproofs_short_witness_print(const BP_WITNESS *witness,
                                            const char *out_file, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (witness == NULL || !(bio = bio_open_default(out_file, 'a', FORMAT_PEM)))
        goto err;

    if (text && !BP_WITNESS_print(bio, witness, 0, 0))
        goto err;

    if (!noout) {
        if (!PEM_write_bio_BULLETPROOFS_ShortWitness(bio, witness))
            goto err;
    }

    ret = 1;

err:
    BIO_free(bio);
    return ret;
}

static int bulletproofs_witness_action(const BP_PUB_PARAM *pp,
                                       ZKP_TRANSCRIPT *transcript, char *argv[],
                                       int argc, int r1cs, const char *out_file,
                                       int text)
{
    int ret = 0, i, value;
    char *name = NULL, *equal_mark, *val;
    BIGNUM *v = NULL;
    BN_CTX *bn_ctx = NULL;
    BP_WITNESS *witness = NULL;

    if (argc == 0) {
        BIO_printf(bio_err, "Error: witness's parameters are not specified.\n");
        goto err;
    }

    if (!(witness = BP_WITNESS_new(pp)))
        goto err;

    if (!(bn_ctx = BN_CTX_new()))
        goto err;

    for (i = 0; i < argc; i++) {
        name = NULL;
        val = argv[i];
        equal_mark = strchr(argv[i], '=');
        if (equal_mark != NULL) {
            *equal_mark = '\0';
            name = argv[i];
            val = equal_mark + 1;
        }
        if (!opt_int(val, &value))
            goto err;

        if (!(v = BN_CTX_get(bn_ctx)))
            goto err;

        BN_set_word(v, value < 0 ? -value : value);
        BN_set_negative(v, value < 1);

        if (r1cs) {
            if (!BP_WITNESS_r1cs_commit(witness, name, v))
                goto err;
        } else {
            if (!BP_WITNESS_commit(witness, name, v))
                goto err;
        }
    }

    ret = bulletproofs_long_witness_print(witness, out_file, text);

err:
    BN_CTX_free(bn_ctx);
    BP_WITNESS_free(witness);
    return ret;
}

static int bulletproofs_range_prove(BP_PUB_PARAM *pp, ZKP_TRANSCRIPT *transcript,
                                    BP_WITNESS *witness, const char *out_file,
                                    int text)
{
    int ret = 0;
    BP_RANGE_CTX *ctx = NULL;
    BP_RANGE_PROOF *proof = NULL;

    if (pp == NULL || transcript == NULL || witness == NULL)
        return ret;

    if (!(ctx = BP_RANGE_CTX_new(pp, witness, transcript)))
        goto err;

    if (!(proof = BP_RANGE_PROOF_new_prove(ctx)))
        goto err;

    ret = bulletproofs_range_proof_print(proof, out_file, text) &&
            bulletproofs_short_witness_print(witness, out_file, text);

err:
    BP_RANGE_PROOF_free(proof);
    BP_RANGE_CTX_free(ctx);
    return ret;
}

static int bulletproofs_range_verify(BP_PUB_PARAM *pp, ZKP_TRANSCRIPT *transcript,
                                     BP_WITNESS *witness, BP_RANGE_PROOF *proof,
                                     const char *out_file)
{
    BIO *bio = NULL;
    int ret = 0, result;
    BP_RANGE_CTX *ctx = NULL;

    if (pp == NULL || witness == NULL || proof == NULL || transcript == NULL
        || !(bio = bio_open_owner(out_file, FORMAT_TEXT, 1)))
        goto err;

    if (!(ctx = BP_RANGE_CTX_new(pp, witness, transcript)))
        goto err;

    result = BP_RANGE_PROOF_verify(ctx, proof);

    if (result)
        BIO_puts(bio, "The proof is valid\n");
    else
        BIO_puts(bio, "The proof is invalid\n");

    ret = 1;

err:
    BP_RANGE_CTX_free(ctx);
    BIO_free(bio);
    return ret;
}

static int bulletproofs_r1cs_prove(BP_PUB_PARAM *pp, ZKP_TRANSCRIPT *transcript,
                                   BP_WITNESS *witness, const char *constraint,
                                   const char *out_file, int text)
{
    int ret = 0;
    BP_R1CS_CTX *ctx = NULL;
    BP_R1CS_PROOF *proof = NULL;

    if (pp == NULL || transcript == NULL || witness == NULL || constraint == NULL)
        return ret;

    if (!(ctx = BP_R1CS_CTX_new(pp, witness, transcript)))
        goto err;

    if (!BP_R1CS_constraint_expression(ctx, constraint, 1))
        goto err;

    if (!(proof = BP_R1CS_PROOF_prove(ctx)))
        goto err;

    ret = bulletproofs_r1cs_proof_print(proof, out_file, text) &&
            bulletproofs_short_witness_print(witness, out_file, text);

err:
    BP_R1CS_PROOF_free(proof);
    BP_R1CS_CTX_free(ctx);
    return ret;
}

static int bulletproofs_r1cs_verify(BP_PUB_PARAM *pp, ZKP_TRANSCRIPT *transcript,
                                    BP_WITNESS *witness, BP_R1CS_PROOF *proof,
                                    const char *constraint, const char *out_file)
{
    BIO *bio = NULL;
    int ret = 0, result;
    BP_R1CS_CTX *ctx = NULL;

    if (pp == NULL || witness == NULL || proof == NULL || constraint == NULL
        || !(bio = bio_open_owner(out_file, FORMAT_TEXT, 1)))
        goto err;

    if (!(ctx = BP_R1CS_CTX_new(pp, witness, transcript)))
        goto err;

    if (!BP_R1CS_constraint_expression(ctx, constraint, 0))
        goto err;

    result = BP_R1CS_PROOF_verify(ctx, proof);

    if (result)
        BIO_puts(bio, "The proof is valid\n");
    else
        BIO_puts(bio, "The proof is invalid\n");

    ret = 1;

err:
    BP_R1CS_CTX_free(ctx);
    BIO_free(bio);
    return ret;
}

int bulletproofs_main(int argc, char **argv)
{
    BIO *in_bio = NULL, *pp_bio = NULL, *witness_bio = NULL;
    ZKP_TRANSCRIPT *transcript = NULL;
    BP_PUB_PARAM *bp_pp = NULL;
    BP_WITNESS *bp_witness = NULL;
    BP_RANGE_PROOF *bp_range_proof = NULL;
    BP_R1CS_PROOF *bp_r1cs_proof = NULL;
    long len;
    int ret = 1, actions = 0, text = 0;
    int gens_capacity = BULLETPROOFS_BITS_DEFAULT, party_capacity = 1, r1cs = 0;
    int ppgen = 0, pp = 0, witness = 0, proof = 0, prove = 0, verify = 0;
    char *pp_file = NULL, *witness_file = NULL, *in_file = NULL, *out_file = NULL;
    char *r1cs_constraint = NULL, *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    const unsigned char *p = NULL;
    char *prog, *curve_name = BULLETPROOFS_CURVE_DEFAULT;
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
        case OPT_WITNESS:
            witness = 1;
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

    actions = ppgen + pp + witness + proof + prove + verify;
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
        case OPT_WITNESS_IN:
            witness_file = opt_arg();
            break;
        case OPT_OUT:
            out_file = opt_arg();
            break;
        case OPT_R1CS:
            r1cs = 1;
            break;
        case OPT_R1CS_CONSTRAINT:
            r1cs_constraint = opt_arg();
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

    if (witness) {
        if (argc > MAX_NUM) {
            BIO_printf(bio_err, "The number of parameters has exceeded %d.\n", MAX_NUM);
            goto opthelp2;
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
        ret = bulletproofs_pub_param_gen(curve_name, gens_capacity,
                                         party_capacity, out_file, text);
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

    if (witness_file) {
        witness_bio = bio_open_default(witness_file, 'r', FORMAT_PEM);
        if (witness_bio == NULL) {
            BIO_printf(bio_err, "File %s failed to read.\n", pp_file);
            goto err;
        }
    }

    if (prove) {
        if (witness_bio == NULL) {
            BIO_printf(bio_err, "No witness_in parameter specified.\n");
            goto err;
        }

        if (!(bp_witness = PEM_read_bio_BULLETPROOFS_LongWitness(witness_bio,
                                                                 NULL, NULL, NULL)))
            goto err;
    }

    if (proof || verify) {
        if (in_bio == NULL) {
            BIO_printf(bio_err, "Error: -in is not specified.\n");
            goto opthelp2;
        }

        while (PEM_read_bio(in_bio, &name, &header, &data, &len)) {
            p = data;
            if (strcmp(name, PEM_STRING_BULLETPROOFS_RANGE_PROOF) == 0) {
                bp_range_proof = d2i_BP_RANGE_PROOF(NULL, &p, len);
            } else if (strcmp(name, PEM_STRING_BULLETPROOFS_R1CS_PROOF) == 0) {
                bp_r1cs_proof = d2i_BP_R1CS_PROOF(NULL, &p, len);
            } else if (strcmp(name, PEM_STRING_BULLETPROOFS_WITNESS) == 0) {
                bp_witness = d2i_short_BP_WITNESS(NULL, &p, len);
            } else {
                BIO_printf(bio_err, "Error: -in file is invalid.\n");
                goto err;
            }
        }

        if (bp_range_proof == NULL && bp_r1cs_proof == NULL) {
            BIO_printf(bio_err, "Error: -in file is invalid.\n");
            goto err;
        }

        if (proof) {
            ret = 0;
            if (bp_range_proof) {
                ret = bulletproofs_range_proof_print(bp_range_proof, out_file, text);
            } else if (bp_r1cs_proof) {
                ret = bulletproofs_r1cs_proof_print(bp_r1cs_proof, out_file, text);
            }

            if (ret && bp_witness)
                ret = bulletproofs_short_witness_print(bp_witness, out_file, text);

            goto err;
        }
    } else if (argc == 0 && witness && in_bio != NULL) {
        bp_witness = PEM_read_bio_BULLETPROOFS_LongWitness(in_bio, NULL, NULL,
                                                           NULL);
        ret = bulletproofs_long_witness_print(bp_witness, out_file, text);
        goto err;
    }

    if (pp_bio) {
        if (!(bp_pp = PEM_read_bio_BULLETPROOFS_PublicParam(pp_bio, NULL,
                                                            NULL, NULL)))
            goto err;
    }

    if (!bp_pp && in_bio) {
        if (!(bp_pp = PEM_read_bio_BULLETPROOFS_PublicParam(in_bio, NULL,
                                                            NULL, NULL)))
            goto err;
    }

    if (bp_pp == NULL) {
        BIO_printf(bio_err, "Error: -pp_in is not specified.\n");
        goto opthelp2;
    }

    if (!(transcript = ZKP_TRANSCRIPT_new(ZKP_TRANSCRIPT_METHOD_sha256(), "bulletproofs_app")))
        goto err;

    if (pp) {
        ret = bulletproofs_pub_param_print(bp_pp, transcript, out_file, text);
    } else if (witness) {
        ret = bulletproofs_witness_action(bp_pp, transcript, argv, argc, r1cs, out_file, text);
    } else if (prove) {
        if (r1cs_constraint) {
            ret = bulletproofs_r1cs_prove(bp_pp, transcript, bp_witness, r1cs_constraint, out_file, text);
        } else {
            ret = bulletproofs_range_prove(bp_pp, transcript, bp_witness, out_file, text);
        }
    } else if (verify) {
        if (r1cs_constraint) {
            ret = bulletproofs_r1cs_verify(bp_pp, transcript, bp_witness, bp_r1cs_proof, r1cs_constraint, out_file);
        } else {
            ret = bulletproofs_range_verify(bp_pp, transcript, bp_witness, bp_range_proof, out_file);
        }
    }

 err:
    ret = ret ? 0 : 1;
    BIO_free_all(in_bio);
    BIO_free_all(pp_bio);
    ZKP_TRANSCRIPT_free(transcript);
    BP_RANGE_PROOF_free(bp_range_proof);
    BP_R1CS_PROOF_free(bp_r1cs_proof);
    BP_PUB_PARAM_free(bp_pp);
    if (ret != 0) {
        BIO_printf(bio_err, "May be extra arguments error, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}
