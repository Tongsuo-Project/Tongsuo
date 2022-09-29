/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
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
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/paillier.h>
#include <internal/cryptlib.h>

static int verbose = 0, noout = 0;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_KEYGEN, OPT_PUBGEN,
    OPT_KEY, OPT_PUB,
    OPT_ENCRYPT, OPT_DECRYPT, OPT_ADD, OPT_ADD_PLAIN, OPT_SUB, OPT_MUL,
    OPT_IN, OPT_KEY_IN,
    OPT_OUT, OPT_NOOUT,
    OPT_TEXT, OPT_VERBOSE,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS paillier_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [action options] [input/output options] [arg1] [arg2]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Action"),
    {"keygen", OPT_KEYGEN, '-', "Generate a paillier private key"},
    {"pubgen", OPT_PUBGEN, '-', "Generate a paillier public key"},
    {"key", OPT_KEY, '-', "Display/Parse a paillier private key"},
    {"pub", OPT_PUB, '-', "Display/Parse a paillier public key"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt a number with the paillier public key, usage: -encrypt 99, 99 is an example number"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt a ciphertext using the paillier private key, usage: -decrypt c1, c1 is an example ciphertext"},
    {"add", OPT_ADD, '-', "Paillier homomorphic addition: add two ciphertexts, usage: -add c1 c2, c1 and c2 are tow example ciphertexts, result: E(c1) + E(c2)"},
    {"add_plain", OPT_ADD_PLAIN, '-', "Paillier homomorphic addition: add a ciphertext to a plaintext, usage: -add_plain c1 99, c1 is an example ciphertext, 99 is an example number, result: E(c1) + 99"},
    {"sub", OPT_SUB, '-', "Paillier homomorphic subtraction: sub two ciphertexts, usage: -sub c1 c2, c1 and c2 are tow example ciphertexts, result: E(c1) - E(c2)"},
    {"mul", OPT_MUL, '-', "Paillier homomorphic scalar multiplication: multiply a ciphertext by a known plaintext, usage: -mul c1 99, c1 is an example ciphertext, 99 is an example number, result: E(c1) * 99"},

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input file"},
    {"key_in", OPT_KEY_IN, 's', "Input is a paillier private key used to generate public key"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output the paillier key to specified file"},
    {"noout", OPT_NOOUT, '-', "Don't print paillier key out"},
    {"text", OPT_TEXT, '-', "Print the paillier key in text"},
    {"verbose", OPT_VERBOSE, '-', "Verbose output"},

    OPT_PARAMETERS(),
    {"arg1", 0, 0, "Argument for encryption/decryption, or the first argument of a homomorphic operation"},
    {"arg2", 0, 0, "The second argument of a homomorphic operation"},

    {NULL}
};

static int paillier_buf2hexstr_print(BIO *bio, unsigned char *buf, size_t size,
                                     char *field, int text)
{
    unsigned char *out = NULL;
    size_t out_n;
    BIO_printf(bio, "%s: ", field);

    if (text) {
        BIO_puts(bio, "\n");
        BIO_indent(bio, 4, 4);
        BIO_hex_string(bio, 4, 16, buf, size);
    } else {
        out_n = size * 2 + 1;
        if (!(out = OPENSSL_zalloc(out_n))
            || !OPENSSL_buf2hexstr_ex((char *)out, out_n, NULL, buf, size, '\0')) {
            OPENSSL_free(out);
            return 0;
        }
        BIO_printf(bio, "%s", out);
        OPENSSL_free(out);
    }

    BIO_puts(bio, "\n");
    return 1;
}

static int paillier_ciphertext_print(BIO *bio, PAILLIER_CTX *ctx,
                                     PAILLIER_CIPHERTEXT *c,
                                     char *field, int text)
{
    int ret = 0;
    size_t size;
    unsigned char *buf = NULL;

    size = PAILLIER_CIPHERTEXT_encode(ctx, NULL, 0, c, 0);
    if (!(buf = OPENSSL_zalloc(size)))
        goto end;

    if (!PAILLIER_CIPHERTEXT_encode(ctx, buf, size, c, 0))
        goto end;

    ret = paillier_buf2hexstr_print(bio, buf, size, field, text);

end:
    OPENSSL_free(buf);
    return ret;
}

static int paillier_keygen(char *outfile, int text)
{
    int ret = 0;
    BIO *bio = NULL;
    PAILLIER_KEY *pail_key = NULL;

    pail_key = PAILLIER_KEY_new();
    if (pail_key == NULL
        || !PAILLIER_KEY_generate_key(pail_key, 255))
        goto end;

    if (!(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    if (text && !PAILLIER_KEY_print(bio, pail_key, 0))
        goto end;

    if (!PEM_write_bio_PAILLIER_PrivateKey(bio, pail_key))
        goto end;

    ret = 1;

end:
    BIO_free(bio);
    PAILLIER_KEY_free(pail_key);
    return ret;
}

static int paillier_pubgen(PAILLIER_KEY *key, char *outfile, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (key == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    if (text && !PAILLIER_KEY_print(bio, key, 0))
        goto end;

    if (!PEM_write_bio_PAILLIER_PublicKey(bio, key))
        goto end;

    ret = 1;

end:
    BIO_free(bio);
    return ret;
}

static int paillier_print(PAILLIER_KEY *key, char *outfile, int text)
{
    int ret = 0;
    BIO *bio = NULL;

    if (key == NULL
        || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    if (text && !PAILLIER_KEY_print(bio, key, 0))
        goto end;

    if (!noout) {
        BIO_printf(bio_err, "writing paillier key\n");

        if (PAILLIER_KEY_type(key) == PAILLIER_KEY_TYPE_PRIVATE) {
            if (!PEM_write_bio_PAILLIER_PrivateKey(bio, key))
                goto end;
        } else if (!PEM_write_bio_PAILLIER_PublicKey(bio, key))
            goto end;
    }

    ret = 1;

end:
    BIO_free(bio);
    return ret;
}

static int paillier_encrypt(PAILLIER_CTX *ctx, int plain, char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    PAILLIER_CIPHERTEXT *r = NULL;

    if (ctx == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    if (!(r = PAILLIER_CIPHERTEXT_new(ctx)))
        goto end;

    if (!PAILLIER_encrypt(ctx, r, plain))
        goto end;

    BIO_puts(bio, "paillier encrypt\n");
    BIO_printf(bio, "plaintext: %d\n", plain);

    ret = paillier_ciphertext_print(bio, ctx, r, "ciphertext", text);

end:
    PAILLIER_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int paillier_decrypt(PAILLIER_CTX *ctx, char *ciphertext,
                            char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    unsigned char *buf = NULL;
    size_t buf_n, len;
    int32_t r = 0;
    PAILLIER_CIPHERTEXT *c = NULL;

    if (ctx == NULL || ciphertext == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    buf_n = strlen(ciphertext) / 2;
    if (buf_n < 1)
        goto end;

    if (!(buf = OPENSSL_zalloc(buf_n))
        || !OPENSSL_hexstr2buf_ex(buf, buf_n, &len, ciphertext, '\0')
        || !(c = PAILLIER_CIPHERTEXT_new(ctx))
        || !PAILLIER_CIPHERTEXT_decode(ctx, c, buf, len)
        || !PAILLIER_decrypt(ctx, &r, c))
        goto end;

    BIO_puts(bio, "paillier decrypt\n");

    ret = paillier_buf2hexstr_print(bio, buf, len, "ciphertext", text);

    BIO_printf(bio, "plaintext: %d\n", r);

end:
    OPENSSL_free(buf);
    PAILLIER_CIPHERTEXT_free(c);
    BIO_free(bio);
    return ret;
}

static int paillier_add(PAILLIER_CTX *ctx, char *in1, char *in2,
                        char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, buf2_n, len1, len2;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (ctx == NULL || in1 == NULL || in2 == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    buf1_n = strlen(in1) / 2;
    buf2_n = strlen(in2) / 2;
    if (buf1_n <= 1 || buf2_n <= 1)
        goto end;

    if (!(buf1 = OPENSSL_zalloc(buf1_n))
        || !(buf2 = OPENSSL_zalloc(buf2_n))
        || !OPENSSL_hexstr2buf_ex(buf1, buf1_n, &len1, in1, '\0')
        || !OPENSSL_hexstr2buf_ex(buf2, buf2_n, &len2, in2, '\0')
        || !(r = PAILLIER_CIPHERTEXT_new(ctx))
        || !(c1 = PAILLIER_CIPHERTEXT_new(ctx))
        || !(c2 = PAILLIER_CIPHERTEXT_new(ctx))
        || !PAILLIER_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !PAILLIER_CIPHERTEXT_decode(ctx, c2, buf2, len2)
        || !PAILLIER_add(ctx, r, c1, c2))
        goto end;

    BIO_puts(bio, "paillier add (result = c1 + c2)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "c2: %s\n", in2);

    ret = paillier_ciphertext_print(bio, ctx, r, "result", text);

end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    PAILLIER_CIPHERTEXT_free(c1);
    PAILLIER_CIPHERTEXT_free(c2);
    PAILLIER_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int paillier_add_plain(PAILLIER_CTX *ctx, char *in1, int32_t plain,
                              char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, len1;
    unsigned char *buf1 = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c1 = NULL;

    if (ctx == NULL || in1 == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    buf1_n = strlen(in1) / 2;
    if (buf1_n <= 1)
        goto end;

    if (!(buf1 = OPENSSL_zalloc(buf1_n))
        || !OPENSSL_hexstr2buf_ex(buf1, buf1_n, &len1, in1, '\0')
        || !(r = PAILLIER_CIPHERTEXT_new(ctx))
        || !(c1 = PAILLIER_CIPHERTEXT_new(ctx))
        || !PAILLIER_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !PAILLIER_add_plain(ctx, r, c1, plain))
        goto end;

    BIO_puts(bio, "paillier addition (result = c1 + plaintext)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "plaintext: %d\n", plain);

    ret = paillier_ciphertext_print(bio, ctx, r, "result", text);

end:
    OPENSSL_free(buf1);
    PAILLIER_CIPHERTEXT_free(c1);
    PAILLIER_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int paillier_sub(PAILLIER_CTX *ctx, char *in1, char *in2,
                        char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, buf2_n, len1, len2;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

    if (ctx == NULL || in1 == NULL || in2 == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    buf1_n = strlen(in1) / 2;
    buf2_n = strlen(in2) / 2;
    if (buf1_n <= 1 || buf2_n <= 1)
        goto end;

    if (!(buf1 = OPENSSL_zalloc(buf1_n))
        || !(buf2 = OPENSSL_zalloc(buf2_n))
        || !OPENSSL_hexstr2buf_ex(buf1, buf1_n, &len1, in1, '\0')
        || !OPENSSL_hexstr2buf_ex(buf2, buf2_n, &len2, in2, '\0')
        || !(r = PAILLIER_CIPHERTEXT_new(ctx))
        || !(c1 = PAILLIER_CIPHERTEXT_new(ctx))
        || !(c2 = PAILLIER_CIPHERTEXT_new(ctx))
        || !PAILLIER_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !PAILLIER_CIPHERTEXT_decode(ctx, c2, buf2, len2)
        || !PAILLIER_sub(ctx, r, c1, c2))
        goto end;

    BIO_puts(bio, "paillier subtraction (result = c1 - c2)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "c2: %s\n", in2);

    ret = paillier_ciphertext_print(bio, ctx, r, "result", text);

    ret = 1;

end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    PAILLIER_CIPHERTEXT_free(c1);
    PAILLIER_CIPHERTEXT_free(c2);
    PAILLIER_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int paillier_mul(PAILLIER_CTX *ctx, char *in1, int32_t plain,
                        char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, len1;
    unsigned char *buf1 = NULL;
    PAILLIER_CIPHERTEXT *r = NULL, *c1 = NULL;

    if (ctx == NULL || in1 == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    buf1_n = strlen(in1) / 2;
    if (buf1_n <= 1)
        goto end;

    if (!(buf1 = OPENSSL_zalloc(buf1_n))
        || !OPENSSL_hexstr2buf_ex(buf1, buf1_n, &len1, in1, '\0')
        || !(r = PAILLIER_CIPHERTEXT_new(ctx))
        || !(c1 = PAILLIER_CIPHERTEXT_new(ctx))
        || !PAILLIER_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !PAILLIER_mul(ctx, r, c1, plain))
        goto end;

    BIO_puts(bio, "paillier scalar multiplication (result = c1 * plaintext)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "plaintext: %d\n", plain);

    ret = paillier_ciphertext_print(bio, ctx, r, "result", text);

    ret = 1;

end:
    OPENSSL_free(buf1);
    PAILLIER_CIPHERTEXT_free(c1);
    PAILLIER_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

int paillier_main(int argc, char **argv)
{
    BIO *in = NULL;
    PAILLIER_KEY *pail_key = NULL;
    PAILLIER_CTX *ctx = NULL;
    int ret = 1, action_sum = 0, text = 0;
    int keygen = 0, pubgen = 0, key = 0, pub = 0;
    int encrypt = 0, decrypt = 0, add = 0, add_plain = 0, sub = 0, mul = 0;
    int plain = 0;
    char *infile = NULL, *outfile = NULL;
    char *prog;
    char *arg1 = NULL, *arg2 = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, paillier_options);
    if ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp1:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(paillier_options);
            goto end;
        case OPT_KEYGEN:
            keygen = 1;
            break;
        case OPT_PUBGEN:
            pubgen = 1;
            break;
        case OPT_KEY:
            key = 1;
            break;
        case OPT_PUB:
            pub = 1;
            break;
        case OPT_ENCRYPT:
            encrypt = 1;
            break;
        case OPT_DECRYPT:
            decrypt = 1;
            break;
        case OPT_ADD:
            add = 1;
            break;
        case OPT_ADD_PLAIN:
            add_plain = 1;
            break;
        case OPT_SUB:
            sub = 1;
            break;
        case OPT_MUL:
            mul = 1;
            break;
        default:
            goto opthelp1;
        }
    }

    action_sum = keygen + pubgen + key + pub + encrypt + decrypt + add + add_plain + sub + mul;
    if (action_sum == 0) {
        BIO_printf(bio_err, "No action parameter specified.\n");
        goto opthelp1;
    } else if (action_sum != 1) {
        BIO_printf(bio_err, "Only one action parameter must be specified.\n");
        goto opthelp1;
    }

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp2:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(paillier_options);
            goto end;
        case OPT_IN:
        case OPT_KEY_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
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

    if (argc == 1) {
        arg1 = argv[0];
        if (encrypt) {
            if (*arg1 == '_')
                arg1++;

            if (!opt_int(arg1, &plain))
                goto end;

            if (*argv[0] == '_')
                plain = -plain;
        }
    } else if (argc == 2) {
        arg1 = argv[0];
        arg2 = argv[1];
        if (add_plain || mul) {
            if (*arg2 == '_')
                arg2++;

            if (!opt_int(arg2, &plain))
                goto end;

            if (*argv[1] == '_')
                plain = -plain;
        }
    } else if (argc > 2) {
        BIO_printf(bio_err, "Extra arguments given.\n");
        goto opthelp2;
    }

    if (!app_RAND_load())
        goto end;

    if (verbose) {
        //TODO
    }

    if (infile != NULL) {
        in = bio_open_default(infile, 'r', FORMAT_PEM);
        if (in == NULL)
            goto end;
        if (pubgen || key || decrypt) {
            if (!(pail_key = PEM_read_bio_PAILLIER_PrivateKey(in, NULL, NULL, NULL)))
                goto end;
        } else if (pub || encrypt || add || add_plain || sub || mul) {
            if (!(pail_key = PEM_read_bio_PAILLIER_PublicKey(in, NULL, NULL, NULL)))
                goto end;
        }

        if (encrypt || decrypt || add || add_plain || sub || mul) {
            if (!(ctx = PAILLIER_CTX_new(pail_key, PAILLIER_MAX_THRESHOLD)))
                goto end;
        }
    }

    if (keygen)
        ret = paillier_keygen(outfile, text);
    else if (pubgen)
        ret = paillier_pubgen(pail_key, outfile, text);
    else if (key || pub)
        ret = paillier_print(pail_key, outfile, text);
    else if (encrypt)
        ret = paillier_encrypt(ctx, plain, outfile, text);
    else if (decrypt)
        ret = paillier_decrypt(ctx, arg1, outfile, text);
    else if (add)
        ret = paillier_add(ctx, arg1, arg2, outfile, text);
    else if (add_plain)
        ret = paillier_add_plain(ctx, arg1, plain, outfile, text);
    else if (sub)
        ret = paillier_sub(ctx, arg1, arg2, outfile, text);
    else if (mul)
        ret = paillier_mul(ctx, arg1, plain, outfile, text);

    ret = ret ? 0 : 1;
 end:
    PAILLIER_CTX_free(ctx);
    BIO_free_all(in);
    PAILLIER_KEY_free(pail_key);
    if (ret != 0) {
        BIO_printf(bio_err, "May be extra arguments error, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}
