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
#include <openssl/ec.h>
#include <internal/cryptlib.h>

static int noout = 0;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_ENCRYPT, OPT_DECRYPT, OPT_ADD, OPT_ADD_PLAIN, OPT_SUB, OPT_MUL,
    OPT_IN, OPT_KEY_IN,
    OPT_OUT, OPT_NOOUT,
    OPT_TEXT,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS ec_elgamal_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [action options] [input/output options] [arg1] [arg2]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Action"),
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt a number with the ec_elgamal public key, usage: -encrypt 99, 99 is an example number"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt a ciphertext using the ec_elgamal private key, usage: -decrypt c1, c1 is an example ciphertext"},
    {"add", OPT_ADD, '-', "EC-ElGamal homomorphic addition: add two ciphertexts, usage: -add c1 c2, c1 and c2 are tow example ciphertexts, result: E(c1) + E(c2)"},
    {"add_plain", OPT_ADD_PLAIN, '-', "EC-ElGamal homomorphic addition: add a ciphertext to a plaintext, usage: -add_plain c1 99, c1 is an example ciphertext, 99 is an example number, result: E(c1) + 99"},
    {"sub", OPT_SUB, '-', "EC-ElGamal homomorphic subtraction: sub two ciphertexts, usage: -sub c1 c2, c1 and c2 are tow example ciphertexts, result: E(c1) - E(c2)"},
    {"mul", OPT_MUL, '-', "EC-ElGamal homomorphic scalar multiplication: multiply a ciphertext by a known plaintext, usage: -mul c1 99, c1 is an example ciphertext, 99 is an example number, result: E(c1) * 99"},

    OPT_SECTION("Input"),
    {"in", OPT_IN, 's', "Input file"},
    {"key_in", OPT_KEY_IN, 's', "Input is a ec_elgamal private key used to generate public key"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output the ec_elgamal key to specified file"},
    {"noout", OPT_NOOUT, '-', "Don't print ec_elgamal key out"},
    {"text", OPT_TEXT, '-', "Print the ec_elgamal key in text"},

    OPT_PARAMETERS(),
    {"arg1", 0, 0, "Argument for encryption/decryption, or the first argument of a homomorphic operation"},
    {"arg2", 0, 0, "The second argument of a homomorphic operation"},

    {NULL}
};

static int ec_elgamal_buf2hexstr_print(BIO *bio, unsigned char *buf, size_t size,
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

static int ec_elgamal_ciphertext_print(BIO *bio, EC_ELGAMAL_CTX *ctx,
                                     EC_ELGAMAL_CIPHERTEXT *c,
                                     char *field, int text)
{
    int ret = 0;
    size_t size;
    unsigned char *buf = NULL;

    size = EC_ELGAMAL_CIPHERTEXT_encode(ctx, NULL, 0, c, 1);
    if (!(buf = OPENSSL_zalloc(size)))
        goto end;

    if (!EC_ELGAMAL_CIPHERTEXT_encode(ctx, buf, size, c, 1))
        goto end;

    ret = ec_elgamal_buf2hexstr_print(bio, buf, size, field, text);

end:
    OPENSSL_free(buf);
    return ret;
}

static int ec_elgamal_encrypt(EC_ELGAMAL_CTX *ctx, int plain, char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    EC_ELGAMAL_CIPHERTEXT *r = NULL;

    if (ctx == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    if (!(r = EC_ELGAMAL_CIPHERTEXT_new(ctx)))
        goto end;

    if (!EC_ELGAMAL_encrypt(ctx, r, plain))
        goto end;

    BIO_puts(bio, "ec_elgamal encrypt\n");
    BIO_printf(bio, "plaintext: %d\n", plain);

    ret = ec_elgamal_ciphertext_print(bio, ctx, r, "ciphertext", text);

end:
    EC_ELGAMAL_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int ec_elgamal_decrypt(EC_ELGAMAL_CTX *ctx, char *ciphertext,
                            char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    unsigned char *buf = NULL;
    size_t buf_n, len;
    int32_t r = 0;
    EC_ELGAMAL_CIPHERTEXT *c = NULL;
    EC_ELGAMAL_DECRYPT_TABLE *dtable = NULL;

    if (ctx == NULL || ciphertext == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    if (!(dtable = EC_ELGAMAL_DECRYPT_TABLE_new(ctx, 1)))
        goto end;

    EC_ELGAMAL_CTX_set_decrypt_table(ctx, dtable);

    buf_n = strlen(ciphertext) / 2;
    if (buf_n < 1)
        goto end;

    if (!(buf = OPENSSL_zalloc(buf_n))
        || !OPENSSL_hexstr2buf_ex(buf, buf_n, &len, ciphertext, '\0')
        || !(c = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !EC_ELGAMAL_CIPHERTEXT_decode(ctx, c, buf, len)
        || !EC_ELGAMAL_decrypt(ctx, &r, c))
        goto end;

    BIO_puts(bio, "ec_elgamal decrypt\n");

    ret = ec_elgamal_buf2hexstr_print(bio, buf, len, "ciphertext", text);

    BIO_printf(bio, "plaintext: %d\n", r);

end:
    OPENSSL_free(buf);
    EC_ELGAMAL_DECRYPT_TABLE_free(dtable);
    EC_ELGAMAL_CIPHERTEXT_free(c);
    BIO_free(bio);
    return ret;
}

static int ec_elgamal_add(EC_ELGAMAL_CTX *ctx, char *in1, char *in2,
                        char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, buf2_n, len1, len2;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

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
        || !(r = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !(c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !EC_ELGAMAL_CIPHERTEXT_decode(ctx, c2, buf2, len2)
        || !EC_ELGAMAL_add(ctx, r, c1, c2))
        goto end;

    BIO_puts(bio, "ec_elgamal add (result = c1 + c2)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "c2: %s\n", in2);

    ret = ec_elgamal_ciphertext_print(bio, ctx, r, "result", text);

end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int ec_elgamal_sub(EC_ELGAMAL_CTX *ctx, char *in1, char *in2,
                        char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, buf2_n, len1, len2;
    unsigned char *buf1 = NULL, *buf2 = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL, *c2 = NULL;

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
        || !(r = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !(c2 = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !EC_ELGAMAL_CIPHERTEXT_decode(ctx, c2, buf2, len2)
        || !EC_ELGAMAL_sub(ctx, r, c1, c2))
        goto end;

    BIO_puts(bio, "ec_elgamal subtraction (result = c1 - c2)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "c2: %s\n", in2);

    ret = ec_elgamal_ciphertext_print(bio, ctx, r, "result", text);

    ret = 1;

end:
    OPENSSL_free(buf1);
    OPENSSL_free(buf2);
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(c2);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

static int ec_elgamal_mul(EC_ELGAMAL_CTX *ctx, char *in1, int32_t plain,
                        char *outfile, int text)
{
    BIO *bio = NULL;
    int ret = 0;
    size_t buf1_n, len1;
    unsigned char *buf1 = NULL;
    EC_ELGAMAL_CIPHERTEXT *r = NULL, *c1 = NULL;

    if (ctx == NULL || in1 == NULL || !(bio = bio_open_owner(outfile, FORMAT_PEM, 1)))
        goto end;

    buf1_n = strlen(in1) / 2;
    if (buf1_n <= 1)
        goto end;

    if (!(buf1 = OPENSSL_zalloc(buf1_n))
        || !OPENSSL_hexstr2buf_ex(buf1, buf1_n, &len1, in1, '\0')
        || !(r = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !(c1 = EC_ELGAMAL_CIPHERTEXT_new(ctx))
        || !EC_ELGAMAL_CIPHERTEXT_decode(ctx, c1, buf1, len1)
        || !EC_ELGAMAL_mul(ctx, r, c1, plain))
        goto end;

    BIO_puts(bio, "ec_elgamal scalar multiplication (result = c1 * plaintext)\n");
    BIO_printf(bio, "c1: %s\n", in1);
    BIO_printf(bio, "plaintext: %d\n", plain);

    ret = ec_elgamal_ciphertext_print(bio, ctx, r, "result", text);

    ret = 1;

end:
    OPENSSL_free(buf1);
    EC_ELGAMAL_CIPHERTEXT_free(c1);
    EC_ELGAMAL_CIPHERTEXT_free(r);
    BIO_free(bio);
    return ret;
}

int ec_elgamal_main(int argc, char **argv)
{
    BIO *in = NULL;
    EC_KEY *eckey = NULL;
    EC_ELGAMAL_CTX *ctx = NULL;
    int ret = 1, action_sum = 0, text = 0;
    int encrypt = 0, decrypt = 0, add = 0, add_plain = 0, sub = 0, mul = 0;
    int plain = 0;
    char *infile = NULL, *outfile = NULL;
    char *prog;
    char *arg1 = NULL, *arg2 = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, ec_elgamal_options);
    if ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp1:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(ec_elgamal_options);
            goto end;
        case OPT_ENCRYPT:
            encrypt = 1;
            break;
        case OPT_DECRYPT:
            decrypt = 1;
            break;
        case OPT_ADD:
            add = 1;
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

    action_sum = encrypt + decrypt + add + sub + mul;
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
            opt_help(ec_elgamal_options);
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

    if (infile == NULL) {
        BIO_printf(bio_err, "No EC_KEY file path specified.\n");
        goto end;
    }

    in = bio_open_default(infile, 'r', FORMAT_PEM);
    if (in == NULL)
        goto end;
    if (decrypt) {
        if (!(eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL, NULL)))
            goto end;
    } else if (encrypt || add || sub || mul) {
        if (!(eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL, NULL)))
            goto end;
    }

    if (!(ctx = EC_ELGAMAL_CTX_new(eckey, EC_ELGAMAL_FLAG_DEFAULT)))
        goto end;

    if (encrypt)
        ret = ec_elgamal_encrypt(ctx, plain, outfile, text);
    else if (decrypt)
        ret = ec_elgamal_decrypt(ctx, arg1, outfile, text);
    else if (add)
        ret = ec_elgamal_add(ctx, arg1, arg2, outfile, text);
    else if (sub)
        ret = ec_elgamal_sub(ctx, arg1, arg2, outfile, text);
    else if (mul)
        ret = ec_elgamal_mul(ctx, arg1, plain, outfile, text);

    ret = ret ? 0 : 1;
 end:
    EC_ELGAMAL_CTX_free(ctx);
    BIO_free_all(in);
    EC_KEY_free(eckey);
    if (ret != 0) {
        BIO_printf(bio_err, "May be extra arguments error, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }
    return ret;
}
