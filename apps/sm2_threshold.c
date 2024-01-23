/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sm2_threshold.h>
#include <openssl/ec.h>
#include <internal/cryptlib.h>

#undef BUFSIZE
#define BUFSIZE 1024*8

typedef enum {
    OUT_FORMAT_DEFAULT = 0,
    OUT_FORMAT_HEX,
    OUT_FORMAT_BINARY,
} OUT_FORMAT;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_DERIVE, OPT_IN, OPT_INKEY, OPT_PEERKEY, OPT_PUBOUT, OPT_PUBIN,
    OPT_SIGN1, OPT_SIGN2, OPT_SIGN3, OPT_DIGEST, OPT_TEMP_KEY, OPT_OUT,
    OPT_TEMP_PEER_KEY, OPT_SIGFILE, OPT_PASSIN, OPT_SIGFORM, OPT_NEWKEY,
    OPT_PASSOUT, OPT_CIPHER, OPT_HEX, OPT_BINARY, OPT_NEWRAND, OPT_NEWPOINT,
    OPT_POINTIN, OPT_POINTOUT, OPT_RANDIN, OPT_DECRYPT1, OPT_DECRYPT2,
    OPT_DECRYPT3, OPT_R_ENUM, OPT_PROV_ENUM,
} OPTION_CHOICE;

/*
Examples:
Alice and Bob perform SM2 threshold key generation, signature and decryption:

[Key generation]
Alice:
# Generate SM2 private key, for example
genpkey -algorithm "ec" -pkeyopt "ec_paramgen_curve:sm2" -out A.key
# Derive SM2 threshold partial public key
sm2_threshold -derive -inkey A.key -pubout A.pub

Bob:
# Generate SM2 private key, for example
genpkey -algorithm "ec" -pkeyopt "ec_paramgen_curve:sm2" -out B.key
# Derive SM2 threshold partial public key
sm2_threshold -derive -inkey B.key -pubout B.pub

Alice -> Bob: A.pub
Bob -> Alice: B.pub

Alice:
sm2_threshold -derive -inkey A.key -peerkey B.pub -pubout pubkey.pem

Bob:
sm2_threshold -derive -inkey B.key -peerkey A.pub -pubout pubkey.pem

[Threshold signature]
Alice:
# Sign1, calculate the digest of the message and generate a new SM2 keypair
sm2_threshold -sign1 -newkey tempA.key -pubout tempA.pub -pubin -inkey pubkey.pem -in file

Alice -> Bob: the message digest and tempA.pub

Bob:
# Sign2, calculate the partial signature
sm2_threshold -sign2 -inkey B.key -temppeerkey tempA.pub -digest dgst -out partial_sig.txt

Bob -> Alice: partial_sig.txt

Alice:
# Sign3, calculate the final signature
sm2_threshold -sign3 -inkey A.key -sigfile partial_sig.txt -tempkey tempA.key -out final_sig.txt

[Threshold decryption]
Alice:
# T_1 = [w]C_1
sm2_threshold -decrypt1 -in ciphertxt -newrand w -newpoint T1

Alice -> Bob: T_1

Bob:
# T_2 = d_2^(-1) * T_1
sm2_threshold -decrypt2 -inkey B.key -pointin T1 -pointout T2

Bob -> Alice: T_2

Alice:
# [k]P = (x2, y2) = [w^(-1) * d_1^(-1)] * T_2 - C1
sm2_threshold -decrypt3 -inkey A.key -randin w -pointin T2 -in ciphertxt -out plaintxt

*/

const OPTIONS sm2_threshold_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [action options] [input/output options] [file]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Key-Action"),
    {"derive", OPT_DERIVE, '-', "Derive SM2 two-party threshold partial or complete public key"},
    {"sign1", OPT_SIGN1, '-', "1st step of SM2 threshold signature"},
    {"sign2", OPT_SIGN2, '-', "2nd step of SM2 threshold signature"},
    {"sign3", OPT_SIGN3, '-', "3rd step of SM2 threshold signature"},
    {"decrypt1", OPT_DECRYPT1, '-', "1st step of SM2 threshold decryption"},
    {"decrypt2", OPT_DECRYPT2, '-', "2nd step of SM2 threshold decryption"},
    {"decrypt3", OPT_DECRYPT3, '-', "3rd step of SM2 threshold decryption"},

    OPT_SECTION("Input"),
    {"in", OPT_IN, '<', "Input file"},
    {"inkey", OPT_INKEY, '<', "Input local SM2 threshold partial keypair"},
    {"pubin", OPT_PUBIN, '-', "Input key is a public key"},
    {"passin", OPT_PASSIN, 's', "Key input pass phrase source"},
    {"peerkey", OPT_PEERKEY, '<', "Input peer SM2 threshold partial public key"},
    {"sigfile", OPT_SIGFILE, '<', "Input a SM2 threshold partial signature"},
    {"digest", OPT_DIGEST, 's', "Input the message digest in hex format, calculated by 1st part SM2 threshold signature"},
    {"tempkey", OPT_TEMP_KEY, '<', "Input the temp key in SM2 threshold signature"},
    {"temppeerkey", OPT_TEMP_PEER_KEY, '<', "Input the temp peer key (Q1) in SM2 threshold signature"},
    {"sigform", OPT_SIGFORM, 's', "The format of input sigfile, binary or hex, default is binary"},
    {"pointin", OPT_POINTIN, '<', "Input a SM2 point"},
    {"randin", OPT_RANDIN, '<', "Input a random number"},

    OPT_SECTION("Output"),
    {"newkey", OPT_NEWKEY, '>', "Generate a new SM2 keypair"},
    {"passout", OPT_PASSOUT, 's', "Output key file pass phrase source"},
    {"", OPT_CIPHER, '-', "Any supported cipher to be used for encryption"},
    {"pubout", OPT_PUBOUT, '>', "Output public key"},
    {"out", OPT_OUT, '>', "Output file"},
    {"hex", OPT_HEX, '-', "Output digest or signature in hex format"},
    {"binary", OPT_BINARY, '-', "Output digest or signature in binary format"},
    {"newrand", OPT_NEWRAND, '>', "Output a random number"},
    {"newpoint", OPT_NEWPOINT, '>', "Output a SM2 point"},
    {"pointout", OPT_POINTOUT, '>', "Output a SM2 point"},

    OPT_R_OPTIONS,
    OPT_PROV_OPTIONS,
    {NULL}
};

static int sign1(EVP_PKEY *pubkey1, BIO *in_bio, int out_format, BIO *out_bio);
static int sign2(const EVP_PKEY *key1, const EVP_PKEY *peer_pubkey,
                 const char *digest, int out_format, BIO *out);
static int sign3(EVP_PKEY *key1, EVP_PKEY *temp_key,
                 const char *sigformat, const char *partial_sigfile,
                 int out_format, BIO *out);
static int decrypt1(BIO *in_bio, int filesize, BIO *randout_bio,
                    BIO *pointout_bio);
static int decrypt2(const EVP_PKEY *inkey, BIO *pointin_bio, BIO *pointout_bio);
static int decrypt3(const EVP_PKEY *inkey, BIO *in_bio, int filesize,
                    BIO *randin_bio, BIO *pointin_bio, BIO *out_bio);

int sm2_threshold_main(int argc, char **argv)
{
    BIO *in_bio = NULL, *out_bio = NULL, *key_bio = NULL, *randout_bio = NULL;
    BIO *randin_bio = NULL, *pointin_bio = NULL, *pointout_bio = NULL;
    EVP_PKEY *inkey = NULL, *peerkey = NULL;
    EVP_PKEY *temp_key = NULL, *sm2key = NULL;
    EVP_CIPHER *cipher = NULL;
    int ret = 1, derive = 0, sign_step = 0, decrypt_step = 0, pubin = 0;
    int filesize = -1, out_format = OUT_FORMAT_DEFAULT;
    const char *sigformat = "binary";
    char *hex_digest = NULL, *newkey_file = NULL;
    const char *inkey_file = NULL, *peerkey_file = NULL;
    const char *partial_sigfile = NULL, *infile = NULL, *outfile = NULL;
    const char *temp_key_file = NULL, *temp_peer_key_file = NULL;
    const char *randinfile = NULL, *randoutfile = NULL;
    const char *pointinfile = NULL, *pointoutfile = NULL;
    char *passin = NULL, *passinarg = NULL;
    char *passout = NULL, *passoutarg = NULL;
    char *prog, *ciphername = NULL;
    unsigned char *msgbuf = NULL;
    OPTION_CHOICE o;

    prog = opt_init(argc, argv, sm2_threshold_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            ret = 0;
            opt_help(sm2_threshold_options);
            goto end;
        case OPT_DERIVE:
            derive = 1;
            break;
        case OPT_INKEY:
            inkey_file = opt_arg();
            break;
        case OPT_PUBIN:
            pubin = 1;
            break;
        case OPT_SIGN1:
            sign_step = 1;
            break;
        case OPT_SIGN2:
            sign_step = 2;
            break;
        case OPT_SIGN3:
            sign_step = 3;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_DIGEST:
            hex_digest = opt_arg();
            break;
        case OPT_PEERKEY:
            peerkey_file = opt_arg();
            break;
        case OPT_SIGFILE:
            partial_sigfile = opt_arg();
            break;
        case OPT_PUBOUT:
            outfile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_PASSIN:
            passinarg = opt_arg();
            break;
        case OPT_PASSOUT:
            passoutarg = opt_arg();
            break;
        case OPT_TEMP_KEY:
            temp_key_file = opt_arg();
            break;
        case OPT_TEMP_PEER_KEY:
            temp_peer_key_file = opt_arg();
            break;
        case OPT_SIGFORM:
            sigformat = opt_arg();
            break;
        case OPT_NEWKEY:
            newkey_file = opt_arg();
            break;
        case OPT_CIPHER:
            ciphername = opt_unknown();
            break;
        case OPT_HEX:
            out_format = OUT_FORMAT_HEX;
            break;
        case OPT_BINARY:
            out_format = OUT_FORMAT_BINARY;
            break;
        case OPT_DECRYPT1:
            decrypt_step = 1;
            break;
        case OPT_DECRYPT2:
            decrypt_step = 2;
            break;
        case OPT_DECRYPT3:
            decrypt_step = 3;
            break;
        case OPT_NEWRAND:
            randoutfile = opt_arg();
            break;
        case OPT_NEWPOINT:
            pointoutfile = opt_arg();
            break;
        case OPT_POINTIN:
            pointinfile = opt_arg();
            break;
        case OPT_POINTOUT:
            pointoutfile = opt_arg();
            break;
        case OPT_RANDIN:
            randinfile = opt_arg();
            break;
        default:
            goto opthelp;
        }
    }

    /* No extra arguments. */
    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (!app_RAND_load())
        goto end;

    if (outfile) {
        if (derive)
            out_bio = bio_open_owner(outfile, FORMAT_PEM, 1);
        else
            out_bio = bio_open_default(outfile, 'w', FORMAT_BINARY);

        if (out_bio == NULL)
            goto end;
    }

    if (inkey_file != NULL) {
        if (pubin) {
            inkey = load_pubkey(inkey_file, FORMAT_PEM, 1, NULL, NULL, "inkey");
        } else {
            if (!app_passwd(passinarg, NULL, &passin, NULL)) {
                BIO_printf(bio_err, "Error getting passwords\n");
                goto end;
            }

            inkey = load_key(inkey_file, FORMAT_PEM, 1, passin, NULL, "inkey");
        }

        if (inkey == NULL)
            goto end;
    }

    if (peerkey_file) {
        peerkey = load_pubkey(peerkey_file, FORMAT_PEM, 1, NULL, NULL,
                              "peerkey");
        if (peerkey == NULL)
            goto end;
    }

    if (temp_peer_key_file) {
        temp_key = load_pubkey(temp_peer_key_file, FORMAT_PEM, 1, NULL, NULL,
                               "temp_peer_key");
        if (temp_key == NULL)
            goto end;
    }

    if (temp_key_file != NULL) {
        if (!app_passwd(passinarg, NULL, &passin, NULL)) {
            BIO_printf(bio_err, "Error getting passwords\n");
            goto end;
        }

        temp_key = load_key(temp_key_file, FORMAT_PEM, 1, passin, NULL,
                            "temp_key");

        if (temp_key == NULL)
            goto end;
    }

    if (partial_sigfile != NULL) {
        if (inkey == NULL) {
            BIO_printf(bio_err, "No key specified\n");
            goto opthelp;
        }
    }

    if (ciphername != NULL) {
        if (!opt_cipher(ciphername, &cipher))
            goto opthelp;
    }

    if (sign_step == 1 && newkey_file) {
        if (!app_passwd(passoutarg, NULL, &passout, NULL)) {
            BIO_printf(bio_err, "Error getting passwords\n");
            goto end;
        }

        sm2key = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
        if (sm2key == NULL) {
            BIO_printf(bio_err, "Failed to generate SM2 key\n");
            goto end;
        }

        key_bio = bio_open_default(newkey_file, 'w', FORMAT_PEM);

        if (!PEM_write_bio_PrivateKey(key_bio, sm2key, cipher, NULL, 0, NULL,
                                      passout)) {
            BIO_printf(bio_err, "Error writing private key\n");
            goto end;
        }

        if (out_bio) {
            if (!PEM_write_bio_PUBKEY(out_bio, sm2key)) {
                BIO_printf(bio_err, "Error writing pubkey\n");
                goto end;
            }
        }
    }

    if (infile) {
        in_bio = bio_open_default(infile, 'r', FORMAT_BINARY);
        if (in_bio == NULL)
            goto end;

        struct stat st;

        if (stat(infile, &st) == 0 && st.st_size <= INT_MAX)
            filesize = (int)st.st_size;
    }

    if (randoutfile) {
        randout_bio = bio_open_default(randoutfile, 'w', FORMAT_BINARY);
        if (randout_bio == NULL)
            goto end;
    }

    if (pointoutfile) {
        pointout_bio = bio_open_default(pointoutfile, 'w', FORMAT_BINARY);
        if (pointout_bio == NULL)
            goto end;
    }

    if (randinfile) {
        randin_bio = bio_open_default(randinfile, 'r', FORMAT_BINARY);
        if (randin_bio == NULL)
            goto end;
    }

    if (pointinfile) {
        pointin_bio = bio_open_default(pointinfile, 'r', FORMAT_BINARY);
        if (pointin_bio == NULL)
            goto end;
    }

    if (derive) {
        EVP_PKEY *pubkey = NULL;

        if (inkey && peerkey) {
            pubkey = SM2_THRESHOLD_derive_complete_pubkey(inkey, peerkey);
        } else if (inkey) {
            pubkey = SM2_THRESHOLD_derive_partial_pubkey(inkey);
        } else {
            BIO_printf(bio_err, "No key specified\n");
            goto opthelp;
        }

        if (pubkey == NULL) {
            BIO_printf(bio_err, "Failed to derive public key\n");
            goto end;
        }

        if (!PEM_write_bio_PUBKEY(out_bio, pubkey)) {
            EVP_PKEY_free(pubkey);
            BIO_printf(bio_err, "Error writing pubkey\n");
            goto end;
        }
    } else if (sign_step == 1) {
        if (in_bio == NULL) {
            BIO_printf(bio_err, "No input file specified\n");
            goto opthelp;
        }

        if (!sign1(inkey, in_bio, out_format, bio_out))
            goto end;
    } else if (sign_step == 2) {
        if (inkey == NULL || temp_key == NULL) {
            BIO_printf(bio_err, "No key specified\n");
            goto opthelp;
        }

        if (!sign2(inkey, temp_key, hex_digest, out_format, out_bio))
            goto end;
    } else if (sign_step == 3) {
        if (inkey == NULL || temp_key == NULL) {
            BIO_printf(bio_err, "No key specified\n");
            goto opthelp;
        }

        if (!sign3(inkey, temp_key, sigformat, partial_sigfile, out_format,
                   out_bio))
            goto end;
    } else if (decrypt_step == 1) {
        if (in_bio == NULL || randout_bio == NULL || pointout_bio == NULL) {
            BIO_printf(bio_err, "No input or output specified\n");
            goto opthelp;
        }

        if (!decrypt1(in_bio, filesize, randout_bio, pointout_bio))
            goto end;
    } else if (decrypt_step == 2) {
        if (inkey == NULL || pointin_bio == NULL || pointout_bio == NULL) {
            BIO_printf(bio_err, "No pointin or pointout specified\n");
            goto opthelp;
        }

        if (!decrypt2(inkey, pointin_bio, pointout_bio))
            goto end;
    } else if (decrypt_step == 3) {
        if (inkey == NULL || in_bio == NULL || randin_bio == NULL
            || pointin_bio == NULL || out_bio == NULL) {
            BIO_printf(bio_err, "No input or output specified\n");
            goto opthelp;
        }

        if (!decrypt3(inkey, in_bio, filesize, randin_bio, pointin_bio,
            out_bio))
            goto end;
    } else {
        BIO_printf(bio_err, "No action specified.\n");
        goto opthelp;
    }

    ret = 0;
end:
    if (ret != 0) {
        BIO_printf(bio_err, "Maybe some errors occured, please use -help for usage summary.\n");
        ERR_print_errors(bio_err);
    }

    EVP_PKEY_free(inkey);
    EVP_PKEY_free(temp_key);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(sm2key);
    EVP_CIPHER_free(cipher);
    OPENSSL_free(msgbuf);
    BIO_free(pointin_bio);
    BIO_free(pointout_bio);
    BIO_free(randout_bio);
    BIO_free(randin_bio);
    BIO_free(in_bio);
    BIO_free(out_bio);
    BIO_free(key_bio);

    return ret;
}

static int sign3(EVP_PKEY *key1, EVP_PKEY *temp_key,
                 const char *sigformat, const char *partial_sigfile,
                 int out_format, BIO *out)
{
    int ret = 0, is_hex;
    BIO *sigbio = NULL;
    unsigned char *final_sig = NULL, *sigbuf = NULL;
    long buflen;
    size_t siglen, final_siglen, tmplen;

    sigbio = bio_open_default(partial_sigfile, 'r', FORMAT_BINARY);
    if (sigbio == NULL) {
        BIO_printf(bio_err, "Error opening signature file %s\n",
                   partial_sigfile);
        goto end;
    }

    buflen = EVP_PKEY_size(key1) * 3;
    sigbuf = app_malloc(buflen, "signature buffer");

    siglen = BIO_read(sigbio, sigbuf, buflen - 1);
    if (siglen <= 0) {
        BIO_printf(bio_err, "Error reading signature file %s\n",
                   partial_sigfile);
        goto end;
    }

    if (strcmp(sigformat, "hex") == 0) {
        is_hex = 1;
    } else if (strcmp(sigformat, "binary") == 0) {
        is_hex = 0;
    } else {
        BIO_printf(bio_err, "Unknown signature format %s\n", sigformat);
        goto end;
    }

    if (is_hex) {
        sigbuf[siglen] = '\0';

        unsigned char *buf = OPENSSL_hexstr2buf((char *)sigbuf, &buflen);
        if (buf == NULL) {
            BIO_printf(bio_err, "Error decoding signature\n");
            goto end;
        }

        OPENSSL_free(sigbuf);
        sigbuf = buf;
        siglen = buflen;
    }

    if (!SM2_THRESHOLD_sign3(key1, temp_key, sigbuf, siglen, &final_sig,
                             &final_siglen)) {
        BIO_printf(bio_err, "Failed to do SM2 threshold sign3\n");
        goto end;
    }

    if (out_format == OUT_FORMAT_HEX) {
        if (BIO_hex_string(out, 0, final_siglen, final_sig, final_siglen)
                != 1) {
            BIO_printf(bio_err, "Error occur when output signature\n");
            goto end;
        }
    } else {
        tmplen = BIO_write(out, final_sig, final_siglen);
        if (tmplen != final_siglen) {
            BIO_printf(bio_err, "Error occur when output signature\n");
            goto end;
        }
    }

    ret = 1;
end:
    OPENSSL_free(sigbuf);
    OPENSSL_free(final_sig);
    BIO_free(sigbio);

    return ret;
}

static int sign1(EVP_PKEY *pubkey1, BIO *in_bio, int out_format, BIO *out_bio)
{
    int ret = 0;
    unsigned char *buf = NULL;
    size_t buflen, dlen;
    EVP_MD_CTX *ctx = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!SM2_THRESHOLD_sign1_init(ctx, EVP_sm3(), pubkey1, NULL, 0)) {
        BIO_printf(bio_err, "sign1 init failed\n");
        goto err;
    }

    buf = app_malloc(BUFSIZE, "I/O buffer");
    if (buf == NULL)
        goto err;

    while (BIO_pending(in_bio) || !BIO_eof(in_bio)) {
        ret = BIO_read(in_bio, (char *)buf, BUFSIZE);
        if (ret < 0) {
            BIO_printf(bio_err, "Read error when do sign1\n");
            goto err;
        }
        if (ret == 0)
            break;

        if (!SM2_THRESHOLD_sign1_update(ctx, buf, ret)) {
            BIO_printf(bio_err, "sign1 update failed\n");
            goto err;
        }
    }

    if (!SM2_THRESHOLD_sign1_final(ctx, digest, &dlen)) {
        BIO_printf(bio_err, "sign1 final failed\n");
        goto err;
    }

    if (out_format == OUT_FORMAT_BINARY) {
        if (BIO_write(out_bio, digest, dlen) != (int)dlen) {
            BIO_printf(bio_err, "Error occur when output digest\n");
            goto err;
        }
    } else {
        if (!OPENSSL_buf2hexstr_ex((char *)buf, BUFSIZE, &buflen, digest, dlen,
                                '\0')) {
            BIO_printf(bio_err, "Error encoding digest\n");
            goto err;
        }

        BIO_printf(out_bio, "SM2_threshold_sign1, digest=%s\n", buf);
    }

    ret = 1;

 err:
    OPENSSL_free(buf);
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int sign2(const EVP_PKEY *key1, const EVP_PKEY *peer_pubkey,
                 const char *digest, int out_format, BIO *out)
{
    int ret = 0;
    unsigned char *buf, *sigbuf = NULL;
    size_t siglen;
    long buflen;

    buf = OPENSSL_hexstr2buf(digest, &buflen);
    if (buf == NULL) {
        BIO_printf(bio_err, "failed to decode digest\n");
        goto end;
    }

    ret = SM2_THRESHOLD_sign2(key1, peer_pubkey, buf, buflen, &sigbuf, &siglen);

    if (ret != 1)
        goto end;

    /* Note: default format for signature is binary */
    if (out_format == OUT_FORMAT_HEX) {
        if (BIO_hex_string(out, 0, siglen, sigbuf, siglen) != 1) {
            BIO_printf(bio_err, "Error occur when output signature\n");
            goto end;
        }
    } else {
        ret = BIO_write(out, sigbuf, siglen);
        if (ret != (int)siglen) {
            BIO_printf(bio_err, "Error occur when output signature\n");
            goto end;
        }
    }

    ret = 1;
end:
    OPENSSL_free(buf);
    OPENSSL_free(sigbuf);
    return ret;
}

static int decrypt1(BIO *in_bio, int filesize, BIO *randout_bio,
                    BIO *pointout_bio)
{
    int ok = 0, ct_len = 0;
    unsigned char *ct = NULL;
    char *buf = NULL;
    size_t buf_len;
    BIGNUM *w = NULL;
    EC_POINT *T1 = NULL;
    EC_GROUP *group = NULL;

    if (filesize < 0) {
        BIO_printf(bio_err, "Failed to get file size\n");
        goto end;
    }

    ct = app_malloc(filesize, "I/O buffer");
    if (ct == NULL)
        goto end;

    ct_len = BIO_read(in_bio, (char *)ct, filesize);
    if (ct_len != filesize) {
        BIO_printf(bio_err, "Error reading input file\n");
        goto end;
    }

    if (!SM2_THRESHOLD_decrypt1(ct, ct_len, &w, &T1)) {
        BIO_printf(bio_err, "Error occur when decrypt1\n");
        goto end;
    }

    buf = BN_bn2hex(w);
    if (buf == NULL)
        goto end;

    buf_len = strlen(buf);

    if (BIO_write(randout_bio, buf, buf_len) != (int)buf_len) {
        BIO_printf(bio_err, "Error occur when output random number\n");
        goto end;
    }

    OPENSSL_free(buf);
    buf = NULL;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_sm2);
    if (group == NULL)
        goto end;

    buf = EC_POINT_point2hex(group, T1, POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (buf == NULL) {
        BIO_printf(bio_err, "Error occur when convert point to buffer\n");
        goto end;
    }

    buf_len = strlen(buf);
    if (BIO_write(pointout_bio, buf, buf_len) != (int)buf_len) {
        BIO_printf(bio_err, "Error occur when output point\n");
        goto end;
    }

    ok = 1;
end:
    EC_GROUP_free(group);
    OPENSSL_free(ct);
    OPENSSL_free(buf);
    BN_free(w);
    EC_POINT_free(T1);

    return ok;
}

static int decrypt2(const EVP_PKEY *inkey, BIO *pointin_bio, BIO *pointout_bio)
{
    int ok = 0, field_size, len;
    EC_GROUP *group = NULL;
    EC_POINT *T1 = NULL, *T2 = NULL;
    char *buf = NULL;
    size_t buf_len;

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_sm2);
    if (group == NULL)
        goto end;

    field_size = BN_num_bytes(EC_GROUP_get0_field(group));
    len = (2 * field_size + 1) * 2 + 1;

    buf = app_malloc(len, "I/O buffer");
    if (buf == NULL)
        goto end;

    buf_len = BIO_read(pointin_bio, buf, len - 1);
    if (buf_len <= 0) {
        BIO_printf(bio_err, "Error reading point file\n");
        goto end;
    }

    buf[buf_len] = '\0';

    T1 = EC_POINT_hex2point(group, buf, NULL, NULL);
    if (T1 == NULL) {
        BIO_printf(bio_err, "Error occur when convert hex to point\n");
        goto end;
    }

    if (!SM2_THRESHOLD_decrypt2(inkey, T1, &T2)) {
        BIO_printf(bio_err, "Error occur when decrypt2\n");
        goto end;
    }

    OPENSSL_free(buf);
    buf = NULL;

    buf = EC_POINT_point2hex(group, T2, POINT_CONVERSION_UNCOMPRESSED, NULL);
    if (buf == NULL) {
        BIO_printf(bio_err, "Error occur when convert point to hex\n");
        goto end;
    }

    buf_len = strlen(buf);

    if (BIO_write(pointout_bio, buf, buf_len) != (int)buf_len) {
        BIO_printf(bio_err, "Error occur when output point\n");
        goto end;
    }

    ok = 1;
end:
    EC_GROUP_free(group);
    EC_POINT_free(T1);
    EC_POINT_free(T2);
    OPENSSL_free(buf);

    return ok;
}

static int decrypt3(const EVP_PKEY *inkey, BIO *in_bio, int filesize,
                    BIO *randin_bio, BIO *pointin_bio, BIO *out_bio)
{
    int ok = 0, ct_len = 0, field_size, len;
    unsigned char *ct = NULL, *pt = NULL;
    char *buf = NULL;
    size_t buf_len, pt_len;
    BIGNUM *w = NULL;
    EC_POINT *T2 = NULL;
    EC_GROUP *group = NULL;

    if (filesize < 0) {
        BIO_printf(bio_err, "Failed to get file size\n");
        goto end;
    }

    ct = app_malloc(filesize, "I/O buffer");
    if (ct == NULL)
        goto end;

    ct_len = BIO_read(in_bio, (char *)ct, filesize);
    if (ct_len != filesize) {
        BIO_printf(bio_err, "Error reading input file\n");
        goto end;
    }

    group = EC_GROUP_new_by_curve_name_ex(NULL, NULL, NID_sm2);
    if (group == NULL)
        goto end;

    field_size = BN_num_bytes(EC_GROUP_get0_field(group));
    len = (2 * field_size + 1) * 2 + 1;

    buf = app_malloc(len, "I/O buffer");
    if (buf == NULL)
        goto end;

    buf_len = BIO_read(pointin_bio, buf, len - 1);
    if (buf_len <= 0) {
        BIO_printf(bio_err, "Error reading point file\n");
        goto end;
    }

    buf[buf_len] = '\0';

    T2 = EC_POINT_hex2point(group, buf, NULL, NULL);
    if (T2 == NULL) {
        BIO_printf(bio_err, "Error occur when convert hex to point\n");
        goto end;
    }

    OPENSSL_free(buf);
    buf = NULL;

    buf_len = BN_num_bytes(EC_GROUP_get0_order(group)) * 2 + 1;
    buf = app_malloc(buf_len, "rand buffer");
    if (buf == NULL)
        goto end;

    buf_len = BIO_read(randin_bio, buf, buf_len - 1);
    if (buf_len <= 0) {
        BIO_printf(bio_err, "Error reading random number file\n");
        goto end;
    }

    buf[buf_len] = '\0';

    if (!BN_hex2bn(&w, buf)) {
        BIO_printf(bio_err, "Error occur when convert hex to BIGNUM\n");
        goto end;
    }

    if (!SM2_THRESHOLD_decrypt3(inkey, ct, ct_len, w, T2, &pt, &pt_len)) {
        BIO_printf(bio_err, "Error occur when decrypt3\n");
        goto end;
    }

    if (BIO_write(out_bio, pt, pt_len) != (int)pt_len) {
        BIO_printf(bio_err, "Error occur when output point\n");
        goto end;
    }

    ok = 1;
end:
    EC_GROUP_free(group);
    OPENSSL_free(ct);
    OPENSSL_free(buf);
    BN_free(w);
    EC_POINT_free(T2);

    return ok;
}
