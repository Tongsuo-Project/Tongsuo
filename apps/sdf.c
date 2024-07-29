/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include "internal/deprecated.h"
#include <stdio.h>
#include <openssl/sdf.h>
#include <openssl/bio.h>
#include <openssl/tsapi.h>
#include <openssl/ec.h>
#include <openssl/sgd.h>
#include "apps.h"
#include "progs.h"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_IN,
    OPT_INKEY,
    OPT_INDEX,
    OPT_GENSM2KEY,
    OPT_DELSM2KEY,
    OPT_UPDATESM2KEY,
    OPT_EXPORTSM2PUBKEY,
    OPT_EXPORTSM2KEY,
    OPT_EXPORTSM2KEYWITHEVLP,
    OPT_IMPORTSM2KEY,
    OPT_IMPORTSM2KEYWITHEVLP,
    OPT_LOGIN,
    OPT_ENCRYPT,
    OPT_DECRYPT,
    OPT_PEERKEY,
    OPT_TYPE,
    OPT_OUT,
    OPT_KEYOUT,
    OPT_DEKOUT,
    OPT_INDEK,
    OPT_IV,
    OPT_ISK,
    OPT_ISKTYPE,
    OPT_ALGORITHM,
} OPTION_CHOICE;

/*
 * Examples:
 *
 * Encrypt data with SM4 key which is encrypted with ISK:
 * sdf -encrypt -algorithm sm4-cbc -inkey sm4key.enc -isk index -isktype sm2 -iv aabbcc -in data.txt -out data.enc
 *
 * Generate SM2 key pair with the index:
 * sdf -gensm2key -index 1
 *
 * Delete SM2 key pair with the index:
 * sdf -delsm2key -index 1
 *
 * Update SM2 key pair with the index:
 * sdf -updatesm2key -index 1
 *
 * Encrypt data with SM2 key with the index:
 * sdf -encrypt -algorithm sm2 -index 1 -in data.txt -out data.enc
 *
 * Import SM2 key with the index, sm2 key is encrypted by sm4 key(indek),
 * sm4 key is encrypted by ISK, default is 0:
 * sdf -importsm2keywithevlp -type enc  -index 7 -inkey sm2_enc.keyenc -indek sm4.keyenc
 *
 * Export SM2 key with the index:
 * sdf -exportsm2key -index 1 -keyout sm2key.pem
 *
 * Export SM2 public key with the index:
 * sdf -exportsm2pubkey -index 1 -keyout sm2pubkey.pem
 */

const OPTIONS sdf_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt file"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt file"},
    {"importsm2key", OPT_IMPORTSM2KEY, '-', "Import SM2 key with the index"},
    {"importsm2keywithevlp", OPT_IMPORTSM2KEYWITHEVLP, '-', "Import SM2 key with digital envelope"},
    {"gensm2key", OPT_GENSM2KEY, '-', "Generate SM2 key pair with the index"},
    {"delsm2key", OPT_DELSM2KEY, '-', "Delete SM2 key pair with the index"},
    {"updatesm2key", OPT_UPDATESM2KEY, '-', "Update SM2 key pair with the index"},
    {"exportsm2key", OPT_EXPORTSM2KEY, '-', "Export SM2 key with the index"},
    {"exportsm2pubkey", OPT_EXPORTSM2PUBKEY, '-', "Export SM2 public key with the index"},
    {"exportsm2keywithevlp", OPT_EXPORTSM2KEYWITHEVLP, '-', "Export SM2 key with digital envelope"},
    {"login", OPT_LOGIN, 's', "Login with username:password"},

    OPT_SECTION("Input"),
    {"inkey", OPT_INKEY, 's', "Input key file"},
    {"index", OPT_INDEX, 's', "Specify the index of key"},
    {"peerkey", OPT_PEERKEY, 's', "Peer public key file used in exporting SM2 key with digital envelope"},
    {"type", OPT_TYPE, 's', "sign: signature key, enc: encryption key"},
    {"indek", OPT_INDEK, '>', "Input digital envelope key"},
    {"isk", OPT_ISK, 's', "Index of ISK key"},
    {"isktype", OPT_ISKTYPE, 's', "ISK type, sm2: SM2 key, rsa: RSA key"},
    {"iv", OPT_IV, 's', "IV in hex format"},
    {"algorithm", OPT_ALGORITHM, 's', "Algorithm to use"},
    {"in", OPT_IN, '>', "Input file"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"keyout", OPT_KEYOUT, '>', "Output key file"},
    {"dekout", OPT_DEKOUT, '>', "Output digital envelope key"},

    {NULL}
};

int sdf_main(int argc, char **argv)
{
    char *prog;
    OPTION_CHOICE o;
    BIO *outkey = NULL, *outdek = NULL, *key_bio = NULL;
    BIO *in = NULL, *out = NULL;
    int ret = 1, index = -1, sign = 1, keylen = 0, deklen = 0, mode = 0;
    int isk = -1;
    int gensm2 = 0, delsm2 = 0, updatesm2 = 0;
    int exportsm2pubkey = 0, exportsm2keywithevlp = 0, importsm2keywithevlp = 0;
    int exportsm2key = 0, importsm2key = 0, encrypt = 0, decrypt = 0;
    unsigned char *inkey = NULL, *indek = NULL, *inbuf = NULL, *outbuf = NULL;
    char *p = NULL;
    char *login = NULL;
    char *outkeyfile = NULL, *peerkey_file = NULL, *indekfile = NULL;
    char *outdekfile = NULL, *inkeyfile = NULL;
    char *infile = NULL, *outfile = NULL;
    const char *user = "admin", *password = "123123", *hexiv = NULL, *algo = NULL;
    const char *isktype = "sm2";
    unsigned char *iv = NULL;
    EVP_PKEY *pkey = NULL, *peer = NULL;
    unsigned char *priv = NULL, *pub = NULL, *outevlp = NULL;
    size_t privlen = 0, publen = 0, outevlplen = 0;
    int inbuflen = -1;
    size_t outbuflen = 0;

    prog = opt_init(argc, argv, sdf_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(sdf_options);
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_INKEY:
            inkeyfile = opt_arg();
            break;
        case OPT_GENSM2KEY:
            gensm2 = 1;
            break;
        case OPT_DELSM2KEY:
            delsm2 = 1;
            break;
        case OPT_UPDATESM2KEY:
            updatesm2 = 1;
            break;
        case OPT_INDEX:
            index = atoi(opt_arg());
            break;
        case OPT_LOGIN:
            login = opt_arg();
            break;
        case OPT_EXPORTSM2KEY:
            exportsm2key = 1;
            break;
        case OPT_EXPORTSM2PUBKEY:
            exportsm2pubkey = 1;
            break;
        case OPT_EXPORTSM2KEYWITHEVLP:
            exportsm2keywithevlp = 1;
            break;
        case OPT_IMPORTSM2KEY:
            importsm2key = 1;
            break;
        case OPT_IMPORTSM2KEYWITHEVLP:
            importsm2keywithevlp = 1;
            break;
        case OPT_PEERKEY:
            peerkey_file = opt_arg();
            break;
        case OPT_TYPE:
            if (strcmp(opt_arg(), "sign") == 0)
                sign = 1;
            else if (strcmp(opt_arg(), "enc") == 0)
                sign = 0;
            else
                goto opthelp;
            break;
        case OPT_KEYOUT:
            outkeyfile = opt_arg();
            break;
        case OPT_INDEK:
            indekfile = opt_arg();
            break;
        case OPT_DEKOUT:
            outdekfile = opt_arg();
            break;
        case OPT_ENCRYPT:
            encrypt = 1;
            break;
        case OPT_DECRYPT:
            decrypt = 1;
            break;
        case OPT_IV:
            hexiv = opt_arg();
            break;
        case OPT_ALGORITHM:
            algo = opt_arg();
            break;
        case OPT_ISK:
            isk = atoi(opt_arg());
            break;
        case OPT_ISKTYPE:
            isktype = opt_arg();
            break;
        }
    }

    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    if (login) {
        user = login;
        p = strchr(login, ':');
        if (p == NULL) {
            BIO_printf(bio_err, "No password found");
            goto end;
        }

        password = p + 1;
        *p = '\0';
    }

    if (gensm2) {
        if (!TSAPI_GenerateSM2KeyWithIndex(index, sign, user, password)) {
            BIO_printf(bio_err, "Failed to generate SM2 key pair with index %d\n", index);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (delsm2) {
        if (!TSAPI_DelSm2KeyWithIndex(index, sign, user, password)) {
            BIO_printf(bio_err, "Failed to delete SM2 key pair with index %d\n", index);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (updatesm2) {
        if (!TSAPI_UpdateSm2KeyWithIndex(index, sign, user, password)) {
            BIO_printf(bio_err, "Failed to update SM2 key pair with index %d\n", index);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (outkeyfile) {
        outkey = bio_open_default(outkeyfile, 'w', FORMAT_BINARY);
        if (outkey == NULL)
            goto end;
    }

    if (exportsm2key) {
        pkey = TSAPI_ExportSM2KeyWithIndex(index, sign, user, password);
        if (pkey == NULL) {
            BIO_printf(bio_err, "Failed to export SM2 pubkey with index %d\n", index);
            goto end;
        }

        if (!PEM_write_bio_PrivateKey(outkey, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_printf(bio_err, "Failed to write SM2 key\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (exportsm2pubkey) {
        pkey = TSAPI_ExportSM2PubKeyWithIndex(index, sign);
        if (pkey == NULL) {
            BIO_printf(bio_err, "Failed to export SM2 pubkey with index %d\n", index);
            goto end;
        }

        if (!PEM_write_bio_PUBKEY(outkey, pkey)) {
            BIO_printf(bio_err, "Failed to write SM2 pubkey");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (exportsm2keywithevlp) {
        peer = load_pubkey(peerkey_file, FORMAT_PEM, 0, NULL, NULL, "peer key");
        if (peer == NULL) {
            BIO_printf(bio_err, "Error reading peer key %s\n", peerkey_file);
            return 0;
        }

        if (!TSAPI_ExportSM2KeyWithEvlp(index, sign, user, password, peer, &priv,
                                        &privlen, &pub, &publen, &outevlp,
                                        &outevlplen)) {
            BIO_printf(bio_err, "Failed to export SM2 key with digital envelope\n");
            goto end;
        }

        if (outkey == NULL) {
            BIO_printf(bio_err, "No output file specified\n");
            goto end;
        }

        if (BIO_write(outkey, pub, publen) != (int)publen
            || BIO_write(outkey, priv, privlen) != (int)privlen) {
            BIO_printf(bio_err, "Failed to write public or private key\n");
            goto end;
        }

        if (outdekfile == NULL) {
            BIO_printf(bio_err, "No digital envelope file specified\n");
            goto end;
        }

        outdek = bio_open_default(outdekfile, 'w', FORMAT_BINARY);
        if (outdek == NULL)
            goto end;

        if (BIO_write(outdek, outevlp, outevlplen) != (int)outevlplen) {
            BIO_printf(bio_err, "Failed to write digital envelope\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (importsm2key) {
        pkey = load_key(inkeyfile, FORMAT_PEM, 0, NULL, NULL, "key");

        if (pkey == NULL) {
            BIO_printf(bio_err, "Error reading key %s\n", inkeyfile);
            goto end;
        }

        if (!TSAPI_ImportSM2Key(index, sign, user, password, pkey)) {
            BIO_printf(bio_err, "Failed to import SM2 key\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (inkeyfile) {
        key_bio = BIO_new(BIO_s_file());
        if (key_bio == NULL) {
            BIO_printf(bio_err, "Error creating key BIO\n");
            goto end;
        }

        if (BIO_read_filename(key_bio, inkeyfile) <= 0) {
            BIO_printf(bio_err, "Error reading key file %s\n", inkeyfile);
            goto end;
        }

        keylen = bio_to_mem(&inkey, 4096, key_bio);
        BIO_free(key_bio);
        key_bio = NULL;

        if (keylen < 0) {
            BIO_printf(bio_err, "Error reading key\n");
            goto end;
        }
    }

    if (indekfile) {
        key_bio = BIO_new(BIO_s_file());
        if (key_bio == NULL) {
            BIO_printf(bio_err, "Error creating key BIO\n");
            goto end;
        }

        if (BIO_read_filename(key_bio, indekfile) <= 0) {
            BIO_printf(bio_err, "Error reading key file %s\n", indekfile);
            goto end;
        }

        deklen = bio_to_mem(&indek, 4096, key_bio);
        BIO_free(key_bio);
        key_bio = NULL;

        if (deklen < 0) {
            BIO_printf(bio_err, "Error reading key\n");
            goto end;
        }
    }

    if (importsm2keywithevlp) {
        if (inkey == NULL || indek == NULL) {
            BIO_printf(bio_err, "No key or digital envelope specified\n");
            goto end;
        }

        if (!TSAPI_ImportSM2KeyWithEvlp(index, sign, user, password, inkey,
                                        keylen, indek, deklen)) {
            BIO_printf(bio_err, "Failed to import SM2 key with digital envelope\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (infile) {
        in = bio_open_default(infile, 'r', FORMAT_BINARY);
        if (in == NULL)
            goto end;

        /* Note: Only supports files less than 1GB */
        inbuflen = bio_to_mem(&inbuf, 1024 * 1024 * 1024, in);
        if (inbuflen < 0) {
            BIO_printf(bio_err, "Error reading input\n");
            goto end;
        }
    }

    if (outfile) {
        out = bio_open_default(outfile, 'w', FORMAT_BINARY);
        if (out == NULL)
            goto end;
    }

    if (encrypt || decrypt) {
        if (inbuf == NULL || inbuflen < 0 || out == NULL || algo == NULL) {
            BIO_printf(bio_err, "No input, output or algorithm specified\n");
            goto end;
        }

        if (OPENSSL_strcasecmp(algo, "sm2") == 0) {
            if (index < 0) {
                BIO_printf(bio_err, "No SM2 key index specified\n");
                goto end;
            }

            if (encrypt)
                outbuf = TSAPI_SM2EncryptWithISK(index, inbuf, inbuflen,
                                                 &outbuflen);
            else
                outbuf = TSAPI_SM2DecryptWithISK(index, inbuf, inbuflen,
                                                 &outbuflen);
        } else {
            if (OPENSSL_strcasecmp(algo, "sm4-ecb") == 0)
                mode = OSSL_SGD_SM4_ECB;
            else if (OPENSSL_strcasecmp(algo, "sm4-cbc") == 0)
                mode = OSSL_SGD_SM4_CBC;
            else if (OPENSSL_strcasecmp(algo, "sm4-cfb") == 0)
                mode = OSSL_SGD_SM4_CFB;
            else if (OPENSSL_strcasecmp(algo, "sm4-ofb") == 0)
                mode = OSSL_SGD_SM4_OFB;
            else {
                BIO_printf(bio_err, "Unknown algorithm %s\n", algo);
                goto end;
            }

            if (hexiv) {
                iv = OPENSSL_hexstr2buf(hexiv, NULL);
                if (iv == NULL) {
                    BIO_printf(bio_err, "Error reading IV\n");
                    goto end;
                }
            }

            if (OPENSSL_strcasecmp(isktype, "sm2") == 0) {
                if (encrypt) {
                    if ((outbuf = TSAPI_SM4Encrypt(mode, inkey, keylen, isk, iv,
                                                   inbuf, inbuflen, &outbuflen))
                                        == NULL) {
                        BIO_printf(bio_err, "Failed to encrypt data\n");
                        goto end;
                    }
                } else {
                    if ((outbuf = TSAPI_SM4Decrypt(mode, inkey, keylen, isk, iv,
                                                   inbuf, inbuflen, &outbuflen))
                                        == NULL) {
                        BIO_printf(bio_err, "Failed to decrypt data\n");
                        goto end;
                    }
                }
            } else {
                BIO_printf(bio_err, "Unknown ISK type %s\n", isktype);
                goto end;
            }
        }

        if (BIO_write(out, outbuf, outbuflen) != (int)outbuflen) {
            BIO_printf(bio_err, "Failed to write output\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    ret = 0;
end:
    OPENSSL_free(iv);
    OPENSSL_free(inbuf);
    OPENSSL_free(outbuf);
    BIO_free(in);
    BIO_free(out);
    OPENSSL_free(inkey);
    BIO_free(outdek);
    BIO_free(key_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer);
    BIO_free(outkey);
    OPENSSL_free(priv);
    OPENSSL_free(pub);
    OPENSSL_free(outevlp);
    return ret;
}
