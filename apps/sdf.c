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
#include <openssl/sdf.h>
#include <openssl/bio.h>
#include <openssl/tsapi.h>
#include <openssl/ec.h>
#include <openssl/sgd.h>
#include "apps.h"
#include "progs.h"

// #define DEBUG

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_VERSION,
    OPT_DEVICE_INFO,
    OPT_RANDOM,
    OPT_EXPORT_ENCPUBKEY_ECC,
    OPT_EXPORT_SIGNPUBKEY_ECC,
    OPT_EXPORT_ENCPUBKEY_RSA,
    OPT_EXPORT_SIGNPUBKEY_RSA,
    OPT_GENERATEKEYWITH_KEK,
    OPT_GENERATEKEYWITH_IPK_RSA,
    OPT_GENERATEKEYWITH_EPK_RSA,
    OPT_GENERATEKEYWITH_IPK_ECC,
    OPT_GENERATEKEYWITH_EPK_ECC,
    OPT_IMPORTKEYWITH_KEK,
    OPT_IMPORTKEYWITH_ISK_RSA,
    OPT_IMPORTKEYWITH_ISK_ECC,
    OPT_EXTRSATEST,
    OPT_INTRSATEST,
    OPT_INTECCSIGNTEST,
    OPT_EXTECCSIGNTEST,
    OPT_EXTECCENTEST,
    OPT_SYMENCDECTEST,
    OPT_CALCULATEMAC
} OPTION_CHOICE;

const OPTIONS sdf_options[] = {
    OPT_SECTION("General: Device Management Options\n"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"version", OPT_VERSION, '-', "Display version information"},
    {"device-info", OPT_DEVICE_INFO, '-', "Display device information"},
    {"random", OPT_RANDOM, 's', "Generate random number of specified length"},

    OPT_SECTION("Export: Asymmetric Public Key Export Options:\n"),
    {"export-encpubkey-ecc", OPT_EXPORT_ENCPUBKEY_ECC, 's', "Export ECC encryption public key"},
    {"export-signpubkey-ecc", OPT_EXPORT_SIGNPUBKEY_ECC, 's', "Export ECC signature public key"},
    {"export-encpubkey-rsa", OPT_EXPORT_ENCPUBKEY_RSA, 's', "Export RSA encryption public key"},
    {"export-signpubkey-rsa", OPT_EXPORT_SIGNPUBKEY_RSA, 's', "Export RSA signature public key"},

    OPT_SECTION("Generation: Session Key Generation Options:\n"),
    {"generatekeywith-kek", OPT_GENERATEKEYWITH_KEK, 's', "Generate session key using KEK"},
    {"generatekeywith-ipk-rsa", OPT_GENERATEKEYWITH_IPK_RSA, 's', "Generate session key using RSA internal public key"},
    {"generatekeywith-epk-rsa", OPT_GENERATEKEYWITH_EPK_RSA, 's', "Generate session key using RSA external public key"},
    {"generatekeywith-ipk-ecc", OPT_GENERATEKEYWITH_IPK_ECC, 's', "Generate session key using ECC internal public key"},
    {"generatekeywith-epk-ecc", OPT_GENERATEKEYWITH_EPK_ECC, 's', "Generate session key using ECC external public key"},

    OPT_SECTION("Import: Session Key Import Options:\n"),
    {"importkeywith-kek", OPT_IMPORTKEYWITH_KEK, 's', "Import session key using KEK"},
    {"importkeywith-isk-rsa", OPT_IMPORTKEYWITH_ISK_RSA, 's', "Import session key using RSA internal private key"},
    {"importkeywith-isk-ecc", OPT_IMPORTKEYWITH_ISK_ECC, 's', "Import session key using ECC internal private key"},

    OPT_SECTION("Crypto: Operation Test Options:\n"),
    {"extrsatest", OPT_EXTRSATEST, '-', "External RSA operation test"},
    {"intrsatest", OPT_INTRSATEST, '-', "Internal RSA operation test"},
    {"inteccsigntest", OPT_INTECCSIGNTEST, '-', "Internal ECC signature test"},
    {"exteccsigntest", OPT_EXTECCSIGNTEST, '-', "External ECC signature test"},
    {"exteccenctest", OPT_EXTECCENTEST, '-', "External ECC encryption test"},
    {"symencdectest", OPT_SYMENCDECTEST, '-', "Symmetric encryption/decryption test"},
    {"calculatemac", OPT_CALCULATEMAC, '-', "Calculate MAC test"},

    OPT_PARAMETERS(),
    {"INDEX", 0, ' ', "Key index number (1-100)"},
    {"LENGTH", 0, ' ', "Random number length in bytes"},
    {NULL}
};

static int parse_index(const char *arg)
{
    int index = atoi(arg);
    if (index < 1 || index > 100) {
        BIO_printf(bio_err, "Error: INDEX must be between 1 and 100\n");
        return -1;
    }
    return index;
}

static int parse_length(const char *arg)
{
    int length = atoi(arg);
    if (length <= 0) {
        BIO_printf(bio_err, "Error: LENGTH must be positive\n");
        return -1;
    }
    return length;
}

static void print_version(void)
{
    BIO_printf(bio_out, "SDF Command Line Tool\n");
    BIO_printf(bio_out, "Based on GM/T 0018-2012 Standard\n");
    BIO_printf(bio_out, "Built with Tongsuo Project\n");


}

/* 测试函数 */
void TestAll(){
    TSAPI_Device();
    TSAPI_Session();
    TSAPI_GetDeviceInfo();
    TSAPI_GenerateRandom(1024);
    TSAPI_PrivateKeyAccessRight();
    TSAPI_ExportEncPublicKey_ECC(1);
    TSAPI_ExportSignPublicKey_ECC(1);
    TSAPI_ExportEncPublic_RSA(1);
    TSAPI_ExportSignPublicKey_RSA(1);
    TSAPI_GenerateKeyWithKEK(1);
    TSAPI_GenerateKeyWithIPK_RSA(1);
    TSAPI_GenerateKeyWithEPK_RSA(1);
    TSAPI_GenerateKeyWithIPK_ECC(1);
    TSAPI_GenerateKeyWithEPK_ECC(1);
    TSAPI_ImportKeyWithKEK(1);
    TSAPI_ImportKeyWithISK_RSA(1);
    TSAPI_ImportKeyWithISK_ECC(1);
    ExtRSAOptTest();
    IntRSAOptTest();
    IntECCSignTest();
    ExtECCSignTest();
    ExtECCOptTest();
    SymmEncDecTest();
    TSAPI_CalculateMAC();
}

int sdf_main(int argc, char **argv)
{
    OPTION_CHOICE o;
    int ret = 1;
    char *prog;
    
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
        case OPT_VERSION:
            print_version();
            ret = 0;
            goto end;
        case OPT_DEVICE_INFO:
            if (TSAPI_GetDeviceInfo()) {
                BIO_printf(bio_err, "Error: Failed to get device info\n");
                goto end;
            }
            break;
        case OPT_RANDOM:
            {
                int length = parse_length(opt_arg());
                if (length <= 0) goto end;
                if (TSAPI_GenerateRandom(length)) {
                    BIO_printf(bio_err, "Error: Failed to generate random\n");
                    goto end;
                }
            }
            break;
        case OPT_EXPORT_ENCPUBKEY_ECC:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ExportEncPublicKey_ECC(index)) {
                    BIO_printf(bio_err, "Error: Failed to export ECC encryption public key\n");
                    goto end;
                }
            }
            break;
        case OPT_EXPORT_SIGNPUBKEY_ECC:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ExportSignPublicKey_ECC(index)) {
                    BIO_printf(bio_err, "Error: Failed to export ECC signature public key\n");
                    goto end;
                }
            }
            break;
        case OPT_EXPORT_ENCPUBKEY_RSA:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ExportEncPublic_RSA(index)) {
                    BIO_printf(bio_err, "Error: Failed to export RSA encryption public key\n");
                    goto end;
                }
            }
            break;
        case OPT_EXPORT_SIGNPUBKEY_RSA:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ExportSignPublicKey_RSA(index)) {
                    BIO_printf(bio_err, "Error: Failed to export RSA signature public key\n");
                    goto end;
                }
            }
            break;
        case OPT_GENERATEKEYWITH_KEK:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_GenerateKeyWithKEK(index)) {
                    BIO_printf(bio_err, "Error: Failed to generate key with KEK\n");
                    goto end;
                }
            }
            break;
        case OPT_GENERATEKEYWITH_IPK_RSA:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_GenerateKeyWithIPK_RSA(index)) {
                    BIO_printf(bio_err, "Error: Failed to generate key with RSA internal public key\n");
                    goto end;
                }
            }
            break;
        case OPT_GENERATEKEYWITH_EPK_RSA:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_GenerateKeyWithEPK_RSA(index)) {
                    BIO_printf(bio_err, "Error: Failed to generate key with RSA external public key\n");
                    goto end;
                }
            }
            break;
        case OPT_GENERATEKEYWITH_IPK_ECC:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_GenerateKeyWithIPK_ECC(index)) {
                    BIO_printf(bio_err, "Error: Failed to generate key with ECC internal public key\n");
                    goto end;
                }
            }
            break;
        case OPT_GENERATEKEYWITH_EPK_ECC:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_GenerateKeyWithEPK_ECC(index)) {
                    BIO_printf(bio_err, "Error: Failed to generate key with ECC external public key\n");
                    goto end;
                }
            }
            break;
        case OPT_IMPORTKEYWITH_KEK:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ImportKeyWithKEK(index)) {
                    BIO_printf(bio_err, "Error: Failed to import key with KEK\n");
                    goto end;
                }
            }
            break;
        case OPT_IMPORTKEYWITH_ISK_RSA:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ImportKeyWithISK_RSA(index)) {
                    BIO_printf(bio_err, "Error: Failed to import key with RSA internal private key\n");
                    goto end;
                }
            }
            break;
        case OPT_IMPORTKEYWITH_ISK_ECC:
            {
                int index = parse_index(opt_arg());
                if (index < 0) goto end;
                if (TSAPI_ImportKeyWithISK_ECC(index)) {
                    BIO_printf(bio_err, "Error: Failed to import key with ECC internal private key\n");
                    goto end;
                }
            }
            break;
        case OPT_EXTRSATEST:
            ExtRSAOptTest();

            break;
        case OPT_INTRSATEST:
            IntRSAOptTest();

            break;
        case OPT_INTECCSIGNTEST:
            IntECCSignTest();

            break;
        case OPT_EXTECCSIGNTEST:
            ExtECCSignTest();
            break;
        case OPT_EXTECCENTEST:
            ExtECCOptTest();
            break;
        case OPT_SYMENCDECTEST:
            SymmEncDecTest();
            break;
        case OPT_CALCULATEMAC:
            TSAPI_CalculateMAC();
            break;

        }
    }

    if (argc == 1) {
        BIO_printf(bio_err, "No options specified. Use -help for usage information.\n");
        goto opthelp;
    }


    ret = 0;

end:
    #ifdef DEBUG
    TestAll();
    #endif
    
    return ret;
}