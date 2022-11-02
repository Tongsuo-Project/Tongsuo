/*
 * Copyright 1995-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#undef SECONDS
#define SECONDS          3
#define PKEY_SECONDS    10
#define EC_ELGAMAL_SECONDS      10
#define PAILLIER_SECONDS        10

#define RSA_SECONDS     PKEY_SECONDS
#define DSA_SECONDS     PKEY_SECONDS
#define ECDSA_SECONDS   PKEY_SECONDS
#define ECDH_SECONDS    PKEY_SECONDS
#define EdDSA_SECONDS   PKEY_SECONDS
#define SM2_SECONDS     PKEY_SECONDS
#define FFDH_SECONDS    PKEY_SECONDS

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "apps.h"
#include "progs.h"
#include "internal/numbers.h"
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include <openssl/async.h>
#if !defined(OPENSSL_SYS_MSDOS)
# include <unistd.h>
#endif

#if defined(__TANDEM)
# if defined(OPENSSL_TANDEM_FLOSS)
#  include <floss.h(floss_fork)>
# endif
#endif

#if defined(_WIN32)
# include <windows.h>
#endif

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include "./testrsa.h"
#ifndef OPENSSL_NO_DH
# include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_PAILLIER
# include <openssl/paillier.h>
#endif
#include <openssl/x509.h>
#include <openssl/dsa.h>
#include "./testdsa.h"
#include <openssl/modes.h>

#ifndef HAVE_FORK
# if defined(OPENSSL_SYS_WINDOWS) || defined(OPENSSL_SYS_VXWORKS)
#  define HAVE_FORK 0
# else
#  define HAVE_FORK 1
# endif
#endif

#if HAVE_FORK
# undef NO_FORK
#else
# define NO_FORK
#endif

#define MAX_MISALIGNMENT 63
#define MAX_ECDH_SIZE   256
#define MISALIGN        64
#define MAX_FFDH_SIZE 1024

#ifndef RSA_DEFAULT_PRIME_NUM
# define RSA_DEFAULT_PRIME_NUM 2
#endif

typedef struct openssl_speed_sec_st {
    int sym;
    int rsa;
    int dsa;
    int ecdsa;
    int ecdh;
    int eddsa;
    int sm2;
    int ffdh;
    int ec_elgamal;
    int paillier;
} openssl_speed_sec_t;

static volatile int run = 0;

static int mr = 0;  /* machine-readeable output format to merge fork results */
static int usertime = 1;

#ifndef OPENSSL_NO_EC_ELGAMAL
static int EC_ELGAMAL_loop(void *args);
static void ec_elgamal_print_message(const char *str, const char *str2,
                                     long num, int tm, int flag);
#endif

#ifndef OPENSSL_NO_PAILLIER
static int PAILLIER_loop(void *args);
static void paillier_print_message(const char *str, const char *str2,
                                   long num, int tm);
#endif

static double Time_F(int s);
static void print_message(const char *s, long num, int length, int tm);
static void pkey_print_message(const char *str, const char *str2,
                               long num, unsigned int bits, int sec);
static void print_result(int alg, int run_no, int count, double time_used);
#ifndef NO_FORK
static int do_multi(int multi, int size_num);
#endif

static const int lengths_list[] = {
    16, 64, 256, 1024, 8 * 1024, 16 * 1024
};
#define SIZE_NUM         OSSL_NELEM(lengths_list)
static const int *lengths = lengths_list;

static const int aead_lengths_list[] = {
    2, 31, 136, 1024, 8 * 1024, 16 * 1024
};

#define START   0
#define STOP    1

#ifdef SIGALRM

static void alarmed(int sig)
{
    signal(SIGALRM, alarmed);
    run = 0;
}

static double Time_F(int s)
{
    double ret = app_tminterval(s, usertime);
    if (s == STOP)
        alarm(0);
    return ret;
}

#elif defined(_WIN32)

# define SIGALRM -1

static unsigned int lapse;
static volatile unsigned int schlock;
static void alarm_win32(unsigned int secs)
{
    lapse = secs * 1000;
}

# define alarm alarm_win32

static DWORD WINAPI sleepy(VOID * arg)
{
    schlock = 1;
    Sleep(lapse);
    run = 0;
    return 0;
}

static double Time_F(int s)
{
    double ret;
    static HANDLE thr;

    if (s == START) {
        schlock = 0;
        thr = CreateThread(NULL, 4096, sleepy, NULL, 0, NULL);
        if (thr == NULL) {
            DWORD err = GetLastError();
            BIO_printf(bio_err, "unable to CreateThread (%lu)", err);
            ExitProcess(err);
        }
        while (!schlock)
            Sleep(0);           /* scheduler spinlock */
        ret = app_tminterval(s, usertime);
    } else {
        ret = app_tminterval(s, usertime);
        if (run)
            TerminateThread(thr, 0);
        CloseHandle(thr);
    }

    return ret;
}
#else
# error "SIGALRM not defined and the platform is not Windows"
#endif

static void multiblock_speed(const EVP_CIPHER *evp_cipher, int lengths_single,
                             const openssl_speed_sec_t *seconds);

static int opt_found(const char *name, unsigned int *result,
                     const OPT_PAIR pairs[], unsigned int nbelem)
{
    unsigned int idx;

    for (idx = 0; idx < nbelem; ++idx, pairs++)
        if (strcmp(name, pairs->name) == 0) {
            *result = pairs->retval;
            return 1;
        }
    return 0;
}
#define opt_found(value, pairs, result)\
    opt_found(value, result, pairs, OSSL_NELEM(pairs))

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_ELAPSED, OPT_EVP, OPT_HMAC, OPT_DECRYPT, OPT_ENGINE, OPT_MULTI,
    OPT_MR, OPT_MB, OPT_MISALIGN, OPT_ASYNCJOBS, OPT_R_ENUM, OPT_PROV_ENUM,
    OPT_PRIMES, OPT_SECONDS, OPT_BYTES, OPT_AEAD, OPT_CMAC
} OPTION_CHOICE;

const OPTIONS speed_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] [algorithm...]\n"},

    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"mb", OPT_MB, '-',
     "Enable (tls1>=1) multi-block mode on EVP-named cipher"},
    {"mr", OPT_MR, '-', "Produce machine readable output"},
#ifndef NO_FORK
    {"multi", OPT_MULTI, 'p', "Run benchmarks in parallel"},
#endif
#ifndef OPENSSL_NO_ASYNC
    {"async_jobs", OPT_ASYNCJOBS, 'p',
     "Enable async mode and start specified number of jobs"},
#endif
#ifndef OPENSSL_NO_ENGINE
    {"engine", OPT_ENGINE, 's', "Use engine, possibly a hardware device"},
#endif
    {"primes", OPT_PRIMES, 'p', "Specify number of primes (for RSA only)"},

    OPT_SECTION("Selection"),
    {"evp", OPT_EVP, 's', "Use EVP-named cipher or digest"},
    {"hmac", OPT_HMAC, 's', "HMAC using EVP-named digest"},
    {"cmac", OPT_CMAC, 's', "CMAC using EVP-named cipher"},
    {"decrypt", OPT_DECRYPT, '-',
     "Time decryption instead of encryption (only EVP)"},
    {"aead", OPT_AEAD, '-',
     "Benchmark EVP-named AEAD cipher in TLS-like sequence"},

    OPT_SECTION("Timing"),
    {"elapsed", OPT_ELAPSED, '-',
     "Use wall-clock time instead of CPU user time as divisor"},
    {"seconds", OPT_SECONDS, 'p',
     "Run benchmarks for specified amount of seconds"},
    {"bytes", OPT_BYTES, 'p',
     "Run [non-PKI] benchmarks on custom-sized buffer"},
    {"misalign", OPT_MISALIGN, 'p',
     "Use specified offset to mis-align buffers"},

    OPT_R_OPTIONS,
    OPT_PROV_OPTIONS,

    OPT_PARAMETERS(),
    {"algorithm", 0, 0, "Algorithm(s) to test (optional; otherwise tests all)"},
    {NULL}
};

enum {
    D_MD5, D_SHA1,
    D_SHA256, D_SHA512, D_HMAC,
    D_CBC_DES, D_EDE3_DES, D_RC4,
    D_CBC_RC5,
    D_CBC_128_AES, D_CBC_192_AES, D_CBC_256_AES,
    D_EVP, D_GHASH, D_RAND, D_EVP_CMAC, D_SM3, D_CBC_SM4, ALGOR_NUM
};
/* name of algorithms to test. MUST BE KEEP IN SYNC with above enum ! */
static const char *names[ALGOR_NUM] = {
    "md5", "sha1",
    "sha256", "sha512", "hmac(md5)",
    "des-cbc", "des-ede3", "rc4",
    "rc5-cbc",
    "aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
    "evp", "ghash", "rand", "cmac", "sm3", "sm4"
};

/* list of configured algorithm (remaining), with some few alias */
static const OPT_PAIR doit_choices[] = {
    {"md5", D_MD5},
    {"hmac", D_HMAC},
    {"sha1", D_SHA1},
    {"sha256", D_SHA256},
    {"sha512", D_SHA512},
    {"rc4", D_RC4},
    {"des-cbc", D_CBC_DES},
    {"des-ede3", D_EDE3_DES},
    {"aes-128-cbc", D_CBC_128_AES},
    {"aes-192-cbc", D_CBC_192_AES},
    {"aes-256-cbc", D_CBC_256_AES},
    {"rc5-cbc", D_CBC_RC5},
    {"rc5", D_CBC_RC5},
    {"ghash", D_GHASH},
    {"rand", D_RAND},
#ifndef OPENSSL_NO_SM3
    {"sm3", D_SM3},
#endif
#ifndef OPENSSL_NO_SM4
    {"sm4-cbc", D_CBC_SM4},
    {"sm4", D_CBC_SM4},
#endif
};

static double results[ALGOR_NUM][SIZE_NUM];

enum { R_DSA_512, R_DSA_1024, R_DSA_2048, DSA_NUM };
static const OPT_PAIR dsa_choices[DSA_NUM] = {
    {"dsa512", R_DSA_512},
    {"dsa1024", R_DSA_1024},
    {"dsa2048", R_DSA_2048}
};
static double dsa_results[DSA_NUM][2];  /* 2 ops: sign then verify */

enum {
    R_RSA_512, R_RSA_1024, R_RSA_2048, R_RSA_3072, R_RSA_4096, R_RSA_7680,
    R_RSA_15360, RSA_NUM
};
static const OPT_PAIR rsa_choices[RSA_NUM] = {
    {"rsa512", R_RSA_512},
    {"rsa1024", R_RSA_1024},
    {"rsa2048", R_RSA_2048},
    {"rsa3072", R_RSA_3072},
    {"rsa4096", R_RSA_4096},
    {"rsa7680", R_RSA_7680},
    {"rsa15360", R_RSA_15360}
};

static double rsa_results[RSA_NUM][2];  /* 2 ops: sign then verify */

#ifndef OPENSSL_NO_DH
enum ff_params_t {
    R_FFDH_2048, R_FFDH_3072, R_FFDH_4096, R_FFDH_6144, R_FFDH_8192, FFDH_NUM
};

static const OPT_PAIR ffdh_choices[FFDH_NUM] = {
    {"ffdh2048", R_FFDH_2048},
    {"ffdh3072", R_FFDH_3072},
    {"ffdh4096", R_FFDH_4096},
    {"ffdh6144", R_FFDH_6144},
    {"ffdh8192", R_FFDH_8192},
};

static double ffdh_results[FFDH_NUM][1];  /* 1 op: derivation */
#endif /* OPENSSL_NO_DH */

enum ec_curves_t {
    R_EC_P160, R_EC_P192, R_EC_P224, R_EC_P256, R_EC_P384, R_EC_P521,
#ifndef OPENSSL_NO_EC2M
    R_EC_K163, R_EC_K233, R_EC_K283, R_EC_K409, R_EC_K571,
    R_EC_B163, R_EC_B233, R_EC_B283, R_EC_B409, R_EC_B571,
#endif
    R_EC_BRP256R1, R_EC_BRP256T1, R_EC_BRP384R1, R_EC_BRP384T1,
    R_EC_BRP512R1, R_EC_BRP512T1, ECDSA_NUM
};
/* list of ecdsa curves */
static const OPT_PAIR ecdsa_choices[ECDSA_NUM] = {
    {"ecdsap160", R_EC_P160},
    {"ecdsap192", R_EC_P192},
    {"ecdsap224", R_EC_P224},
    {"ecdsap256", R_EC_P256},
    {"ecdsap384", R_EC_P384},
    {"ecdsap521", R_EC_P521},
#ifndef OPENSSL_NO_EC2M
    {"ecdsak163", R_EC_K163},
    {"ecdsak233", R_EC_K233},
    {"ecdsak283", R_EC_K283},
    {"ecdsak409", R_EC_K409},
    {"ecdsak571", R_EC_K571},
    {"ecdsab163", R_EC_B163},
    {"ecdsab233", R_EC_B233},
    {"ecdsab283", R_EC_B283},
    {"ecdsab409", R_EC_B409},
    {"ecdsab571", R_EC_B571},
#endif
    {"ecdsabrp256r1", R_EC_BRP256R1},
    {"ecdsabrp256t1", R_EC_BRP256T1},
    {"ecdsabrp384r1", R_EC_BRP384R1},
    {"ecdsabrp384t1", R_EC_BRP384T1},
    {"ecdsabrp512r1", R_EC_BRP512R1},
    {"ecdsabrp512t1", R_EC_BRP512T1}
};
enum { R_EC_X25519 = ECDSA_NUM, R_EC_X448, EC_NUM };
/* list of ecdh curves, extension of |ecdsa_choices| list above */
static const OPT_PAIR ecdh_choices[EC_NUM] = {
    {"ecdhp160", R_EC_P160},
    {"ecdhp192", R_EC_P192},
    {"ecdhp224", R_EC_P224},
    {"ecdhp256", R_EC_P256},
    {"ecdhp384", R_EC_P384},
    {"ecdhp521", R_EC_P521},
#ifndef OPENSSL_NO_EC2M
    {"ecdhk163", R_EC_K163},
    {"ecdhk233", R_EC_K233},
    {"ecdhk283", R_EC_K283},
    {"ecdhk409", R_EC_K409},
    {"ecdhk571", R_EC_K571},
    {"ecdhb163", R_EC_B163},
    {"ecdhb233", R_EC_B233},
    {"ecdhb283", R_EC_B283},
    {"ecdhb409", R_EC_B409},
    {"ecdhb571", R_EC_B571},
#endif
    {"ecdhbrp256r1", R_EC_BRP256R1},
    {"ecdhbrp256t1", R_EC_BRP256T1},
    {"ecdhbrp384r1", R_EC_BRP384R1},
    {"ecdhbrp384t1", R_EC_BRP384T1},
    {"ecdhbrp512r1", R_EC_BRP512R1},
    {"ecdhbrp512t1", R_EC_BRP512T1},
    {"ecdhx25519", R_EC_X25519},
    {"ecdhx448", R_EC_X448}
};

static double ecdh_results[EC_NUM][1];      /* 1 op: derivation */
static double ecdsa_results[ECDSA_NUM][2];  /* 2 ops: sign then verify */

enum { R_EC_Ed25519, R_EC_Ed448, EdDSA_NUM };
static const OPT_PAIR eddsa_choices[EdDSA_NUM] = {
    {"ed25519", R_EC_Ed25519},
    {"ed448", R_EC_Ed448}

};
static double eddsa_results[EdDSA_NUM][2];    /* 2 ops: sign then verify */

#ifndef OPENSSL_NO_SM2
enum { R_EC_CURVESM2, SM2_NUM };
static const OPT_PAIR sm2_choices[SM2_NUM] = {
    {"curveSM2", R_EC_CURVESM2}
};
# define SM2_ID        "TLSv1.3+GM+Cipher+Suite"
# define SM2_ID_LEN    sizeof("TLSv1.3+GM+Cipher+Suite") - 1
static double sm2_results[SM2_NUM][2];    /* 2 ops: sign then verify */
#endif /* OPENSSL_NO_SM2 */

#ifndef OPENSSL_NO_EC_ELGAMAL
enum {
    R_EC_ELGAMAL_P160,
    R_EC_ELGAMAL_P192,
    R_EC_ELGAMAL_P224,
    R_EC_ELGAMAL_P256,
    R_EC_ELGAMAL_P384,
    R_EC_ELGAMAL_P521,
# ifndef OPENSSL_NO_EC2M
    R_EC_ELGAMAL_K163,
    R_EC_ELGAMAL_K233,
    R_EC_ELGAMAL_K283,
    R_EC_ELGAMAL_K409,
    R_EC_ELGAMAL_K571,
    R_EC_ELGAMAL_B163,
    R_EC_ELGAMAL_B233,
    R_EC_ELGAMAL_B283,
    R_EC_ELGAMAL_B409,
    R_EC_ELGAMAL_B571,
# endif
    R_EC_ELGAMAL_BRP256R1,
    R_EC_ELGAMAL_BRP256T1,
    R_EC_ELGAMAL_BRP384R1,
    R_EC_ELGAMAL_BRP384T1,
    R_EC_ELGAMAL_BRP512R1,
    R_EC_ELGAMAL_BRP512T1,
# ifndef OPENSSL_NO_SM2
    R_EC_ELGAMAL_SM2
# endif
};

static OPT_PAIR ec_elgamal_choices[] = {
    {"ecelgamalp160", R_EC_ELGAMAL_P160},
    {"ecelgamalp192", R_EC_ELGAMAL_P192},
    {"ecelgamalp224", R_EC_ELGAMAL_P224},
    {"ecelgamalp256", R_EC_ELGAMAL_P256},
    {"ecelgamalp384", R_EC_ELGAMAL_P384},
    {"ecelgamalp521", R_EC_ELGAMAL_P521},
# ifndef OPENSSL_NO_EC2M
    {"ecelgamalk163", R_EC_ELGAMAL_K163},
    {"ecelgamalk233", R_EC_ELGAMAL_K233},
    {"ecelgamalk283", R_EC_ELGAMAL_K283},
    {"ecelgamalk409", R_EC_ELGAMAL_K409},
    {"ecelgamalk571", R_EC_ELGAMAL_K571},
    {"ecelgamalb163", R_EC_ELGAMAL_B163},
    {"ecelgamalb233", R_EC_ELGAMAL_B233},
    {"ecelgamalb283", R_EC_ELGAMAL_B283},
    {"ecelgamalb409", R_EC_ELGAMAL_B409},
    {"ecelgamalb571", R_EC_ELGAMAL_B571},
# endif
    {"ecelgamalbrp256r1", R_EC_ELGAMAL_BRP256R1},
    {"ecelgamalbrp256t1", R_EC_ELGAMAL_BRP256T1},
    {"ecelgamalbrp384r1", R_EC_ELGAMAL_BRP384R1},
    {"ecelgamalbrp384t1", R_EC_ELGAMAL_BRP384T1},
    {"ecelgamalbrp512r1", R_EC_ELGAMAL_BRP512R1},
    {"ecelgamalbrp512t1", R_EC_ELGAMAL_BRP512T1},
# ifndef OPENSSL_NO_SM2
    {"ecelgamalsm2", R_EC_ELGAMAL_SM2}
# endif
};

static int ec_elgamal_plaintexts[] = {10, 100000, 100000000,
                                      -10, -100000, -100000000};

# define EC_ELGAMAL_NUM                  OSSL_NELEM(ec_elgamal_choices)
# define EC_ELGAMAL_PLAINTEXTS_NUM       OSSL_NELEM(ec_elgamal_plaintexts)

static double ec_elgamal_results[EC_ELGAMAL_NUM][EC_ELGAMAL_PLAINTEXTS_NUM][6];

#endif /* OPENSSL_NO_EC_ELGAMAL */

#ifndef OPENSSL_NO_PAILLIER
enum {
    R_PAILLIER_G_OPTIMIZE,
};

static OPT_PAIR paillier_choices[] = {
    {"ecelgamalp160", R_PAILLIER_G_OPTIMIZE},
};

static int paillier_plaintexts[] = {10, 100000, 100000000, -10, -100000, -100000000};

# define PAILLIER_NUM                    OSSL_NELEM(paillier_choices)
# define PAILLIER_PLAINTEXTS_NUM         OSSL_NELEM(paillier_plaintexts)

static double paillier_results[PAILLIER_NUM][PAILLIER_PLAINTEXTS_NUM][6];

#endif /* OPENSSL_NO_PAILLIER */

#define COND(unused_cond) (run && count < INT_MAX)
#define COUNT(d) (count)

typedef struct loopargs_st {
    ASYNC_JOB *inprogress_job;
    ASYNC_WAIT_CTX *wait_ctx;
    unsigned char *buf;
    unsigned char *buf2;
    unsigned char *buf_malloc;
    unsigned char *buf2_malloc;
    unsigned char *key;
    size_t buflen;
    size_t sigsize;
    EVP_PKEY_CTX *rsa_sign_ctx[RSA_NUM];
    EVP_PKEY_CTX *rsa_verify_ctx[RSA_NUM];
    EVP_PKEY_CTX *dsa_sign_ctx[DSA_NUM];
    EVP_PKEY_CTX *dsa_verify_ctx[DSA_NUM];
    EVP_PKEY_CTX *ecdsa_sign_ctx[ECDSA_NUM];
    EVP_PKEY_CTX *ecdsa_verify_ctx[ECDSA_NUM];
    EVP_PKEY_CTX *ecdh_ctx[EC_NUM];
    EVP_MD_CTX *eddsa_ctx[EdDSA_NUM];
    EVP_MD_CTX *eddsa_ctx2[EdDSA_NUM];
#ifndef OPENSSL_NO_SM2
    EVP_MD_CTX *sm2_ctx[SM2_NUM];
    EVP_MD_CTX *sm2_vfy_ctx[SM2_NUM];
    EVP_PKEY *sm2_pkey[SM2_NUM];
#endif
#ifndef OPENSSL_NO_EC_ELGAMAL
    EC_KEY *ec_elgamal_key[EC_ELGAMAL_NUM];
    EC_ELGAMAL_CTX *ec_elgamal_ctx[EC_ELGAMAL_NUM];
    EC_ELGAMAL_CIPHERTEXT *ciphertext_a[EC_ELGAMAL_NUM];
    EC_ELGAMAL_CIPHERTEXT *ciphertext_b[EC_ELGAMAL_NUM];
    EC_ELGAMAL_CIPHERTEXT *ciphertext_r[EC_ELGAMAL_NUM];
    EC_ELGAMAL_DECRYPT_TABLE *decrypt_table[EC_ELGAMAL_NUM][2];
#endif
#ifndef OPENSSL_NO_PAILLIER
    PAILLIER_KEY *paillier_key[PAILLIER_NUM];
    PAILLIER_CTX *paillier_ctx[PAILLIER_NUM];
    PAILLIER_CIPHERTEXT *paillier_ciphertext_a[PAILLIER_NUM];
    PAILLIER_CIPHERTEXT *paillier_ciphertext_b[PAILLIER_NUM];
    PAILLIER_CIPHERTEXT *paillier_ciphertext_r[PAILLIER_NUM];
#endif
    unsigned char *secret_a;
    unsigned char *secret_b;
    size_t outlen[EC_NUM];
#ifndef OPENSSL_NO_DH
    EVP_PKEY_CTX *ffdh_ctx[FFDH_NUM];
    unsigned char *secret_ff_a;
    unsigned char *secret_ff_b;
#endif
    EVP_CIPHER_CTX *ctx;
    EVP_MAC_CTX *mctx;
} loopargs_t;
static int run_benchmark(int async_jobs, int (*loop_function) (void *),
                         loopargs_t * loopargs);

static unsigned int testnum;

/* Nb of iterations to do per algorithm and key-size */
static long c[ALGOR_NUM][SIZE_NUM];

static char *evp_mac_mdname = "md5";
static char *evp_hmac_name = NULL;
static const char *evp_md_name = NULL;
static char *evp_mac_ciphername = "aes-128-cbc";
static char *evp_cmac_name = NULL;

static int have_md(const char *name)
{
    int ret = 0;
    EVP_MD *md = NULL;

    if (opt_md_silent(name, &md)) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();

        if (ctx != NULL && EVP_DigestInit(ctx, md) > 0)
            ret = 1;
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
    }
    return ret;
}

static int have_cipher(const char *name)
{
    int ret = 0;
    EVP_CIPHER *cipher = NULL;

    if (opt_cipher_silent(name, &cipher)) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (ctx != NULL
            && EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1) > 0)
            ret = 1;
        EVP_CIPHER_CTX_free(ctx);
        EVP_CIPHER_free(cipher);
    }
    return ret;
}

static int EVP_Digest_loop(const char *mdname, int algindex, void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char digest[EVP_MAX_MD_SIZE];
    int count;
    EVP_MD *md = NULL;

    if (!opt_md_silent(mdname, &md))
        return -1;
    for (count = 0; COND(c[algindex][testnum]); count++) {
        if (!EVP_Digest(buf, (size_t)lengths[testnum], digest, NULL, md,
                        NULL)) {
            count = -1;
            break;
        }
    }
    EVP_MD_free(md);
    return count;
}

static int EVP_Digest_md_loop(void *args)
{
    return EVP_Digest_loop(evp_md_name, D_EVP, args);
}

static int MD5_loop(void *args)
{
    return EVP_Digest_loop("md5", D_MD5, args);
}

static int EVP_MAC_loop(int algindex, void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_MAC_CTX *mctx = tempargs->mctx;
    unsigned char mac[EVP_MAX_MD_SIZE];
    int count;

    for (count = 0; COND(c[algindex][testnum]); count++) {
        size_t outl;

        if (!EVP_MAC_init(mctx, NULL, 0, NULL)
            || !EVP_MAC_update(mctx, buf, lengths[testnum])
            || !EVP_MAC_final(mctx, mac, &outl, sizeof(mac)))
            return -1;
    }
    return count;
}

static int HMAC_loop(void *args)
{
    return EVP_MAC_loop(D_HMAC, args);
}

static int CMAC_loop(void *args)
{
    return EVP_MAC_loop(D_EVP_CMAC, args);
}

static int SHA1_loop(void *args)
{
    return EVP_Digest_loop("sha1", D_SHA1, args);
}

static int SHA256_loop(void *args)
{
    return EVP_Digest_loop("sha256", D_SHA256, args);
}

static int SHA512_loop(void *args)
{
    return EVP_Digest_loop("sha512", D_SHA512, args);
}

#ifndef OPENSSL_NO_SM3
static int EVP_Digest_SM3_loop(void *args)
{
    return EVP_Digest_loop("sm3", D_SM3, args);
}
#endif

static int algindex;

static int EVP_Cipher_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    int count;

    if (tempargs->ctx == NULL)
        return -1;
    for (count = 0; COND(c[algindex][testnum]); count++)
        if (EVP_Cipher(tempargs->ctx, buf, buf, (size_t)lengths[testnum]) <= 0)
            return -1;
    return count;
}

static int GHASH_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_MAC_CTX *mctx = tempargs->mctx;
    int count;

    /* just do the update in the loop to be comparable with 1.1.1 */
    for (count = 0; COND(c[D_GHASH][testnum]); count++) {
        if (!EVP_MAC_update(mctx, buf, lengths[testnum]))
            return -1;
    }
    return count;
}

#define MAX_BLOCK_SIZE 128

static unsigned char iv[2 * MAX_BLOCK_SIZE / 8];

static EVP_CIPHER_CTX *init_evp_cipher_ctx(const char *ciphername,
                                           const unsigned char *key,
                                           int keylen)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;

    if (!opt_cipher_silent(ciphername, &cipher))
        return NULL;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto end;

    if (!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 1)) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
        goto end;
    }

    if (!EVP_CIPHER_CTX_set_key_length(ctx, keylen)) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
        goto end;
    }

    if (!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1)) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
        goto end;
    }

end:
    EVP_CIPHER_free(cipher);
    return ctx;
}

static int RAND_bytes_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    int count;

    for (count = 0; COND(c[D_RAND][testnum]); count++)
        RAND_bytes(buf, lengths[testnum]);
    return count;
}

static int decrypt = 0;
static int EVP_Update_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_CIPHER_CTX *ctx = tempargs->ctx;
    int outl, count, rc;

    if (decrypt) {
        for (count = 0; COND(c[D_EVP][testnum]); count++) {
            rc = EVP_DecryptUpdate(ctx, buf, &outl, buf, lengths[testnum]);
            if (rc != 1) {
                /* reset iv in case of counter overflow */
                EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1);
            }
        }
    } else {
        for (count = 0; COND(c[D_EVP][testnum]); count++) {
            rc = EVP_EncryptUpdate(ctx, buf, &outl, buf, lengths[testnum]);
            if (rc != 1) {
                /* reset iv in case of counter overflow */
                EVP_CipherInit_ex(ctx, NULL, NULL, NULL, iv, -1);
            }
        }
    }
    if (decrypt)
        EVP_DecryptFinal_ex(ctx, buf, &outl);
    else
        EVP_EncryptFinal_ex(ctx, buf, &outl);
    return count;
}

/*
 * CCM does not support streaming. For the purpose of performance measurement,
 * each message is encrypted using the same (key,iv)-pair. Do not use this
 * code in your application.
 */
static int EVP_Update_loop_ccm(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_CIPHER_CTX *ctx = tempargs->ctx;
    int outl, count;
    unsigned char tag[12];

    if (decrypt) {
        for (count = 0; COND(c[D_EVP][testnum]); count++) {
            (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, sizeof(tag),
                                      tag);
            /* reset iv */
            (void)EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv);
            /* counter is reset on every update */
            (void)EVP_DecryptUpdate(ctx, buf, &outl, buf, lengths[testnum]);
        }
    } else {
        for (count = 0; COND(c[D_EVP][testnum]); count++) {
            /* restore iv length field */
            (void)EVP_EncryptUpdate(ctx, NULL, &outl, NULL, lengths[testnum]);
            /* counter is reset on every update */
            (void)EVP_EncryptUpdate(ctx, buf, &outl, buf, lengths[testnum]);
        }
    }
    if (decrypt)
        (void)EVP_DecryptFinal_ex(ctx, buf, &outl);
    else
        (void)EVP_EncryptFinal_ex(ctx, buf, &outl);
    return count;
}

/*
 * To make AEAD benchmarking more relevant perform TLS-like operations,
 * 13-byte AAD followed by payload. But don't use TLS-formatted AAD, as
 * payload length is not actually limited by 16KB...
 */
static int EVP_Update_loop_aead(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_CIPHER_CTX *ctx = tempargs->ctx;
    int outl, count;
    unsigned char aad[13] = { 0xcc };
    unsigned char faketag[16] = { 0xcc };

    if (decrypt) {
        for (count = 0; COND(c[D_EVP][testnum]); count++) {
            (void)EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv);
            (void)EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                      sizeof(faketag), faketag);
            (void)EVP_DecryptUpdate(ctx, NULL, &outl, aad, sizeof(aad));
            (void)EVP_DecryptUpdate(ctx, buf, &outl, buf, lengths[testnum]);
            (void)EVP_DecryptFinal_ex(ctx, buf + outl, &outl);
        }
    } else {
        for (count = 0; COND(c[D_EVP][testnum]); count++) {
            (void)EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
            (void)EVP_EncryptUpdate(ctx, NULL, &outl, aad, sizeof(aad));
            (void)EVP_EncryptUpdate(ctx, buf, &outl, buf, lengths[testnum]);
            (void)EVP_EncryptFinal_ex(ctx, buf + outl, &outl);
        }
    }
    return count;
}

static long rsa_c[RSA_NUM][2];  /* # RSA iteration test */

static int RSA_sign_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t *rsa_num = &tempargs->sigsize;
    EVP_PKEY_CTX **rsa_sign_ctx = tempargs->rsa_sign_ctx;
    int ret, count;

    for (count = 0; COND(rsa_c[testnum][0]); count++) {
        *rsa_num = tempargs->buflen;
        ret = EVP_PKEY_sign(rsa_sign_ctx[testnum], buf2, rsa_num, buf, 36);
        if (ret <= 0) {
            BIO_printf(bio_err, "RSA sign failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

static int RSA_verify_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t rsa_num = tempargs->sigsize;
    EVP_PKEY_CTX **rsa_verify_ctx = tempargs->rsa_verify_ctx;
    int ret, count;

    for (count = 0; COND(rsa_c[testnum][1]); count++) {
        ret = EVP_PKEY_verify(rsa_verify_ctx[testnum], buf2, rsa_num, buf, 36);
        if (ret <= 0) {
            BIO_printf(bio_err, "RSA verify failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

#ifndef OPENSSL_NO_DH
static long ffdh_c[FFDH_NUM][1];

static int FFDH_derive_key_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    EVP_PKEY_CTX *ffdh_ctx = tempargs->ffdh_ctx[testnum];
    unsigned char *derived_secret = tempargs->secret_ff_a;
    size_t outlen = MAX_FFDH_SIZE;
    int count;

    for (count = 0; COND(ffdh_c[testnum][0]); count++)
        EVP_PKEY_derive(ffdh_ctx, derived_secret, &outlen);
    return count;
}
#endif /* OPENSSL_NO_DH */

static long dsa_c[DSA_NUM][2];
static int DSA_sign_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t *dsa_num = &tempargs->sigsize;
    EVP_PKEY_CTX **dsa_sign_ctx = tempargs->dsa_sign_ctx;
    int ret, count;

    for (count = 0; COND(dsa_c[testnum][0]); count++) {
        *dsa_num = tempargs->buflen;
        ret = EVP_PKEY_sign(dsa_sign_ctx[testnum], buf2, dsa_num, buf, 20);
        if (ret <= 0) {
            BIO_printf(bio_err, "DSA sign failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

static int DSA_verify_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t dsa_num = tempargs->sigsize;
    EVP_PKEY_CTX **dsa_verify_ctx = tempargs->dsa_verify_ctx;
    int ret, count;

    for (count = 0; COND(dsa_c[testnum][1]); count++) {
        ret = EVP_PKEY_verify(dsa_verify_ctx[testnum], buf2, dsa_num, buf, 20);
        if (ret <= 0) {
            BIO_printf(bio_err, "DSA verify failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

static long ecdsa_c[ECDSA_NUM][2];
static int ECDSA_sign_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t *ecdsa_num = &tempargs->sigsize;
    EVP_PKEY_CTX **ecdsa_sign_ctx = tempargs->ecdsa_sign_ctx;
    int ret, count;

    for (count = 0; COND(ecdsa_c[testnum][0]); count++) {
        *ecdsa_num = tempargs->buflen;
        ret = EVP_PKEY_sign(ecdsa_sign_ctx[testnum], buf2, ecdsa_num, buf, 20);
        if (ret <= 0) {
            BIO_printf(bio_err, "ECDSA sign failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

static int ECDSA_verify_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    unsigned char *buf2 = tempargs->buf2;
    size_t ecdsa_num = tempargs->sigsize;
    EVP_PKEY_CTX **ecdsa_verify_ctx = tempargs->ecdsa_verify_ctx;
    int ret, count;

    for (count = 0; COND(ecdsa_c[testnum][1]); count++) {
        ret = EVP_PKEY_verify(ecdsa_verify_ctx[testnum], buf2, ecdsa_num,
                              buf, 20);
        if (ret <= 0) {
            BIO_printf(bio_err, "ECDSA verify failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

/* ******************************************************************** */
static long ecdh_c[EC_NUM][1];

static int ECDH_EVP_derive_key_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    EVP_PKEY_CTX *ctx = tempargs->ecdh_ctx[testnum];
    unsigned char *derived_secret = tempargs->secret_a;
    int count;
    size_t *outlen = &(tempargs->outlen[testnum]);

    for (count = 0; COND(ecdh_c[testnum][0]); count++)
        EVP_PKEY_derive(ctx, derived_secret, outlen);

    return count;
}

static long eddsa_c[EdDSA_NUM][2];
static int EdDSA_sign_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_MD_CTX **edctx = tempargs->eddsa_ctx;
    unsigned char *eddsasig = tempargs->buf2;
    size_t *eddsasigsize = &tempargs->sigsize;
    int ret, count;

    for (count = 0; COND(eddsa_c[testnum][0]); count++) {
        ret = EVP_DigestSign(edctx[testnum], eddsasig, eddsasigsize, buf, 20);
        if (ret == 0) {
            BIO_printf(bio_err, "EdDSA sign failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

static int EdDSA_verify_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_MD_CTX **edctx = tempargs->eddsa_ctx2;
    unsigned char *eddsasig = tempargs->buf2;
    size_t eddsasigsize = tempargs->sigsize;
    int ret, count;

    for (count = 0; COND(eddsa_c[testnum][1]); count++) {
        ret = EVP_DigestVerify(edctx[testnum], eddsasig, eddsasigsize, buf, 20);
        if (ret != 1) {
            BIO_printf(bio_err, "EdDSA verify failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}

#ifndef OPENSSL_NO_SM2
static long sm2_c[SM2_NUM][2];
static int SM2_sign_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_MD_CTX **sm2ctx = tempargs->sm2_ctx;
    unsigned char *sm2sig = tempargs->buf2;
    size_t sm2sigsize;
    int ret, count;
    EVP_PKEY **sm2_pkey = tempargs->sm2_pkey;
    const size_t max_size = EVP_PKEY_get_size(sm2_pkey[testnum]);

    for (count = 0; COND(sm2_c[testnum][0]); count++) {
        sm2sigsize = max_size;

        if (!EVP_DigestSignInit(sm2ctx[testnum], NULL, EVP_sm3(),
                                NULL, sm2_pkey[testnum])) {
            BIO_printf(bio_err, "SM2 init sign failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
        ret = EVP_DigestSign(sm2ctx[testnum], sm2sig, &sm2sigsize,
                             buf, 20);
        if (ret == 0) {
            BIO_printf(bio_err, "SM2 sign failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
        /* update the latest returned size and always use the fixed buffer size */
        tempargs->sigsize = sm2sigsize;
    }

    return count;
}

static int SM2_verify_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    unsigned char *buf = tempargs->buf;
    EVP_MD_CTX **sm2ctx = tempargs->sm2_vfy_ctx;
    unsigned char *sm2sig = tempargs->buf2;
    size_t sm2sigsize = tempargs->sigsize;
    int ret, count;
    EVP_PKEY **sm2_pkey = tempargs->sm2_pkey;

    for (count = 0; COND(sm2_c[testnum][1]); count++) {
        if (!EVP_DigestVerifyInit(sm2ctx[testnum], NULL, EVP_sm3(),
                                  NULL, sm2_pkey[testnum])) {
            BIO_printf(bio_err, "SM2 verify init failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
        ret = EVP_DigestVerify(sm2ctx[testnum], sm2sig, sm2sigsize,
                               buf, 20);
        if (ret != 1) {
            BIO_printf(bio_err, "SM2 verify failure\n");
            ERR_print_errors(bio_err);
            count = -1;
            break;
        }
    }
    return count;
}
#endif                         /* OPENSSL_NO_SM2 */

#ifndef OPENSSL_NO_EC_ELGAMAL
static int ec_elgamal_encrypt = 0;
static int ec_elgamal_decrypt = 0;
static int ec_elgamal_add = 0;
static int ec_elgamal_sub = 0;
static int ec_elgamal_mul = 0;

static int32_t ec_elgamal_plaintext_a = 9;
static int32_t ec_elgamal_plaintext_b = 0;

static long ec_elgamal_c[EC_ELGAMAL_NUM][5];

static int EC_ELGAMAL_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    EC_ELGAMAL_CTX **ectx = tempargs->ec_elgamal_ctx;
    EC_ELGAMAL_CIPHERTEXT **ciphertext_a = tempargs->ciphertext_a;
    EC_ELGAMAL_CIPHERTEXT **ciphertext_b = tempargs->ciphertext_b;
    EC_ELGAMAL_CIPHERTEXT **ciphertext_r = tempargs->ciphertext_r;
    int count = 0, dcount = ec_elgamal_c[testnum][1];
    int32_t r;

    if (ec_elgamal_encrypt) {
        for (; COND(ec_elgamal_c[testnum][0]); count++) {
            if (!EC_ELGAMAL_encrypt(ectx[testnum], ciphertext_b[testnum],
                                    ec_elgamal_plaintext_b)) {
                BIO_printf(bio_err, "EC-ElGamal encrypt failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (ec_elgamal_decrypt) {
        if (ec_elgamal_plaintext_b > 0) {
            EC_ELGAMAL_CTX_set_decrypt_table(ectx[testnum],
                                             tempargs->decrypt_table[testnum][0]);
            if (ec_elgamal_plaintext_b > 100000)
                dcount = 20;
        } else {
            EC_ELGAMAL_CTX_set_decrypt_table(ectx[testnum],
                                             tempargs->decrypt_table[testnum][1]);
            dcount = 3;
        }

        for (; COND(dcount); count++) {
            if (!EC_ELGAMAL_decrypt(ectx[testnum], &r, ciphertext_b[testnum])) {
                BIO_printf(bio_err, "EC-ElGamal decrypt(+) failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (ec_elgamal_add) {
        for (; COND(ec_elgamal_c[testnum][2]); count++) {
            if (!EC_ELGAMAL_add(ectx[testnum], ciphertext_r[testnum],
                                ciphertext_a[testnum], ciphertext_b[testnum])) {
                BIO_printf(bio_err, "EC-ElGamal add failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (ec_elgamal_sub) {
        for (; COND(ec_elgamal_c[testnum][3]); count++) {
            if (!EC_ELGAMAL_sub(ectx[testnum], ciphertext_r[testnum],
                                ciphertext_a[testnum], ciphertext_b[testnum])) {
                BIO_printf(bio_err, "EC-ElGamal sub failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (ec_elgamal_mul) {
        for (; COND(ec_elgamal_c[testnum][4]); count++) {
            if (!EC_ELGAMAL_mul(ectx[testnum], ciphertext_r[testnum],
                                ciphertext_b[testnum], ec_elgamal_plaintext_a)) {
                BIO_printf(bio_err, "EC-ElGamal mul failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    }

    (void)dcount;

    return count;
}
#endif                         /* OPENSSL_NO_EC_ELGAMAL */

#ifndef OPENSSL_NO_PAILLIER
static int paillier_encrypt = 0;
static int paillier_decrypt = 0;
static int paillier_add = 0;
static int paillier_sub = 0;
static int paillier_mul = 0;

static int32_t paillier_plaintext_a = 9;
static int32_t paillier_plaintext_b = 0;

static long paillier_c[PAILLIER_NUM][5];

static int PAILLIER_loop(void *args)
{
    loopargs_t *tempargs = *(loopargs_t **) args;
    PAILLIER_CTX **ectx = tempargs->paillier_ctx;
    PAILLIER_CIPHERTEXT **ciphertext_a = tempargs->paillier_ciphertext_a;
    PAILLIER_CIPHERTEXT **ciphertext_b = tempargs->paillier_ciphertext_b;
    PAILLIER_CIPHERTEXT **ciphertext_r = tempargs->paillier_ciphertext_r;
    int count = 0, dcount = paillier_c[testnum][1];
    int32_t r;

    if (paillier_encrypt) {
        for (; COND(paillier_c[testnum][0]); count++) {
            if (!PAILLIER_encrypt(ectx[testnum], ciphertext_b[testnum],
                                    paillier_plaintext_b)) {
                BIO_printf(bio_err, "PAILLIER encrypt failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (paillier_decrypt) {
        for (; COND(dcount); count++) {
            if (!PAILLIER_decrypt(ectx[testnum], &r, ciphertext_b[testnum])) {
                BIO_printf(bio_err, "PAILLIER decrypt(+) failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (paillier_add) {
        for (; COND(paillier_c[testnum][2]); count++) {
            if (!PAILLIER_add(ectx[testnum], ciphertext_r[testnum],
                              ciphertext_a[testnum], ciphertext_b[testnum])) {
                BIO_printf(bio_err, "PAILLIER add failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (paillier_sub) {
        for (; COND(paillier_c[testnum][3]); count++) {
            if (!PAILLIER_sub(ectx[testnum], ciphertext_r[testnum],
                              ciphertext_a[testnum], ciphertext_b[testnum])) {
                BIO_printf(bio_err, "PAILLIER sub failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    } else if (paillier_mul) {
        for (; COND(paillier_c[testnum][4]); count++) {
            if (!PAILLIER_mul(ectx[testnum], ciphertext_r[testnum],
                              ciphertext_b[testnum], paillier_plaintext_a)) {
                BIO_printf(bio_err, "PAILLIER mul failure\n");
                ERR_print_errors(bio_err);
                count = -1;
                break;
            }
        }
    }

    (void)dcount;

    return count;
}
#endif                         /* OPENSSL_NO_PAILLIER */

static int run_benchmark(int async_jobs,
                         int (*loop_function) (void *), loopargs_t * loopargs)
{
    int job_op_count = 0;
    int total_op_count = 0;
    int num_inprogress = 0;
    int error = 0, i = 0, ret = 0;
    OSSL_ASYNC_FD job_fd = 0;
    size_t num_job_fds = 0;

    if (async_jobs == 0) {
        return loop_function((void *)&loopargs);
    }

    for (i = 0; i < async_jobs && !error; i++) {
        loopargs_t *looparg_item = loopargs + i;

        /* Copy pointer content (looparg_t item address) into async context */
        ret = ASYNC_start_job(&loopargs[i].inprogress_job, loopargs[i].wait_ctx,
                              &job_op_count, loop_function,
                              (void *)&looparg_item, sizeof(looparg_item));
        switch (ret) {
        case ASYNC_PAUSE:
            ++num_inprogress;
            break;
        case ASYNC_FINISH:
            if (job_op_count == -1) {
                error = 1;
            } else {
                total_op_count += job_op_count;
            }
            break;
        case ASYNC_NO_JOBS:
        case ASYNC_ERR:
            BIO_printf(bio_err, "Failure in the job\n");
            ERR_print_errors(bio_err);
            error = 1;
            break;
        }
    }

    while (num_inprogress > 0) {
#if defined(OPENSSL_SYS_WINDOWS)
        DWORD avail = 0;
#elif defined(OPENSSL_SYS_UNIX)
        int select_result = 0;
        OSSL_ASYNC_FD max_fd = 0;
        fd_set waitfdset;

        FD_ZERO(&waitfdset);

        for (i = 0; i < async_jobs && num_inprogress > 0; i++) {
            if (loopargs[i].inprogress_job == NULL)
                continue;

            if (!ASYNC_WAIT_CTX_get_all_fds
                (loopargs[i].wait_ctx, NULL, &num_job_fds)
                || num_job_fds > 1) {
                BIO_printf(bio_err, "Too many fds in ASYNC_WAIT_CTX\n");
                ERR_print_errors(bio_err);
                error = 1;
                break;
            }
            ASYNC_WAIT_CTX_get_all_fds(loopargs[i].wait_ctx, &job_fd,
                                       &num_job_fds);
            FD_SET(job_fd, &waitfdset);
            if (job_fd > max_fd)
                max_fd = job_fd;
        }

        if (max_fd >= (OSSL_ASYNC_FD)FD_SETSIZE) {
            BIO_printf(bio_err,
                       "Error: max_fd (%d) must be smaller than FD_SETSIZE (%d). "
                       "Decrease the value of async_jobs\n",
                       max_fd, FD_SETSIZE);
            ERR_print_errors(bio_err);
            error = 1;
            break;
        }

        select_result = select(max_fd + 1, &waitfdset, NULL, NULL, NULL);
        if (select_result == -1 && errno == EINTR)
            continue;

        if (select_result == -1) {
            BIO_printf(bio_err, "Failure in the select\n");
            ERR_print_errors(bio_err);
            error = 1;
            break;
        }

        if (select_result == 0)
            continue;
#endif

        for (i = 0; i < async_jobs; i++) {
            if (loopargs[i].inprogress_job == NULL)
                continue;

            if (!ASYNC_WAIT_CTX_get_all_fds
                (loopargs[i].wait_ctx, NULL, &num_job_fds)
                || num_job_fds > 1) {
                BIO_printf(bio_err, "Too many fds in ASYNC_WAIT_CTX\n");
                ERR_print_errors(bio_err);
                error = 1;
                break;
            }
            ASYNC_WAIT_CTX_get_all_fds(loopargs[i].wait_ctx, &job_fd,
                                       &num_job_fds);

#if defined(OPENSSL_SYS_UNIX)
            if (num_job_fds == 1 && !FD_ISSET(job_fd, &waitfdset))
                continue;
#elif defined(OPENSSL_SYS_WINDOWS)
            if (num_job_fds == 1
                && !PeekNamedPipe(job_fd, NULL, 0, NULL, &avail, NULL)
                && avail > 0)
                continue;
#endif

            ret = ASYNC_start_job(&loopargs[i].inprogress_job,
                                  loopargs[i].wait_ctx, &job_op_count,
                                  loop_function, (void *)(loopargs + i),
                                  sizeof(loopargs_t));
            switch (ret) {
            case ASYNC_PAUSE:
                break;
            case ASYNC_FINISH:
                if (job_op_count == -1) {
                    error = 1;
                } else {
                    total_op_count += job_op_count;
                }
                --num_inprogress;
                loopargs[i].inprogress_job = NULL;
                break;
            case ASYNC_NO_JOBS:
            case ASYNC_ERR:
                --num_inprogress;
                loopargs[i].inprogress_job = NULL;
                BIO_printf(bio_err, "Failure in the job\n");
                ERR_print_errors(bio_err);
                error = 1;
                break;
            }
        }
    }

    return error ? -1 : total_op_count;
}

typedef struct ec_curve_st {
    const char *name;
    unsigned int nid;
    unsigned int bits;
    size_t sigsize; /* only used for EdDSA curves */
} EC_CURVE;

static EVP_PKEY *get_ecdsa(const EC_CURVE *curve)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;

    /* Ensure that the error queue is empty */
    if (ERR_peek_error()) {
        BIO_printf(bio_err,
                   "WARNING: the error queue contains previous unhandled errors.\n");
        ERR_print_errors(bio_err);
    }

    /*
     * Let's try to create a ctx directly from the NID: this works for
     * curves like Curve25519 that are not implemented through the low
     * level EC interface.
     * If this fails we try creating a EVP_PKEY_EC generic param ctx,
     * then we set the curve by NID before deriving the actual keygen
     * ctx for that specific curve.
     */
    kctx = EVP_PKEY_CTX_new_id(curve->nid, NULL);
    if (kctx == NULL) {
        EVP_PKEY_CTX *pctx = NULL;
        EVP_PKEY *params = NULL;
        /*
         * If we reach this code EVP_PKEY_CTX_new_id() failed and a
         * "int_ctx_new:unsupported algorithm" error was added to the
         * error queue.
         * We remove it from the error queue as we are handling it.
         */
        unsigned long error = ERR_peek_error();

        if (error == ERR_peek_last_error() /* oldest and latest errors match */
            /* check that the error origin matches */
            && ERR_GET_LIB(error) == ERR_LIB_EVP
            && (ERR_GET_REASON(error) == EVP_R_UNSUPPORTED_ALGORITHM
                || ERR_GET_REASON(error) == ERR_R_UNSUPPORTED))
            ERR_get_error(); /* pop error from queue */
        if (ERR_peek_error()) {
            BIO_printf(bio_err,
                       "Unhandled error in the error queue during EC key setup.\n");
            ERR_print_errors(bio_err);
            return NULL;
        }

        /* Create the context for parameter generation */
        if ((pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL
            || EVP_PKEY_paramgen_init(pctx) <= 0
            || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                                                      curve->nid) <= 0
            || EVP_PKEY_paramgen(pctx, &params) <= 0) {
            BIO_printf(bio_err, "EC params init failure.\n");
            ERR_print_errors(bio_err);
            EVP_PKEY_CTX_free(pctx);
            return NULL;
        }
        EVP_PKEY_CTX_free(pctx);

        /* Create the context for the key generation */
        kctx = EVP_PKEY_CTX_new(params, NULL);
        EVP_PKEY_free(params);
    }
    if (kctx == NULL
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_keygen(kctx, &key) <= 0) {
        BIO_printf(bio_err, "EC key generation failure.\n");
        ERR_print_errors(bio_err);
        key = NULL;
    }
    EVP_PKEY_CTX_free(kctx);
    return key;
}

#define stop_it(do_it, test_num)\
    memset(do_it + test_num, 0, OSSL_NELEM(do_it) - test_num);

int speed_main(int argc, char **argv)
{
    ENGINE *e = NULL;
    loopargs_t *loopargs = NULL;
    const char *prog;
    const char *engine_id = NULL;
    EVP_CIPHER *evp_cipher = NULL;
    EVP_MAC *mac = NULL;
    double d = 0.0;
    OPTION_CHOICE o;
    int async_init = 0, multiblock = 0, pr_header = 0;
    uint8_t doit[ALGOR_NUM] = { 0 };
    int ret = 1, misalign = 0, lengths_single = 0, aead = 0;
    long count = 0;
    unsigned int size_num = SIZE_NUM;
    unsigned int i, k, loopargs_len = 0, async_jobs = 0;
    int keylen;
    int buflen;
    BIGNUM *bn = NULL;
    EVP_PKEY_CTX *genctx = NULL;
#ifndef NO_FORK
    int multi = 0;
#endif
    long op_count = 1;
    openssl_speed_sec_t seconds = { SECONDS, RSA_SECONDS, DSA_SECONDS,
                                    ECDSA_SECONDS, ECDH_SECONDS,
                                    EdDSA_SECONDS, SM2_SECONDS,
                                    FFDH_SECONDS, EC_ELGAMAL_SECONDS,
                                    PAILLIER_SECONDS };

    static const unsigned char key32[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
        0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56
    };
    static const unsigned char deskey[] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, /* key1 */
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, /* key2 */
        0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34  /* key3 */
    };
    static const struct {
        const unsigned char *data;
        unsigned int length;
        unsigned int bits;
    } rsa_keys[] = {
        {   test512,   sizeof(test512),   512 },
        {  test1024,  sizeof(test1024),  1024 },
        {  test2048,  sizeof(test2048),  2048 },
        {  test3072,  sizeof(test3072),  3072 },
        {  test4096,  sizeof(test4096),  4096 },
        {  test7680,  sizeof(test7680),  7680 },
        { test15360, sizeof(test15360), 15360 }
    };
    uint8_t rsa_doit[RSA_NUM] = { 0 };
    int primes = RSA_DEFAULT_PRIME_NUM;
#ifndef OPENSSL_NO_DH
    typedef struct ffdh_params_st {
        const char *name;
        unsigned int nid;
        unsigned int bits;
    } FFDH_PARAMS;

    static const FFDH_PARAMS ffdh_params[FFDH_NUM] = {
        {"ffdh2048", NID_ffdhe2048, 2048},
        {"ffdh3072", NID_ffdhe3072, 3072},
        {"ffdh4096", NID_ffdhe4096, 4096},
        {"ffdh6144", NID_ffdhe6144, 6144},
        {"ffdh8192", NID_ffdhe8192, 8192}
    };
    uint8_t ffdh_doit[FFDH_NUM] = { 0 };

#endif /* OPENSSL_NO_DH */
    static const unsigned int dsa_bits[DSA_NUM] = { 512, 1024, 2048 };
    uint8_t dsa_doit[DSA_NUM] = { 0 };
    /*
     * We only test over the following curves as they are representative, To
     * add tests over more curves, simply add the curve NID and curve name to
     * the following arrays and increase the |ecdh_choices| and |ecdsa_choices|
     * lists accordingly.
     */
    static const EC_CURVE ec_curves[EC_NUM] = {
        /* Prime Curves */
        {"secp160r1", NID_secp160r1, 160},
        {"nistp192", NID_X9_62_prime192v1, 192},
        {"nistp224", NID_secp224r1, 224},
        {"nistp256", NID_X9_62_prime256v1, 256},
        {"nistp384", NID_secp384r1, 384},
        {"nistp521", NID_secp521r1, 521},
#ifndef OPENSSL_NO_EC2M
        /* Binary Curves */
        {"nistk163", NID_sect163k1, 163},
        {"nistk233", NID_sect233k1, 233},
        {"nistk283", NID_sect283k1, 283},
        {"nistk409", NID_sect409k1, 409},
        {"nistk571", NID_sect571k1, 571},
        {"nistb163", NID_sect163r2, 163},
        {"nistb233", NID_sect233r1, 233},
        {"nistb283", NID_sect283r1, 283},
        {"nistb409", NID_sect409r1, 409},
        {"nistb571", NID_sect571r1, 571},
#endif
        {"brainpoolP256r1", NID_brainpoolP256r1, 256},
        {"brainpoolP256t1", NID_brainpoolP256t1, 256},
        {"brainpoolP384r1", NID_brainpoolP384r1, 384},
        {"brainpoolP384t1", NID_brainpoolP384t1, 384},
        {"brainpoolP512r1", NID_brainpoolP512r1, 512},
        {"brainpoolP512t1", NID_brainpoolP512t1, 512},
        /* Other and ECDH only ones */
        {"X25519", NID_X25519, 253},
        {"X448", NID_X448, 448}
    };
    static const EC_CURVE ed_curves[EdDSA_NUM] = {
        /* EdDSA */
        {"Ed25519", NID_ED25519, 253, 64},
        {"Ed448", NID_ED448, 456, 114}
    };
#ifndef OPENSSL_NO_SM2
    static const EC_CURVE sm2_curves[SM2_NUM] = {
        /* SM2 */
        {"CurveSM2", NID_sm2, 256}
    };
    uint8_t sm2_doit[SM2_NUM] = { 0 };
#endif
#ifndef OPENSSL_NO_EC_ELGAMAL
    static const EC_CURVE test_ec_elgamal_curves[] = {
        /* Prime Curves */
        {"secp160r1", NID_secp160r1},
        {"nistp192", NID_X9_62_prime192v1},
        {"nistp224", NID_secp224r1},
        {"nistp256", NID_X9_62_prime256v1},
        {"nistp384", NID_secp384r1},
        {"nistp521", NID_secp521r1},
# ifndef OPENSSL_NO_EC2M
        /* Binary Curves */
        {"nistk163", NID_sect163k1},
        {"nistk233", NID_sect233k1},
        {"nistk283", NID_sect283k1},
        {"nistk409", NID_sect409k1},
        {"nistk571", NID_sect571k1},
        {"nistb163", NID_sect163r2},
        {"nistb233", NID_sect233r1},
        {"nistb283", NID_sect283r1},
        {"nistb409", NID_sect409r1},
        {"nistb571", NID_sect571r1},
# endif
        {"brainpoolP256r1", NID_brainpoolP256r1},
        {"brainpoolP256t1", NID_brainpoolP256t1},
        {"brainpoolP384r1", NID_brainpoolP384r1},
        {"brainpoolP384t1", NID_brainpoolP384t1},
        {"brainpoolP512r1", NID_brainpoolP512r1},
        {"brainpoolP512t1", NID_brainpoolP512t1},
# ifndef OPENSSL_NO_SM2
        {"sm2", NID_sm2},
# endif
    };
    int ec_elgamal_doit[EC_ELGAMAL_NUM] = { 0 };
    int ec_elgamal_flag[EC_ELGAMAL_NUM] = { 0 };
#endif

#ifndef OPENSSL_NO_PAILLIER
    static const char *test_paillier_names[] = {
        "g_optimize",
    };
    int paillier_doit[PAILLIER_NUM] = { 0 };
#endif

    uint8_t ecdsa_doit[ECDSA_NUM] = { 0 };
    uint8_t ecdh_doit[EC_NUM] = { 0 };
    uint8_t eddsa_doit[EdDSA_NUM] = { 0 };

    /* checks declarated curves against choices list. */
    OPENSSL_assert(ed_curves[EdDSA_NUM - 1].nid == NID_ED448);
    OPENSSL_assert(strcmp(eddsa_choices[EdDSA_NUM - 1].name, "ed448") == 0);

    OPENSSL_assert(ec_curves[EC_NUM - 1].nid == NID_X448);
    OPENSSL_assert(strcmp(ecdh_choices[EC_NUM - 1].name, "ecdhx448") == 0);

    OPENSSL_assert(ec_curves[ECDSA_NUM - 1].nid == NID_brainpoolP512t1);
    OPENSSL_assert(strcmp(ecdsa_choices[ECDSA_NUM - 1].name, "ecdsabrp512t1") == 0);

#ifndef OPENSSL_NO_SM2
    OPENSSL_assert(sm2_curves[SM2_NUM - 1].nid == NID_sm2);
    OPENSSL_assert(strcmp(sm2_choices[SM2_NUM - 1].name, "curveSM2") == 0);
#endif

    prog = opt_init(argc, argv, speed_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opterr:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(speed_options);
            ret = 0;
            goto end;
        case OPT_ELAPSED:
            usertime = 0;
            break;
        case OPT_EVP:
            if (doit[D_EVP]) {
                BIO_printf(bio_err, "%s: -evp option cannot be used more than once\n", prog);
                goto opterr;
            }
            ERR_set_mark();
            if (!opt_cipher_silent(opt_arg(), &evp_cipher)) {
                if (have_md(opt_arg()))
                    evp_md_name = opt_arg();
            }
            if (evp_cipher == NULL && evp_md_name == NULL) {
                ERR_clear_last_mark();
                BIO_printf(bio_err,
                           "%s: %s is an unknown cipher or digest\n",
                           prog, opt_arg());
                goto end;
            }
            ERR_pop_to_mark();
            doit[D_EVP] = 1;
            break;
        case OPT_HMAC:
            if (!have_md(opt_arg())) {
                BIO_printf(bio_err, "%s: %s is an unknown digest\n",
                           prog, opt_arg());
                goto end;
            }
            evp_mac_mdname = opt_arg();
            doit[D_HMAC] = 1;
            break;
        case OPT_CMAC:
            if (!have_cipher(opt_arg())) {
                BIO_printf(bio_err, "%s: %s is an unknown cipher\n",
                           prog, opt_arg());
                goto end;
            }
            evp_mac_ciphername = opt_arg();
            doit[D_EVP_CMAC] = 1;
            break;
        case OPT_DECRYPT:
            decrypt = 1;
            break;
        case OPT_ENGINE:
            /*
             * In a forked execution, an engine might need to be
             * initialised by each child process, not by the parent.
             * So store the name here and run setup_engine() later on.
             */
            engine_id = opt_arg();
            break;
        case OPT_MULTI:
#ifndef NO_FORK
            multi = atoi(opt_arg());
            if ((size_t)multi >= SIZE_MAX / sizeof(int)) {
                BIO_printf(bio_err, "%s: multi argument too large\n", prog);
                return 0;
            }
#endif
            break;
        case OPT_ASYNCJOBS:
#ifndef OPENSSL_NO_ASYNC
            async_jobs = atoi(opt_arg());
            if (!ASYNC_is_capable()) {
                BIO_printf(bio_err,
                           "%s: async_jobs specified but async not supported\n",
                           prog);
                goto opterr;
            }
            if (async_jobs > 99999) {
                BIO_printf(bio_err, "%s: too many async_jobs\n", prog);
                goto opterr;
            }
#endif
            break;
        case OPT_MISALIGN:
            misalign = opt_int_arg();
            if (misalign > MISALIGN) {
                BIO_printf(bio_err,
                           "%s: Maximum offset is %d\n", prog, MISALIGN);
                goto opterr;
            }
            break;
        case OPT_MR:
            mr = 1;
            break;
        case OPT_MB:
            multiblock = 1;
#ifdef OPENSSL_NO_MULTIBLOCK
            BIO_printf(bio_err,
                       "%s: -mb specified but multi-block support is disabled\n",
                       prog);
            goto end;
#endif
            break;
        case OPT_R_CASES:
            if (!opt_rand(o))
                goto end;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        case OPT_PRIMES:
            primes = opt_int_arg();
            break;
        case OPT_SECONDS:
            seconds.sym = seconds.rsa = seconds.dsa = seconds.ecdsa
                        = seconds.ecdh = seconds.eddsa
                        = seconds.sm2 = seconds.ffdh = atoi(opt_arg());
            break;
        case OPT_BYTES:
            lengths_single = atoi(opt_arg());
            lengths = &lengths_single;
            size_num = 1;
            break;
        case OPT_AEAD:
            aead = 1;
            break;
        }
    }

    /* Remaining arguments are algorithms. */
    argc = opt_num_rest();
    argv = opt_rest();

    if (!app_RAND_load())
        goto end;

    for (; *argv; argv++) {
        const char *algo = *argv;

        if (opt_found(algo, doit_choices, &i)) {
            doit[i] = 1;
            continue;
        }
        if (strcmp(algo, "des") == 0) {
            doit[D_CBC_DES] = doit[D_EDE3_DES] = 1;
            continue;
        }
        if (strcmp(algo, "sha") == 0) {
            doit[D_SHA1] = doit[D_SHA256] = doit[D_SHA512] = 1;
            continue;
        }
#ifndef OPENSSL_NO_DEPRECATED_3_0
        if (strcmp(algo, "openssl") == 0) /* just for compatibility */
            continue;
#endif
        if (strncmp(algo, "rsa", 3) == 0) {
            if (algo[3] == '\0') {
                memset(rsa_doit, 1, sizeof(rsa_doit));
                continue;
            }
            if (opt_found(algo, rsa_choices, &i)) {
                rsa_doit[i] = 1;
                continue;
            }
        }
#ifndef OPENSSL_NO_DH
        if (strncmp(algo, "ffdh", 4) == 0) {
            if (algo[4] == '\0') {
                memset(ffdh_doit, 1, sizeof(ffdh_doit));
                continue;
            }
            if (opt_found(algo, ffdh_choices, &i)) {
                ffdh_doit[i] = 2;
                continue;
            }
        }
#endif
        if (strncmp(algo, "dsa", 3) == 0) {
            if (algo[3] == '\0') {
                memset(dsa_doit, 1, sizeof(dsa_doit));
                continue;
            }
            if (opt_found(algo, dsa_choices, &i)) {
                dsa_doit[i] = 2;
                continue;
            }
        }
        if (strcmp(algo, "aes") == 0) {
            doit[D_CBC_128_AES] = doit[D_CBC_192_AES] = doit[D_CBC_256_AES] = 1;
            continue;
        }
        if (strncmp(algo, "ecdsa", 5) == 0) {
            if (algo[5] == '\0') {
                memset(ecdsa_doit, 1, sizeof(ecdsa_doit));
                continue;
            }
            if (opt_found(algo, ecdsa_choices, &i)) {
                ecdsa_doit[i] = 2;
                continue;
            }
        }
        if (strncmp(algo, "ecdh", 4) == 0) {
            if (algo[4] == '\0') {
                memset(ecdh_doit, 1, sizeof(ecdh_doit));
                continue;
            }
            if (opt_found(algo, ecdh_choices, &i)) {
                ecdh_doit[i] = 2;
                continue;
            }
        }
        if (strcmp(algo, "eddsa") == 0) {
            memset(eddsa_doit, 1, sizeof(eddsa_doit));
            continue;
        }
        if (opt_found(algo, eddsa_choices, &i)) {
            eddsa_doit[i] = 2;
            continue;
        }
#ifndef OPENSSL_NO_SM2
        if (strcmp(algo, "sm2") == 0) {
            memset(sm2_doit, 1, sizeof(sm2_doit));
            continue;
        }
        if (opt_found(algo, sm2_choices, &i)) {
            sm2_doit[i] = 2;
            continue;
        }
#endif
#ifndef OPENSSL_NO_EC_ELGAMAL
        if (strcmp(algo, "ecelgamal") == 0
# ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
            ||strcmp(algo, "twisted-ecelgamal") == 0
# endif
            ) {
            for (i = 0; i < OSSL_NELEM(ec_elgamal_doit); i++)
                ec_elgamal_doit[i] = 1;
# ifndef OPENSSL_NO_EC2M
            for (i = R_EC_ELGAMAL_K163; i <= R_EC_ELGAMAL_BRP512T1; i++)
# else
            for (i = R_EC_ELGAMAL_BRP256R1; i <= R_EC_ELGAMAL_BRP512T1; i++)
# endif
                ec_elgamal_doit[i] = 0;

# ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
            if (strcmp(algo, "twisted-ecelgamal") == 0 ) {
                for (i = 0; i < EC_ELGAMAL_NUM; i++) {
                    ec_elgamal_flag[i] = EC_ELGAMAL_FLAG_TWISTED;
                }
            }
# endif
            continue;
        }

# ifndef OPENSSL_NO_TWISTED_EC_ELGAMAL
        if (strncmp(algo, "twisted-ecelgamal", sizeof("twisted-ecelgamal")-1) == 0) {
            algo += sizeof("twisted-")-1;
            if (opt_found(algo, ec_elgamal_choices, &i)) {
                ec_elgamal_doit[i] = 2;
                ec_elgamal_flag[i] = EC_ELGAMAL_FLAG_TWISTED;
                continue;
            }
        }
# endif

        if (opt_found(algo, ec_elgamal_choices, &i)) {
            ec_elgamal_doit[i] = 2;
            continue;
        }
#endif
#ifndef OPENSSL_NO_PAILLIER
        if (strcmp(algo, "paillier") == 0) {
            for (i = 0; i < OSSL_NELEM(paillier_doit); i++)
                paillier_doit[i] = 1;
            continue;
        }
        if (opt_found(algo, paillier_choices, &i)) {
            paillier_doit[i] = 2;
            continue;
        }
#endif
        BIO_printf(bio_err, "%s: Unknown algorithm %s\n", prog, algo);
        goto end;
    }

    /* Sanity checks */
    if (aead) {
        if (evp_cipher == NULL) {
            BIO_printf(bio_err, "-aead can be used only with an AEAD cipher\n");
            goto end;
        } else if (!(EVP_CIPHER_get_flags(evp_cipher) &
                     EVP_CIPH_FLAG_AEAD_CIPHER)) {
            BIO_printf(bio_err, "%s is not an AEAD cipher\n",
                       EVP_CIPHER_get0_name(evp_cipher));
            goto end;
        }
    }
    if (multiblock) {
        if (evp_cipher == NULL) {
            BIO_printf(bio_err, "-mb can be used only with a multi-block"
                                " capable cipher\n");
            goto end;
        } else if (!(EVP_CIPHER_get_flags(evp_cipher) &
                     EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK)) {
            BIO_printf(bio_err, "%s is not a multi-block capable\n",
                       EVP_CIPHER_get0_name(evp_cipher));
            goto end;
        } else if (async_jobs > 0) {
            BIO_printf(bio_err, "Async mode is not supported with -mb");
            goto end;
        }
    }

    /* Initialize the job pool if async mode is enabled */
    if (async_jobs > 0) {
        async_init = ASYNC_init_thread(async_jobs, async_jobs);
        if (!async_init) {
            BIO_printf(bio_err, "Error creating the ASYNC job pool\n");
            goto end;
        }
    }

    loopargs_len = (async_jobs == 0 ? 1 : async_jobs);
    loopargs =
        app_malloc(loopargs_len * sizeof(loopargs_t), "array of loopargs");
    memset(loopargs, 0, loopargs_len * sizeof(loopargs_t));

    for (i = 0; i < loopargs_len; i++) {
        if (async_jobs > 0) {
            loopargs[i].wait_ctx = ASYNC_WAIT_CTX_new();
            if (loopargs[i].wait_ctx == NULL) {
                BIO_printf(bio_err, "Error creating the ASYNC_WAIT_CTX\n");
                goto end;
            }
        }

        buflen = lengths[size_num - 1];
        if (buflen < 36)    /* size of random vector in RSA benchmark */
            buflen = 36;
        if (INT_MAX - (MAX_MISALIGNMENT + 1) < buflen) {
            BIO_printf(bio_err, "Error: buffer size too large\n");
            goto end;
        }
        buflen += MAX_MISALIGNMENT + 1;
        loopargs[i].buf_malloc = app_malloc(buflen, "input buffer");
        loopargs[i].buf2_malloc = app_malloc(buflen, "input buffer");
        memset(loopargs[i].buf_malloc, 0, buflen);
        memset(loopargs[i].buf2_malloc, 0, buflen);

        /* Align the start of buffers on a 64 byte boundary */
        loopargs[i].buf = loopargs[i].buf_malloc + misalign;
        loopargs[i].buf2 = loopargs[i].buf2_malloc + misalign;
        loopargs[i].buflen = buflen - misalign;
        loopargs[i].sigsize = buflen - misalign;
        loopargs[i].secret_a = app_malloc(MAX_ECDH_SIZE, "ECDH secret a");
        loopargs[i].secret_b = app_malloc(MAX_ECDH_SIZE, "ECDH secret b");
#ifndef OPENSSL_NO_DH
        loopargs[i].secret_ff_a = app_malloc(MAX_FFDH_SIZE, "FFDH secret a");
        loopargs[i].secret_ff_b = app_malloc(MAX_FFDH_SIZE, "FFDH secret b");
#endif
    }

#ifndef NO_FORK
    if (multi && do_multi(multi, size_num))
        goto show_res;
#endif

    /* Initialize the engine after the fork */
    e = setup_engine(engine_id, 0);

    /* No parameters; turn on everything. */
    if (argc == 0 && !doit[D_EVP] && !doit[D_HMAC] && !doit[D_EVP_CMAC]) {
        memset(doit, 1, sizeof(doit));
        doit[D_EVP] = doit[D_EVP_CMAC] = 0;
        ERR_set_mark();
        for (i = D_MD5; i <= D_SHA512; i++) {
            if (!have_md(names[i]))
                doit[i] = 0;
        }
        for (i = D_CBC_DES; i <= D_CBC_256_AES; i++) {
            if (!have_cipher(names[i]))
                doit[i] = 0;
        }
        if ((mac = EVP_MAC_fetch(app_get0_libctx(), "GMAC",
                                 app_get0_propq())) != NULL) {
            EVP_MAC_free(mac);
            mac = NULL;
        } else {
            doit[D_GHASH] = 0;
        }
        if ((mac = EVP_MAC_fetch(app_get0_libctx(), "HMAC",
                                 app_get0_propq())) != NULL) {
            EVP_MAC_free(mac);
            mac = NULL;
        } else {
            doit[D_HMAC] = 0;
        }
        ERR_pop_to_mark();
        memset(rsa_doit, 1, sizeof(rsa_doit));
#ifndef OPENSSL_NO_DH
        memset(ffdh_doit, 1, sizeof(ffdh_doit));
#endif
        memset(dsa_doit, 1, sizeof(dsa_doit));
        memset(ecdsa_doit, 1, sizeof(ecdsa_doit));
        memset(ecdh_doit, 1, sizeof(ecdh_doit));
        memset(eddsa_doit, 1, sizeof(eddsa_doit));
#ifndef OPENSSL_NO_SM2
        memset(sm2_doit, 1, sizeof(sm2_doit));
#endif
    }
    for (i = 0; i < ALGOR_NUM; i++)
        if (doit[i])
            pr_header++;

    if (usertime == 0 && !mr)
        BIO_printf(bio_err,
                   "You have chosen to measure elapsed time "
                   "instead of user CPU time.\n");

#if SIGALRM > 0
    signal(SIGALRM, alarmed);
#endif

#ifndef OPENSSL_NO_EC_ELGAMAL
    ec_elgamal_c[R_EC_ELGAMAL_P160][0] = count / 18000;
    ec_elgamal_c[R_EC_ELGAMAL_P160][1] = count / 180000;
    ec_elgamal_c[R_EC_ELGAMAL_P160][2] = count / 130;
    ec_elgamal_c[R_EC_ELGAMAL_P160][3] = count / 200;
    ec_elgamal_c[R_EC_ELGAMAL_P160][4] = count / 20000;

    ec_elgamal_c[R_EC_ELGAMAL_P192][0] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_P192][1] = count / 10000;
    ec_elgamal_c[R_EC_ELGAMAL_P192][2] = count / 130;
    ec_elgamal_c[R_EC_ELGAMAL_P192][3] = count / 200;
    ec_elgamal_c[R_EC_ELGAMAL_P192][4] = count / 20000;

    ec_elgamal_c[R_EC_ELGAMAL_P224][0] = count / 10000;
    ec_elgamal_c[R_EC_ELGAMAL_P224][1] = count / 10000;
    ec_elgamal_c[R_EC_ELGAMAL_P224][2] = count / 140;
    ec_elgamal_c[R_EC_ELGAMAL_P224][3] = count / 200;
    ec_elgamal_c[R_EC_ELGAMAL_P224][4] = count / 30000;

    ec_elgamal_c[R_EC_ELGAMAL_P256][0] = count / 2400;
    ec_elgamal_c[R_EC_ELGAMAL_P256][1] = count / 2000;
    ec_elgamal_c[R_EC_ELGAMAL_P256][2] = count / 150;
    ec_elgamal_c[R_EC_ELGAMAL_P256][3] = count / 200;
    ec_elgamal_c[R_EC_ELGAMAL_P256][4] = count / 3000;

    ec_elgamal_c[R_EC_ELGAMAL_P384][0] = count / 60000;
    ec_elgamal_c[R_EC_ELGAMAL_P384][1] = count / 40000;
    ec_elgamal_c[R_EC_ELGAMAL_P384][2] = count / 17000;
    ec_elgamal_c[R_EC_ELGAMAL_P384][3] = count / 2400;
    ec_elgamal_c[R_EC_ELGAMAL_P384][4] = count / 73000;

    ec_elgamal_c[R_EC_ELGAMAL_P521][0] = count / 60000 / 2;
    ec_elgamal_c[R_EC_ELGAMAL_P521][1] = count / 40000 / 2;
    ec_elgamal_c[R_EC_ELGAMAL_P521][2] = count / 250;
    ec_elgamal_c[R_EC_ELGAMAL_P521][3] = count / 3000;
    ec_elgamal_c[R_EC_ELGAMAL_P521][4] = count / 73000 / 2;
# ifndef OPENSSL_NO_EC2M
    ec_elgamal_c[R_EC_ELGAMAL_K163][0] = count / 50000;
    ec_elgamal_c[R_EC_ELGAMAL_K163][1] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_K163][2] = count / 1000;
    ec_elgamal_c[R_EC_ELGAMAL_K163][3] = count / 1000;
    ec_elgamal_c[R_EC_ELGAMAL_K163][4] = count / 33000;

    ec_elgamal_c[R_EC_ELGAMAL_K233][0] = count / 70000;
    ec_elgamal_c[R_EC_ELGAMAL_K233][1] = count / 25000;
    ec_elgamal_c[R_EC_ELGAMAL_K233][2] = count / 1400;
    ec_elgamal_c[R_EC_ELGAMAL_K233][3] = count / 1400;
    ec_elgamal_c[R_EC_ELGAMAL_K233][4] = count / 50000;

    ec_elgamal_c[R_EC_ELGAMAL_K283][0] = count / 120000;
    ec_elgamal_c[R_EC_ELGAMAL_K283][1] = count / 40000;
    ec_elgamal_c[R_EC_ELGAMAL_K283][2] = count / 1700;
    ec_elgamal_c[R_EC_ELGAMAL_K283][3] = count / 1700;
    ec_elgamal_c[R_EC_ELGAMAL_K283][4] = count / 80000;

    ec_elgamal_c[R_EC_ELGAMAL_K409][0] = count / 200000;
    ec_elgamal_c[R_EC_ELGAMAL_K409][1] = count / 60000;
    ec_elgamal_c[R_EC_ELGAMAL_K409][2] = count / 2500;
    ec_elgamal_c[R_EC_ELGAMAL_K409][3] = count / 2500;
    ec_elgamal_c[R_EC_ELGAMAL_K409][4] = count / 120000;

    ec_elgamal_c[R_EC_ELGAMAL_K571][0] = count / 400000;
    ec_elgamal_c[R_EC_ELGAMAL_K571][1] = count / 120000;
    ec_elgamal_c[R_EC_ELGAMAL_K571][2] = count / 4000;
    ec_elgamal_c[R_EC_ELGAMAL_K571][3] = count / 4000;
    ec_elgamal_c[R_EC_ELGAMAL_K571][4] = count / 250000;

    ec_elgamal_c[R_EC_ELGAMAL_B163][0] = count / 50000;
    ec_elgamal_c[R_EC_ELGAMAL_B163][1] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_B163][2] = count / 1000;
    ec_elgamal_c[R_EC_ELGAMAL_B163][3] = count / 1000;
    ec_elgamal_c[R_EC_ELGAMAL_B163][4] = count / 35000;

    ec_elgamal_c[R_EC_ELGAMAL_B233][0] = count / 65000;
    ec_elgamal_c[R_EC_ELGAMAL_B233][1] = count / 25000;
    ec_elgamal_c[R_EC_ELGAMAL_B233][2] = count / 1300;
    ec_elgamal_c[R_EC_ELGAMAL_B233][3] = count / 1300;
    ec_elgamal_c[R_EC_ELGAMAL_B233][4] = count / 45000;

    ec_elgamal_c[R_EC_ELGAMAL_B283][0] = count / 65000 / 2;
    ec_elgamal_c[R_EC_ELGAMAL_B283][1] = count / 40000;
    ec_elgamal_c[R_EC_ELGAMAL_B283][2] = count / 1700;
    ec_elgamal_c[R_EC_ELGAMAL_B283][3] = count / 1700;
    ec_elgamal_c[R_EC_ELGAMAL_B283][4] = count / 90000;

    ec_elgamal_c[R_EC_ELGAMAL_B409][0] = count / 200000;
    ec_elgamal_c[R_EC_ELGAMAL_B409][1] = count / 65000;
    ec_elgamal_c[R_EC_ELGAMAL_B409][2] = count / 2500;
    ec_elgamal_c[R_EC_ELGAMAL_B409][3] = count / 2500;
    ec_elgamal_c[R_EC_ELGAMAL_B409][4] = count / 130000;

    ec_elgamal_c[R_EC_ELGAMAL_B571][0] = count / 450000;
    ec_elgamal_c[R_EC_ELGAMAL_B571][1] = count / 150000;
    ec_elgamal_c[R_EC_ELGAMAL_B571][2] = count / 4000;
    ec_elgamal_c[R_EC_ELGAMAL_B571][3] = count / 4000;
    ec_elgamal_c[R_EC_ELGAMAL_B571][4] = count / 300000;
# endif
    ec_elgamal_c[R_EC_ELGAMAL_BRP256R1][0] = count / 30000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256R1][1] = count / 18000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256R1][2] = count / 140;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256R1][3] = count / 200;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256R1][4] = count / 32000;

    ec_elgamal_c[R_EC_ELGAMAL_BRP256T1][0] = count / 30000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256T1][1] = count / 18000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256T1][2] = count / 140;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256T1][3] = count / 200;
    ec_elgamal_c[R_EC_ELGAMAL_BRP256T1][4] = count / 32000;

    ec_elgamal_c[R_EC_ELGAMAL_BRP384R1][0] = count / 60000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384R1][1] = count / 40000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384R1][2] = count / 160;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384R1][3] = count / 210;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384R1][4] = count / 70000;

    ec_elgamal_c[R_EC_ELGAMAL_BRP384T1][0] = count / 60000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384T1][1] = count / 40000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384T1][2] = count / 160;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384T1][3] = count / 210;
    ec_elgamal_c[R_EC_ELGAMAL_BRP384T1][4] = count / 70000;

    ec_elgamal_c[R_EC_ELGAMAL_BRP512R1][0] = count / 90000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512R1][1] = count / 60000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512R1][2] = count / 180;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512R1][3] = count / 210;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512R1][4] = count / 120000;

    ec_elgamal_c[R_EC_ELGAMAL_BRP512T1][0] = count / 90000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512T1][1] = count / 60000;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512T1][2] = count / 180;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512T1][3] = count / 210;
    ec_elgamal_c[R_EC_ELGAMAL_BRP512T1][4] = count / 120000;
# ifndef OPENSSL_NO_SM2
    ec_elgamal_c[R_EC_ELGAMAL_SM2][0] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_SM2][1] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_SM2][2] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_SM2][3] = count / 20000;
    ec_elgamal_c[R_EC_ELGAMAL_SM2][4] = count / 20000;
# endif  /* OPENSSL_NO_SM2 */
#endif   /* OPENSSL_NO_EC_ELGAMAL */
#ifndef OPENSSL_NO_PAILLIER
    paillier_c[R_PAILLIER_G_OPTIMIZE][0] = count / 18000;
#endif   /* OPENSSL_NO_PAILLIER */

    if (doit[D_MD5]) {
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_MD5], c[D_MD5][testnum], lengths[testnum],
                          seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, MD5_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_MD5, testnum, count, d);
            if (count < 0)
                break;
        }
    }

    if (doit[D_SHA1]) {
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_SHA1], c[D_SHA1][testnum], lengths[testnum],
                          seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, SHA1_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_SHA1, testnum, count, d);
            if (count < 0)
                break;
        }
    }

    if (doit[D_SHA256]) {
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_SHA256], c[D_SHA256][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, SHA256_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_SHA256, testnum, count, d);
            if (count < 0)
                break;
        }
    }

    if (doit[D_SHA512]) {
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_SHA512], c[D_SHA512][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, SHA512_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_SHA512, testnum, count, d);
            if (count < 0)
                break;
        }
    }

#ifndef OPENSSL_NO_SM3
    if (doit[D_SM3]) {
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_SM3], c[D_SM3][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, EVP_Digest_SM3_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_SM3, testnum, count, d);
        }
    }
#endif

    if (doit[D_HMAC]) {
        static const char hmac_key[] = "This is a key...";
        int len = strlen(hmac_key);
        OSSL_PARAM params[3];

        mac = EVP_MAC_fetch(app_get0_libctx(), "HMAC", app_get0_propq());
        if (mac == NULL || evp_mac_mdname == NULL)
            goto end;

        evp_hmac_name = app_malloc(sizeof("hmac()") + strlen(evp_mac_mdname),
                                   "HMAC name");
        sprintf(evp_hmac_name, "hmac(%s)", evp_mac_mdname);
        names[D_HMAC] = evp_hmac_name;

        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                             evp_mac_mdname, 0);
        params[1] =
            OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                              (char *)hmac_key, len);
        params[2] = OSSL_PARAM_construct_end();

        for (i = 0; i < loopargs_len; i++) {
            loopargs[i].mctx = EVP_MAC_CTX_new(mac);
            if (loopargs[i].mctx == NULL)
                goto end;

            if (!EVP_MAC_CTX_set_params(loopargs[i].mctx, params))
                goto end;
        }

        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_HMAC], c[D_HMAC][testnum], lengths[testnum],
                          seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, HMAC_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_HMAC, testnum, count, d);
            if (count < 0)
                break;
        }
        for (i = 0; i < loopargs_len; i++)
            EVP_MAC_CTX_free(loopargs[i].mctx);
        EVP_MAC_free(mac);
        mac = NULL;
    }

    if (doit[D_CBC_DES]) {
        int st = 1;

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].ctx = init_evp_cipher_ctx("des-cbc", deskey,
                                                  sizeof(deskey) / 3);
            st = loopargs[i].ctx != NULL;
        }
        algindex = D_CBC_DES;
        for (testnum = 0; st && testnum < size_num; testnum++) {
            print_message(names[D_CBC_DES], c[D_CBC_DES][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, EVP_Cipher_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_CBC_DES, testnum, count, d);
        }
        for (i = 0; i < loopargs_len; i++)
            EVP_CIPHER_CTX_free(loopargs[i].ctx);
    }

    if (doit[D_EDE3_DES]) {
        int st = 1;

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].ctx = init_evp_cipher_ctx("des-ede3-cbc", deskey,
                                                  sizeof(deskey));
            st = loopargs[i].ctx != NULL;
        }
        algindex = D_EDE3_DES;
        for (testnum = 0; st && testnum < size_num; testnum++) {
            print_message(names[D_EDE3_DES], c[D_EDE3_DES][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count =
                run_benchmark(async_jobs, EVP_Cipher_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_EDE3_DES, testnum, count, d);
        }
        for (i = 0; i < loopargs_len; i++)
            EVP_CIPHER_CTX_free(loopargs[i].ctx);
    }

    for (k = 0; k < 3; k++) {
        algindex = D_CBC_128_AES + k;
        if (doit[algindex]) {
            int st = 1;

            keylen = 16 + k * 8;
            for (i = 0; st && i < loopargs_len; i++) {
                loopargs[i].ctx = init_evp_cipher_ctx(names[algindex],
                                                      key32, keylen);
                st = loopargs[i].ctx != NULL;
            }

            for (testnum = 0; st && testnum < size_num; testnum++) {
                print_message(names[algindex], c[algindex][testnum],
                              lengths[testnum], seconds.sym);
                Time_F(START);
                count =
                    run_benchmark(async_jobs, EVP_Cipher_loop, loopargs);
                d = Time_F(STOP);
                print_result(algindex, testnum, count, d);
            }
            for (i = 0; i < loopargs_len; i++)
                EVP_CIPHER_CTX_free(loopargs[i].ctx);
        }
    }

    for (algindex = D_RC4; algindex <= D_CBC_RC5; algindex++) {
        if (doit[algindex]) {
            int st = 1;

            keylen = 16;
            for (i = 0; st && i < loopargs_len; i++) {
                loopargs[i].ctx = init_evp_cipher_ctx(names[algindex],
                                                      key32, keylen);
                st = loopargs[i].ctx != NULL;
            }

            for (testnum = 0; st && testnum < size_num; testnum++) {
                print_message(names[algindex], c[algindex][testnum],
                              lengths[testnum], seconds.sym);
                Time_F(START);
                count =
                    run_benchmark(async_jobs, EVP_Cipher_loop, loopargs);
                d = Time_F(STOP);
                print_result(algindex, testnum, count, d);
            }
            for (i = 0; i < loopargs_len; i++)
                EVP_CIPHER_CTX_free(loopargs[i].ctx);
        }
    }

#ifndef OPENSSL_NO_SM4
    if (doit[D_CBC_SM4]) {
        int st = 1;

        keylen = 16;
        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].ctx = init_evp_cipher_ctx(names[D_CBC_SM4],
                                                  key32, keylen);
            st = loopargs[i].ctx != NULL;
        }

        for (testnum = 0; st && testnum < size_num; testnum++) {
            print_message(names[D_CBC_SM4], c[D_CBC_SM4][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count =
                run_benchmark(async_jobs, EVP_Cipher_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_CBC_SM4, testnum, count, d);
        }
        for (i = 0; i < loopargs_len; i++)
            EVP_CIPHER_CTX_free(loopargs[i].ctx);
    }
#endif

    if (doit[D_GHASH]) {
        static const char gmac_iv[] = "0123456789ab";
        OSSL_PARAM params[3];

        mac = EVP_MAC_fetch(app_get0_libctx(), "GMAC", app_get0_propq());
        if (mac == NULL)
            goto end;

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_CIPHER,
                                                     "aes-128-gcm", 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_IV,
                                                      (char *)gmac_iv,
                                                      sizeof(gmac_iv) - 1);
        params[2] = OSSL_PARAM_construct_end();

        for (i = 0; i < loopargs_len; i++) {
            loopargs[i].mctx = EVP_MAC_CTX_new(mac);
            if (loopargs[i].mctx == NULL)
                goto end;

            if (!EVP_MAC_init(loopargs[i].mctx, key32, 16, params))
                goto end;
        }
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_GHASH], c[D_GHASH][testnum], lengths[testnum],
                          seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, GHASH_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_GHASH, testnum, count, d);
            if (count < 0)
                break;
        }
        for (i = 0; i < loopargs_len; i++)
            EVP_MAC_CTX_free(loopargs[i].mctx);
        EVP_MAC_free(mac);
        mac = NULL;
    }

    if (doit[D_RAND]) {
        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_RAND], c[D_RAND][testnum], lengths[testnum],
                          seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, RAND_bytes_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_RAND, testnum, count, d);
        }
    }

    if (doit[D_EVP]) {
        if (evp_cipher != NULL) {
            int (*loopfunc) (void *) = EVP_Update_loop;

            if (multiblock && (EVP_CIPHER_get_flags(evp_cipher) &
                               EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK)) {
                multiblock_speed(evp_cipher, lengths_single, &seconds);
                ret = 0;
                goto end;
            }

            names[D_EVP] = EVP_CIPHER_get0_name(evp_cipher);

            if (EVP_CIPHER_get_mode(evp_cipher) == EVP_CIPH_CCM_MODE) {
                loopfunc = EVP_Update_loop_ccm;
            } else if (aead && (EVP_CIPHER_get_flags(evp_cipher) &
                                EVP_CIPH_FLAG_AEAD_CIPHER)) {
                loopfunc = EVP_Update_loop_aead;
                if (lengths == lengths_list) {
                    lengths = aead_lengths_list;
                    size_num = OSSL_NELEM(aead_lengths_list);
                }
            }

            for (testnum = 0; testnum < size_num; testnum++) {
                print_message(names[D_EVP], c[D_EVP][testnum], lengths[testnum],
                              seconds.sym);

                for (k = 0; k < loopargs_len; k++) {
                    loopargs[k].ctx = EVP_CIPHER_CTX_new();
                    if (loopargs[k].ctx == NULL) {
                        BIO_printf(bio_err, "\nEVP_CIPHER_CTX_new failure\n");
                        exit(1);
                    }
                    if (!EVP_CipherInit_ex(loopargs[k].ctx, evp_cipher, NULL,
                                           NULL, iv, decrypt ? 0 : 1)) {
                        BIO_printf(bio_err, "\nEVP_CipherInit_ex failure\n");
                        ERR_print_errors(bio_err);
                        exit(1);
                    }

                    EVP_CIPHER_CTX_set_padding(loopargs[k].ctx, 0);

                    keylen = EVP_CIPHER_CTX_get_key_length(loopargs[k].ctx);
                    loopargs[k].key = app_malloc(keylen, "evp_cipher key");
                    EVP_CIPHER_CTX_rand_key(loopargs[k].ctx, loopargs[k].key);
                    if (!EVP_CipherInit_ex(loopargs[k].ctx, NULL, NULL,
                                           loopargs[k].key, NULL, -1)) {
                        BIO_printf(bio_err, "\nEVP_CipherInit_ex failure\n");
                        ERR_print_errors(bio_err);
                        exit(1);
                    }
                    OPENSSL_clear_free(loopargs[k].key, keylen);

                    /* SIV mode only allows for a single Update operation */
                    if (EVP_CIPHER_get_mode(evp_cipher) == EVP_CIPH_SIV_MODE)
                        (void)EVP_CIPHER_CTX_ctrl(loopargs[k].ctx,
                                                  EVP_CTRL_SET_SPEED, 1, NULL);
                }

                Time_F(START);
                count = run_benchmark(async_jobs, loopfunc, loopargs);
                d = Time_F(STOP);
                for (k = 0; k < loopargs_len; k++)
                    EVP_CIPHER_CTX_free(loopargs[k].ctx);
                print_result(D_EVP, testnum, count, d);
            }
        } else if (evp_md_name != NULL) {
            names[D_EVP] = evp_md_name;

            for (testnum = 0; testnum < size_num; testnum++) {
                print_message(names[D_EVP], c[D_EVP][testnum], lengths[testnum],
                              seconds.sym);
                Time_F(START);
                count = run_benchmark(async_jobs, EVP_Digest_md_loop, loopargs);
                d = Time_F(STOP);
                print_result(D_EVP, testnum, count, d);
                if (count < 0)
                    break;
            }
        }
    }

    if (doit[D_EVP_CMAC]) {
        OSSL_PARAM params[3];
        EVP_CIPHER *cipher = NULL;

        mac = EVP_MAC_fetch(app_get0_libctx(), "CMAC", app_get0_propq());
        if (mac == NULL || evp_mac_ciphername == NULL)
            goto end;
        if (!opt_cipher(evp_mac_ciphername, &cipher))
            goto end;

        keylen = EVP_CIPHER_get_key_length(cipher);
        EVP_CIPHER_free(cipher);
        if (keylen <= 0 || keylen > (int)sizeof(key32)) {
            BIO_printf(bio_err, "\nRequested CMAC cipher with unsupported key length.\n");
            goto end;
        }
        evp_cmac_name = app_malloc(sizeof("cmac()")
                                   + strlen(evp_mac_ciphername), "CMAC name");
        sprintf(evp_cmac_name, "cmac(%s)", evp_mac_ciphername);
        names[D_EVP_CMAC] = evp_cmac_name;

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_CIPHER,
                                                     evp_mac_ciphername, 0);
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                      (char *)key32, keylen);
        params[2] = OSSL_PARAM_construct_end();

        for (i = 0; i < loopargs_len; i++) {
            loopargs[i].mctx = EVP_MAC_CTX_new(mac);
            if (loopargs[i].mctx == NULL)
                goto end;

            if (!EVP_MAC_CTX_set_params(loopargs[i].mctx, params))
                goto end;
        }

        for (testnum = 0; testnum < size_num; testnum++) {
            print_message(names[D_EVP_CMAC], c[D_EVP_CMAC][testnum],
                          lengths[testnum], seconds.sym);
            Time_F(START);
            count = run_benchmark(async_jobs, CMAC_loop, loopargs);
            d = Time_F(STOP);
            print_result(D_EVP_CMAC, testnum, count, d);
            if (count < 0)
                break;
        }
        for (i = 0; i < loopargs_len; i++)
            EVP_MAC_CTX_free(loopargs[i].mctx);
        EVP_MAC_free(mac);
        mac = NULL;
    }

    for (i = 0; i < loopargs_len; i++)
        if (RAND_bytes(loopargs[i].buf, 36) <= 0)
            goto end;

    for (testnum = 0; testnum < RSA_NUM; testnum++) {
        EVP_PKEY *rsa_key = NULL;
        int st = 0;

        if (!rsa_doit[testnum])
            continue;

        if (primes > RSA_DEFAULT_PRIME_NUM) {
            /* we haven't set keys yet,  generate multi-prime RSA keys */
            bn = BN_new();
            st = bn != NULL
                && BN_set_word(bn, RSA_F4)
                && init_gen_str(&genctx, "RSA", NULL, 0, NULL, NULL)
                && EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, rsa_keys[testnum].bits) > 0
                && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(genctx, bn) > 0
                && EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) > 0
                && EVP_PKEY_keygen(genctx, &rsa_key);
            BN_free(bn);
            bn = NULL;
            EVP_PKEY_CTX_free(genctx);
            genctx = NULL;
        } else {
            const unsigned char *p = rsa_keys[testnum].data;

            st = (rsa_key = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p,
                                           rsa_keys[testnum].length)) != NULL;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].rsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key, NULL);
            loopargs[i].sigsize = loopargs[i].buflen;
            if (loopargs[i].rsa_sign_ctx[testnum] == NULL
                || EVP_PKEY_sign_init(loopargs[i].rsa_sign_ctx[testnum]) <= 0
                || EVP_PKEY_sign(loopargs[i].rsa_sign_ctx[testnum],
                                 loopargs[i].buf2,
                                 &loopargs[i].sigsize,
                                 loopargs[i].buf, 36) <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                       "RSA sign setup failure.  No RSA sign will be done.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            pkey_print_message("private", "rsa",
                               rsa_c[testnum][0], rsa_keys[testnum].bits,
                               seconds.rsa);
            /* RSA_blinding_on(rsa_key[testnum],NULL); */
            Time_F(START);
            count = run_benchmark(async_jobs, RSA_sign_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R1:%ld:%d:%.2f\n"
                       : "%ld %u bits private RSA's in %.2fs\n",
                       count, rsa_keys[testnum].bits, d);
            rsa_results[testnum][0] = (double)count / d;
            op_count = count;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].rsa_verify_ctx[testnum] = EVP_PKEY_CTX_new(rsa_key,
                                                                   NULL);
            if (loopargs[i].rsa_verify_ctx[testnum] == NULL
                || EVP_PKEY_verify_init(loopargs[i].rsa_verify_ctx[testnum]) <= 0
                || EVP_PKEY_verify(loopargs[i].rsa_verify_ctx[testnum],
                                   loopargs[i].buf2,
                                   loopargs[i].sigsize,
                                   loopargs[i].buf, 36) <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                       "RSA verify setup failure.  No RSA verify will be done.\n");
            ERR_print_errors(bio_err);
            rsa_doit[testnum] = 0;
        } else {
            pkey_print_message("public", "rsa",
                               rsa_c[testnum][1], rsa_keys[testnum].bits,
                               seconds.rsa);
            Time_F(START);
            count = run_benchmark(async_jobs, RSA_verify_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R2:%ld:%d:%.2f\n"
                       : "%ld %u bits public RSA's in %.2fs\n",
                       count, rsa_keys[testnum].bits, d);
            rsa_results[testnum][1] = (double)count / d;
        }

        if (op_count <= 1) {
            /* if longer than 10s, don't do any more */
            stop_it(rsa_doit, testnum);
        }
        EVP_PKEY_free(rsa_key);
    }

    for (testnum = 0; testnum < DSA_NUM; testnum++) {
        EVP_PKEY *dsa_key = NULL;
        int st;

        if (!dsa_doit[testnum])
            continue;

        st = (dsa_key = get_dsa(dsa_bits[testnum])) != NULL;

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].dsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(dsa_key,
                                                                 NULL);
            loopargs[i].sigsize = loopargs[i].buflen;
            if (loopargs[i].dsa_sign_ctx[testnum] == NULL
                || EVP_PKEY_sign_init(loopargs[i].dsa_sign_ctx[testnum]) <= 0

                || EVP_PKEY_sign(loopargs[i].dsa_sign_ctx[testnum],
                                 loopargs[i].buf2,
                                 &loopargs[i].sigsize,
                                 loopargs[i].buf, 20) <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                       "DSA sign setup failure.  No DSA sign will be done.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            pkey_print_message("sign", "dsa",
                               dsa_c[testnum][0], dsa_bits[testnum],
                               seconds.dsa);
            Time_F(START);
            count = run_benchmark(async_jobs, DSA_sign_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R3:%ld:%u:%.2f\n"
                       : "%ld %u bits DSA signs in %.2fs\n",
                       count, dsa_bits[testnum], d);
            dsa_results[testnum][0] = (double)count / d;
            op_count = count;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].dsa_verify_ctx[testnum] = EVP_PKEY_CTX_new(dsa_key,
                                                                   NULL);
            if (loopargs[i].dsa_verify_ctx[testnum] == NULL
                || EVP_PKEY_verify_init(loopargs[i].dsa_verify_ctx[testnum]) <= 0
                || EVP_PKEY_verify(loopargs[i].dsa_verify_ctx[testnum],
                                   loopargs[i].buf2,
                                   loopargs[i].sigsize,
                                   loopargs[i].buf, 36) <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                       "DSA verify setup failure.  No DSA verify will be done.\n");
            ERR_print_errors(bio_err);
            dsa_doit[testnum] = 0;
        } else {
            pkey_print_message("verify", "dsa",
                               dsa_c[testnum][1], dsa_bits[testnum],
                               seconds.dsa);
            Time_F(START);
            count = run_benchmark(async_jobs, DSA_verify_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R4:%ld:%u:%.2f\n"
                       : "%ld %u bits DSA verify in %.2fs\n",
                       count, dsa_bits[testnum], d);
            dsa_results[testnum][1] = (double)count / d;
        }

        if (op_count <= 1) {
            /* if longer than 10s, don't do any more */
            stop_it(dsa_doit, testnum);
        }
        EVP_PKEY_free(dsa_key);
    }

    for (testnum = 0; testnum < ECDSA_NUM; testnum++) {
        EVP_PKEY *ecdsa_key = NULL;
        int st;

        if (!ecdsa_doit[testnum])
            continue;

        st = (ecdsa_key = get_ecdsa(&ec_curves[testnum])) != NULL;

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].ecdsa_sign_ctx[testnum] = EVP_PKEY_CTX_new(ecdsa_key,
                                                                   NULL);
            loopargs[i].sigsize = loopargs[i].buflen;
            if (loopargs[i].ecdsa_sign_ctx[testnum] == NULL
                || EVP_PKEY_sign_init(loopargs[i].ecdsa_sign_ctx[testnum]) <= 0

                || EVP_PKEY_sign(loopargs[i].ecdsa_sign_ctx[testnum],
                                 loopargs[i].buf2,
                                 &loopargs[i].sigsize,
                                 loopargs[i].buf, 20) <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                       "ECDSA sign setup failure.  No ECDSA sign will be done.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            pkey_print_message("sign", "ecdsa",
                               ecdsa_c[testnum][0], ec_curves[testnum].bits,
                               seconds.ecdsa);
            Time_F(START);
            count = run_benchmark(async_jobs, ECDSA_sign_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R5:%ld:%u:%.2f\n"
                       : "%ld %u bits ECDSA signs in %.2fs\n",
                       count, ec_curves[testnum].bits, d);
            ecdsa_results[testnum][0] = (double)count / d;
            op_count = count;
        }

        for (i = 0; st && i < loopargs_len; i++) {
            loopargs[i].ecdsa_verify_ctx[testnum] = EVP_PKEY_CTX_new(ecdsa_key,
                                                                     NULL);
            if (loopargs[i].ecdsa_verify_ctx[testnum] == NULL
                || EVP_PKEY_verify_init(loopargs[i].ecdsa_verify_ctx[testnum]) <= 0
                || EVP_PKEY_verify(loopargs[i].ecdsa_verify_ctx[testnum],
                                   loopargs[i].buf2,
                                   loopargs[i].sigsize,
                                   loopargs[i].buf, 20) <= 0)
                st = 0;
        }
        if (!st) {
            BIO_printf(bio_err,
                       "ECDSA verify setup failure.  No ECDSA verify will be done.\n");
            ERR_print_errors(bio_err);
            ecdsa_doit[testnum] = 0;
        } else {
            pkey_print_message("verify", "ecdsa",
                               ecdsa_c[testnum][1], ec_curves[testnum].bits,
                               seconds.ecdsa);
            Time_F(START);
            count = run_benchmark(async_jobs, ECDSA_verify_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R6:%ld:%u:%.2f\n"
                       : "%ld %u bits ECDSA verify in %.2fs\n",
                       count, ec_curves[testnum].bits, d);
            ecdsa_results[testnum][1] = (double)count / d;
        }

        if (op_count <= 1) {
            /* if longer than 10s, don't do any more */
            stop_it(ecdsa_doit, testnum);
        }
    }

    for (testnum = 0; testnum < EC_NUM; testnum++) {
        int ecdh_checks = 1;

        if (!ecdh_doit[testnum])
            continue;

        for (i = 0; i < loopargs_len; i++) {
            EVP_PKEY_CTX *test_ctx = NULL;
            EVP_PKEY_CTX *ctx = NULL;
            EVP_PKEY *key_A = NULL;
            EVP_PKEY *key_B = NULL;
            size_t outlen;
            size_t test_outlen;

            if ((key_A = get_ecdsa(&ec_curves[testnum])) == NULL /* generate secret key A */
                || (key_B = get_ecdsa(&ec_curves[testnum])) == NULL /* generate secret key B */
                || (ctx = EVP_PKEY_CTX_new(key_A, NULL)) == NULL /* derivation ctx from skeyA */
                || EVP_PKEY_derive_init(ctx) <= 0 /* init derivation ctx */
                || EVP_PKEY_derive_set_peer(ctx, key_B) <= 0 /* set peer pubkey in ctx */
                || EVP_PKEY_derive(ctx, NULL, &outlen) <= 0 /* determine max length */
                || outlen == 0 /* ensure outlen is a valid size */
                || outlen > MAX_ECDH_SIZE /* avoid buffer overflow */) {
                ecdh_checks = 0;
                BIO_printf(bio_err, "ECDH key generation failure.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                break;
            }

            /*
             * Here we perform a test run, comparing the output of a*B and b*A;
             * we try this here and assume that further EVP_PKEY_derive calls
             * never fail, so we can skip checks in the actually benchmarked
             * code, for maximum performance.
             */
            if ((test_ctx = EVP_PKEY_CTX_new(key_B, NULL)) == NULL /* test ctx from skeyB */
                || !EVP_PKEY_derive_init(test_ctx) /* init derivation test_ctx */
                || !EVP_PKEY_derive_set_peer(test_ctx, key_A) /* set peer pubkey in test_ctx */
                || !EVP_PKEY_derive(test_ctx, NULL, &test_outlen) /* determine max length */
                || !EVP_PKEY_derive(ctx, loopargs[i].secret_a, &outlen) /* compute a*B */
                || !EVP_PKEY_derive(test_ctx, loopargs[i].secret_b, &test_outlen) /* compute b*A */
                || test_outlen != outlen /* compare output length */) {
                ecdh_checks = 0;
                BIO_printf(bio_err, "ECDH computation failure.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                break;
            }

            /* Compare the computation results: CRYPTO_memcmp() returns 0 if equal */
            if (CRYPTO_memcmp(loopargs[i].secret_a,
                              loopargs[i].secret_b, outlen)) {
                ecdh_checks = 0;
                BIO_printf(bio_err, "ECDH computations don't match.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                break;
            }

            loopargs[i].ecdh_ctx[testnum] = ctx;
            loopargs[i].outlen[testnum] = outlen;

            EVP_PKEY_free(key_A);
            EVP_PKEY_free(key_B);
            EVP_PKEY_CTX_free(test_ctx);
            test_ctx = NULL;
        }
        if (ecdh_checks != 0) {
            pkey_print_message("", "ecdh",
                               ecdh_c[testnum][0],
                               ec_curves[testnum].bits, seconds.ecdh);
            Time_F(START);
            count =
                run_benchmark(async_jobs, ECDH_EVP_derive_key_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R7:%ld:%d:%.2f\n" :
                       "%ld %u-bits ECDH ops in %.2fs\n", count,
                       ec_curves[testnum].bits, d);
            ecdh_results[testnum][0] = (double)count / d;
            op_count = count;
        }

        if (op_count <= 1) {
            /* if longer than 10s, don't do any more */
            stop_it(ecdh_doit, testnum);
        }
    }

    for (testnum = 0; testnum < EdDSA_NUM; testnum++) {
        int st = 1;
        EVP_PKEY *ed_pkey = NULL;
        EVP_PKEY_CTX *ed_pctx = NULL;

        if (!eddsa_doit[testnum])
            continue;           /* Ignore Curve */
        for (i = 0; i < loopargs_len; i++) {
            loopargs[i].eddsa_ctx[testnum] = EVP_MD_CTX_new();
            if (loopargs[i].eddsa_ctx[testnum] == NULL) {
                st = 0;
                break;
            }
            loopargs[i].eddsa_ctx2[testnum] = EVP_MD_CTX_new();
            if (loopargs[i].eddsa_ctx2[testnum] == NULL) {
                st = 0;
                break;
            }

            if ((ed_pctx = EVP_PKEY_CTX_new_id(ed_curves[testnum].nid,
                                               NULL)) == NULL
                || EVP_PKEY_keygen_init(ed_pctx) <= 0
                || EVP_PKEY_keygen(ed_pctx, &ed_pkey) <= 0) {
                st = 0;
                EVP_PKEY_CTX_free(ed_pctx);
                break;
            }
            EVP_PKEY_CTX_free(ed_pctx);

            if (!EVP_DigestSignInit(loopargs[i].eddsa_ctx[testnum], NULL, NULL,
                                    NULL, ed_pkey)) {
                st = 0;
                EVP_PKEY_free(ed_pkey);
                break;
            }
            if (!EVP_DigestVerifyInit(loopargs[i].eddsa_ctx2[testnum], NULL,
                                      NULL, NULL, ed_pkey)) {
                st = 0;
                EVP_PKEY_free(ed_pkey);
                break;
            }

            EVP_PKEY_free(ed_pkey);
            ed_pkey = NULL;
        }
        if (st == 0) {
            BIO_printf(bio_err, "EdDSA failure.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            for (i = 0; i < loopargs_len; i++) {
                /* Perform EdDSA signature test */
                loopargs[i].sigsize = ed_curves[testnum].sigsize;
                st = EVP_DigestSign(loopargs[i].eddsa_ctx[testnum],
                                    loopargs[i].buf2, &loopargs[i].sigsize,
                                    loopargs[i].buf, 20);
                if (st == 0)
                    break;
            }
            if (st == 0) {
                BIO_printf(bio_err,
                           "EdDSA sign failure.  No EdDSA sign will be done.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
            } else {
                pkey_print_message("sign", ed_curves[testnum].name,
                                   eddsa_c[testnum][0],
                                   ed_curves[testnum].bits, seconds.eddsa);
                Time_F(START);
                count = run_benchmark(async_jobs, EdDSA_sign_loop, loopargs);
                d = Time_F(STOP);

                BIO_printf(bio_err,
                           mr ? "+R8:%ld:%u:%s:%.2f\n" :
                           "%ld %u bits %s signs in %.2fs \n",
                           count, ed_curves[testnum].bits,
                           ed_curves[testnum].name, d);
                eddsa_results[testnum][0] = (double)count / d;
                op_count = count;
            }
            /* Perform EdDSA verification test */
            for (i = 0; i < loopargs_len; i++) {
                st = EVP_DigestVerify(loopargs[i].eddsa_ctx2[testnum],
                                      loopargs[i].buf2, loopargs[i].sigsize,
                                      loopargs[i].buf, 20);
                if (st != 1)
                    break;
            }
            if (st != 1) {
                BIO_printf(bio_err,
                           "EdDSA verify failure.  No EdDSA verify will be done.\n");
                ERR_print_errors(bio_err);
                eddsa_doit[testnum] = 0;
            } else {
                pkey_print_message("verify", ed_curves[testnum].name,
                                   eddsa_c[testnum][1],
                                   ed_curves[testnum].bits, seconds.eddsa);
                Time_F(START);
                count = run_benchmark(async_jobs, EdDSA_verify_loop, loopargs);
                d = Time_F(STOP);
                BIO_printf(bio_err,
                           mr ? "+R9:%ld:%u:%s:%.2f\n"
                           : "%ld %u bits %s verify in %.2fs\n",
                           count, ed_curves[testnum].bits,
                           ed_curves[testnum].name, d);
                eddsa_results[testnum][1] = (double)count / d;
            }

            if (op_count <= 1) {
                /* if longer than 10s, don't do any more */
                stop_it(eddsa_doit, testnum);
            }
        }
    }

#ifndef OPENSSL_NO_SM2
    for (testnum = 0; testnum < SM2_NUM; testnum++) {
        int st = 1;
        EVP_PKEY *sm2_pkey = NULL;

        if (!sm2_doit[testnum])
            continue;           /* Ignore Curve */
        /* Init signing and verification */
        for (i = 0; i < loopargs_len; i++) {
            EVP_PKEY_CTX *sm2_pctx = NULL;
            EVP_PKEY_CTX *sm2_vfy_pctx = NULL;
            EVP_PKEY_CTX *pctx = NULL;
            st = 0;

            loopargs[i].sm2_ctx[testnum] = EVP_MD_CTX_new();
            loopargs[i].sm2_vfy_ctx[testnum] = EVP_MD_CTX_new();
            if (loopargs[i].sm2_ctx[testnum] == NULL
                    || loopargs[i].sm2_vfy_ctx[testnum] == NULL)
                break;

            sm2_pkey = NULL;

            st = !((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, NULL)) == NULL
                || EVP_PKEY_keygen_init(pctx) <= 0
                || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                    sm2_curves[testnum].nid) <= 0
                || EVP_PKEY_keygen(pctx, &sm2_pkey) <= 0);
            EVP_PKEY_CTX_free(pctx);
            if (st == 0)
                break;

            st = 0; /* set back to zero */
            /* attach it sooner to rely on main final cleanup */
            loopargs[i].sm2_pkey[testnum] = sm2_pkey;
            loopargs[i].sigsize = EVP_PKEY_get_size(sm2_pkey);

            sm2_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
            sm2_vfy_pctx = EVP_PKEY_CTX_new(sm2_pkey, NULL);
            if (sm2_pctx == NULL || sm2_vfy_pctx == NULL) {
                EVP_PKEY_CTX_free(sm2_vfy_pctx);
                break;
            }

            /* attach them directly to respective ctx */
            EVP_MD_CTX_set_pkey_ctx(loopargs[i].sm2_ctx[testnum], sm2_pctx);
            EVP_MD_CTX_set_pkey_ctx(loopargs[i].sm2_vfy_ctx[testnum], sm2_vfy_pctx);

            /*
             * No need to allow user to set an explicit ID here, just use
             * the one defined in the 'draft-yang-tls-tl13-sm-suites' I-D.
             */
            if (EVP_PKEY_CTX_set1_id(sm2_pctx, SM2_ID, SM2_ID_LEN) != 1
                || EVP_PKEY_CTX_set1_id(sm2_vfy_pctx, SM2_ID, SM2_ID_LEN) != 1)
                break;

            if (!EVP_DigestSignInit(loopargs[i].sm2_ctx[testnum], NULL,
                                    EVP_sm3(), NULL, sm2_pkey))
                break;
            if (!EVP_DigestVerifyInit(loopargs[i].sm2_vfy_ctx[testnum], NULL,
                                      EVP_sm3(), NULL, sm2_pkey))
                break;
            st = 1;         /* mark loop as succeeded */
        }
        if (st == 0) {
            BIO_printf(bio_err, "SM2 init failure.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            for (i = 0; i < loopargs_len; i++) {
                /* Perform SM2 signature test */
                st = EVP_DigestSign(loopargs[i].sm2_ctx[testnum],
                                    loopargs[i].buf2, &loopargs[i].sigsize,
                                    loopargs[i].buf, 20);
                if (st == 0)
                    break;
            }
            if (st == 0) {
                BIO_printf(bio_err,
                           "SM2 sign failure.  No SM2 sign will be done.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
            } else {
                pkey_print_message("sign", sm2_curves[testnum].name,
                                   sm2_c[testnum][0],
                                   sm2_curves[testnum].bits, seconds.sm2);
                Time_F(START);
                count = run_benchmark(async_jobs, SM2_sign_loop, loopargs);
                d = Time_F(STOP);

                BIO_printf(bio_err,
                           mr ? "+R10:%ld:%u:%s:%.2f\n" :
                           "%ld %u bits %s signs in %.2fs \n",
                           count, sm2_curves[testnum].bits,
                           sm2_curves[testnum].name, d);
                sm2_results[testnum][0] = (double)count / d;
                op_count = count;
            }

            /* Perform SM2 verification test */
            for (i = 0; i < loopargs_len; i++) {
                st = EVP_DigestVerify(loopargs[i].sm2_vfy_ctx[testnum],
                                      loopargs[i].buf2, loopargs[i].sigsize,
                                      loopargs[i].buf, 20);
                if (st != 1)
                    break;
            }
            if (st != 1) {
                BIO_printf(bio_err,
                           "SM2 verify failure.  No SM2 verify will be done.\n");
                ERR_print_errors(bio_err);
                sm2_doit[testnum] = 0;
            } else {
                pkey_print_message("verify", sm2_curves[testnum].name,
                                   sm2_c[testnum][1],
                                   sm2_curves[testnum].bits, seconds.sm2);
                Time_F(START);
                count = run_benchmark(async_jobs, SM2_verify_loop, loopargs);
                d = Time_F(STOP);
                BIO_printf(bio_err,
                           mr ? "+R11:%ld:%u:%s:%.2f\n"
                           : "%ld %u bits %s verify in %.2fs\n",
                           count, sm2_curves[testnum].bits,
                           sm2_curves[testnum].name, d);
                sm2_results[testnum][1] = (double)count / d;
            }

            if (op_count <= 1) {
                /* if longer than 10s, don't do any more */
                for (testnum++; testnum < SM2_NUM; testnum++)
                    sm2_doit[testnum] = 0;
            }
        }
    }
#endif                         /* OPENSSL_NO_SM2 */

#ifndef OPENSSL_NO_DH
    for (testnum = 0; testnum < FFDH_NUM; testnum++) {
        int ffdh_checks = 1;

        if (!ffdh_doit[testnum])
            continue;

        for (i = 0; i < loopargs_len; i++) {
            EVP_PKEY *pkey_A = NULL;
            EVP_PKEY *pkey_B = NULL;
            EVP_PKEY_CTX *ffdh_ctx = NULL;
            EVP_PKEY_CTX *test_ctx = NULL;
            size_t secret_size;
            size_t test_out;

            /* Ensure that the error queue is empty */
            if (ERR_peek_error()) {
                BIO_printf(bio_err,
                           "WARNING: the error queue contains previous unhandled errors.\n");
                ERR_print_errors(bio_err);
            }

            pkey_A = EVP_PKEY_new();
            if (!pkey_A) {
                BIO_printf(bio_err, "Error while initialising EVP_PKEY (out of memory?).\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            pkey_B = EVP_PKEY_new();
            if (!pkey_B) {
                BIO_printf(bio_err, "Error while initialising EVP_PKEY (out of memory?).\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }

            ffdh_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
            if (!ffdh_ctx) {
                BIO_printf(bio_err, "Error while allocating EVP_PKEY_CTX.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }

            if (EVP_PKEY_keygen_init(ffdh_ctx) <= 0) {
                BIO_printf(bio_err, "Error while initialising EVP_PKEY_CTX.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (EVP_PKEY_CTX_set_dh_nid(ffdh_ctx, ffdh_params[testnum].nid) <= 0) {
                BIO_printf(bio_err, "Error setting DH key size for keygen.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }

            if (EVP_PKEY_keygen(ffdh_ctx, &pkey_A) <= 0 ||
                EVP_PKEY_keygen(ffdh_ctx, &pkey_B) <= 0) {
                BIO_printf(bio_err, "FFDH key generation failure.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }

            EVP_PKEY_CTX_free(ffdh_ctx);

            /*
             * check if the derivation works correctly both ways so that
             * we know if future derive calls will fail, and we can skip
             * error checking in benchmarked code
             */
            ffdh_ctx = EVP_PKEY_CTX_new(pkey_A, NULL);
            if (ffdh_ctx == NULL) {
                BIO_printf(bio_err, "Error while allocating EVP_PKEY_CTX.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (EVP_PKEY_derive_init(ffdh_ctx) <= 0) {
                BIO_printf(bio_err, "FFDH derivation context init failure.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (EVP_PKEY_derive_set_peer(ffdh_ctx, pkey_B) <= 0) {
                BIO_printf(bio_err, "Assigning peer key for derivation failed.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (EVP_PKEY_derive(ffdh_ctx, NULL, &secret_size) <= 0) {
                BIO_printf(bio_err, "Checking size of shared secret failed.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (secret_size > MAX_FFDH_SIZE) {
                BIO_printf(bio_err, "Assertion failure: shared secret too large.\n");
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (EVP_PKEY_derive(ffdh_ctx,
                                loopargs[i].secret_ff_a,
                                &secret_size) <= 0) {
                BIO_printf(bio_err, "Shared secret derive failure.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            /* Now check from side B */
            test_ctx = EVP_PKEY_CTX_new(pkey_B, NULL);
            if (!test_ctx) {
                BIO_printf(bio_err, "Error while allocating EVP_PKEY_CTX.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }
            if (!EVP_PKEY_derive_init(test_ctx) ||
                !EVP_PKEY_derive_set_peer(test_ctx, pkey_A) ||
                !EVP_PKEY_derive(test_ctx, NULL, &test_out) ||
                !EVP_PKEY_derive(test_ctx, loopargs[i].secret_ff_b, &test_out) ||
                test_out != secret_size) {
                BIO_printf(bio_err, "FFDH computation failure.\n");
                op_count = 1;
                ffdh_checks = 0;
                break;
            }

            /* compare the computed secrets */
            if (CRYPTO_memcmp(loopargs[i].secret_ff_a,
                              loopargs[i].secret_ff_b, secret_size)) {
                BIO_printf(bio_err, "FFDH computations don't match.\n");
                ERR_print_errors(bio_err);
                op_count = 1;
                ffdh_checks = 0;
                break;
            }

            loopargs[i].ffdh_ctx[testnum] = ffdh_ctx;

            EVP_PKEY_free(pkey_A);
            pkey_A = NULL;
            EVP_PKEY_free(pkey_B);
            pkey_B = NULL;
            EVP_PKEY_CTX_free(test_ctx);
            test_ctx = NULL;
        }
        if (ffdh_checks != 0) {
            pkey_print_message("", "ffdh", ffdh_c[testnum][0],
                               ffdh_params[testnum].bits, seconds.ffdh);
            Time_F(START);
            count =
                run_benchmark(async_jobs, FFDH_derive_key_loop, loopargs);
            d = Time_F(STOP);
            BIO_printf(bio_err,
                       mr ? "+R12:%ld:%d:%.2f\n" :
                       "%ld %u-bits FFDH ops in %.2fs\n", count,
                       ffdh_params[testnum].bits, d);
            ffdh_results[testnum][0] = (double)count / d;
            op_count = count;
        }
        if (op_count <= 1) {
            /* if longer than 10s, don't do any more */
            stop_it(ffdh_doit, testnum);
        }
    }
#endif  /* OPENSSL_NO_DH */

#ifndef OPENSSL_NO_EC_ELGAMAL
    for (testnum = 0; testnum < EC_ELGAMAL_NUM; testnum++) {
        int st = 1;
        int32_t r = 0;
        EC_ELGAMAL_CTX *ectx = NULL;

        if (!ec_elgamal_doit[testnum])
            continue;           /* Ignore Curve */
        ec_elgamal_plaintext_b = ec_elgamal_plaintexts[0];

        for (i = 0; i < loopargs_len; i++) {
            loopargs[i].ec_elgamal_key[testnum] =
                EC_KEY_new_by_curve_name(test_ec_elgamal_curves[testnum].nid);
            if (loopargs[i].ec_elgamal_key[testnum] == NULL) {
                st = 0;
                break;
            }

            EC_KEY_precompute_mult(loopargs[i].ec_elgamal_key[testnum], NULL);
            EC_KEY_generate_key(loopargs[i].ec_elgamal_key[testnum]);

            ectx = EC_ELGAMAL_CTX_new(loopargs[i].ec_elgamal_key[testnum],
                                      ec_elgamal_flag[testnum]);
            if (ectx == NULL) {
                st = 0;
                break;
            }

            loopargs[i].ec_elgamal_ctx[testnum] = ectx;

            loopargs[i].ciphertext_a[testnum] = EC_ELGAMAL_CIPHERTEXT_new(ectx);
            loopargs[i].ciphertext_b[testnum] = EC_ELGAMAL_CIPHERTEXT_new(ectx);
            loopargs[i].ciphertext_r[testnum] = EC_ELGAMAL_CIPHERTEXT_new(ectx);

            if (!mr)
                BIO_printf(bio_err, "Doing %s ec_elgamal init with curve %s: ",
                           ec_elgamal_flag[testnum] == EC_ELGAMAL_FLAG_TWISTED ? "twisted" : "",
                           test_ec_elgamal_curves[testnum].name);

            Time_F(START);
            loopargs[i].decrypt_table[testnum][0] = EC_ELGAMAL_DECRYPT_TABLE_new(ectx, 0);
            d = Time_F(STOP);
            ec_elgamal_results[testnum][0][0] = d;
            Time_F(START);
            loopargs[i].decrypt_table[testnum][1] = EC_ELGAMAL_DECRYPT_TABLE_new(ectx, 1);
            d = Time_F(STOP);
            ec_elgamal_results[testnum][1][0] = d;

            if (!mr)
                BIO_printf(bio_err, "%.2fs\n", d);

            EC_ELGAMAL_CTX_set_decrypt_table(ectx,
                                             loopargs[i].decrypt_table[testnum][1]);

            if (!EC_ELGAMAL_encrypt(ectx, loopargs[i].ciphertext_a[testnum],
                                    ec_elgamal_plaintext_a)
                || !EC_ELGAMAL_encrypt(ectx, loopargs[i].ciphertext_b[testnum],
                                       ec_elgamal_plaintext_b)
                || !EC_ELGAMAL_add(ectx, loopargs[i].ciphertext_r[testnum],
                                   loopargs[i].ciphertext_a[testnum],
                                   loopargs[i].ciphertext_b[testnum])
                || !EC_ELGAMAL_decrypt(ectx, &r,
                                       loopargs[i].ciphertext_r[testnum])
                || r != (ec_elgamal_plaintext_a + ec_elgamal_plaintext_b)
                || !EC_ELGAMAL_sub(ectx, loopargs[i].ciphertext_r[testnum],
                                   loopargs[i].ciphertext_a[testnum],
                                   loopargs[i].ciphertext_b[testnum])
                || !EC_ELGAMAL_decrypt(ectx, &r,
                                       loopargs[i].ciphertext_r[testnum])
                || r != (ec_elgamal_plaintext_a - ec_elgamal_plaintext_b)
                || !EC_ELGAMAL_mul(ectx, loopargs[i].ciphertext_r[testnum],
                                   loopargs[i].ciphertext_b[testnum],
                                   ec_elgamal_plaintext_a)
                || !EC_ELGAMAL_decrypt(ectx, &r,
                                       loopargs[i].ciphertext_r[testnum])
                || r != (ec_elgamal_plaintext_a * ec_elgamal_plaintext_b)) {
                st = 0;
                break;
            }
        }

        if (st == 0) {
            BIO_printf(bio_err, "EC-ElGamal failure.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            unsigned long j = 0;

            for (j = 0; j < sizeof(ec_elgamal_plaintexts) / sizeof(int); j++) {
                ec_elgamal_print_message("encrypt",
                                         test_ec_elgamal_curves[testnum].name,
                                         ec_elgamal_c[testnum][0],
                                         seconds.ec_elgamal,
                                         ec_elgamal_flag[testnum]);
                ec_elgamal_decrypt = 0;
                ec_elgamal_add = 0;
                ec_elgamal_sub = 0;
                ec_elgamal_mul = 0;
                ec_elgamal_plaintext_b = ec_elgamal_plaintexts[j];

                ec_elgamal_encrypt = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, EC_ELGAMAL_loop, loopargs);
                d = Time_F(STOP);
                ec_elgamal_encrypt = 0;

                BIO_printf(bio_err,
                           mr ? "+R13:%ld:%s:%d:%.2f\n" :
                           "%ld %s EC-ElGamal encrypt(%d) in %.2fs \n",
                           count, test_ec_elgamal_curves[testnum].name,
                           ec_elgamal_plaintext_b, d);
                ec_elgamal_results[testnum][j][1] = (double)count / d;

                ec_elgamal_print_message("decrypt",
                                         test_ec_elgamal_curves[testnum].name,
                                         ec_elgamal_c[testnum][1],
                                         seconds.ec_elgamal,
                                         ec_elgamal_flag[testnum]);
                ec_elgamal_decrypt = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, EC_ELGAMAL_loop, loopargs);
                d = Time_F(STOP);
                ec_elgamal_decrypt = 0;

                BIO_printf(bio_err,
                           mr ? "+R14:%ld:%s:%d:%.2f\n" :
                           "%ld %s EC-ElGamal decrypt(%d) in %.2fs \n",
                           count, test_ec_elgamal_curves[testnum].name,
                           ec_elgamal_plaintext_b, d);
                ec_elgamal_results[testnum][j][2] = (double)count / d;

                ec_elgamal_print_message("add",
                                         test_ec_elgamal_curves[testnum].name,
                                         ec_elgamal_c[testnum][2],
                                         seconds.ec_elgamal,
                                         ec_elgamal_flag[testnum]);
                ec_elgamal_add = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, EC_ELGAMAL_loop, loopargs);
                d = Time_F(STOP);
                ec_elgamal_add = 0;

                BIO_printf(bio_err,
                           mr ? "+R15:%ld:%s:%d:%d:%.2f\n" :
                           "%ld %s EC-ElGamal add(%d,%d) in %.2fs \n",
                           count, test_ec_elgamal_curves[testnum].name,
                           ec_elgamal_plaintext_a, ec_elgamal_plaintext_b, d);
                ec_elgamal_results[testnum][j][3] = (double)count / d;

                ec_elgamal_print_message("sub",
                                         test_ec_elgamal_curves[testnum].name,
                                         ec_elgamal_c[testnum][3],
                                         seconds.ec_elgamal,
                                         ec_elgamal_flag[testnum]);
                ec_elgamal_sub = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, EC_ELGAMAL_loop, loopargs);
                d = Time_F(STOP);
                ec_elgamal_sub = 0;

                BIO_printf(bio_err,
                           mr ? "+R16:%ld:%s:%d:%d:%.2f\n" :
                           "%ld %s EC-ElGamal sub(%d,%d) in %.2fs \n",
                           count, test_ec_elgamal_curves[testnum].name,
                           ec_elgamal_plaintext_a, ec_elgamal_plaintext_b, d);
                ec_elgamal_results[testnum][j][4] = (double)count / d;

                ec_elgamal_print_message("mul",
                                         test_ec_elgamal_curves[testnum].name,
                                         ec_elgamal_c[testnum][4],
                                         seconds.ec_elgamal,
                                         ec_elgamal_flag[testnum]);
                ec_elgamal_mul = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, EC_ELGAMAL_loop, loopargs);
                d = Time_F(STOP);
                ec_elgamal_mul = 0;

                BIO_printf(bio_err,
                           mr ? "+R17:%ld:%s:%d:%d:%.2f\n" :
                           "%ld %s EC-ElGamal mul(%d,%d) in %.2fs \n",
                           count, test_ec_elgamal_curves[testnum].name,
                           ec_elgamal_plaintext_a, ec_elgamal_plaintext_b, d);
                ec_elgamal_results[testnum][j][5] = (double)count / d;
            }
        }
    }
#endif                         /* OPENSSL_NO_EC_ELGAMAL */

#ifndef OPENSSL_NO_PAILLIER
    for (testnum = 0; testnum < PAILLIER_NUM; testnum++) {
        int st = 1;
        int32_t r = 0;
        PAILLIER_CTX *ectx = NULL;

        if (!paillier_doit[testnum])
            continue;

        paillier_plaintext_b = paillier_plaintexts[0];

        for (i = 0; i < loopargs_len; i++) {
            loopargs[i].paillier_key[testnum] = PAILLIER_KEY_new();
            if (loopargs[i].paillier_key[testnum] == NULL
                || !PAILLIER_KEY_generate_key(loopargs[i].paillier_key[testnum],
                                              255)
                || !(ectx = PAILLIER_CTX_new(loopargs[i].paillier_key[testnum],
                                             PAILLIER_MAX_THRESHOLD))) {
                st = 0;
                break;
            }

            loopargs[i].paillier_ctx[testnum] = ectx;

            loopargs[i].paillier_ciphertext_a[testnum] = PAILLIER_CIPHERTEXT_new(ectx);
            loopargs[i].paillier_ciphertext_b[testnum] = PAILLIER_CIPHERTEXT_new(ectx);
            loopargs[i].paillier_ciphertext_r[testnum] = PAILLIER_CIPHERTEXT_new(ectx);

            if (!PAILLIER_encrypt(ectx,
                                  loopargs[i].paillier_ciphertext_a[testnum],
                                  paillier_plaintext_a)
                || !PAILLIER_encrypt(ectx,
                                     loopargs[i].paillier_ciphertext_b[testnum],
                                     paillier_plaintext_b)
                || !PAILLIER_add(ectx,
                                 loopargs[i].paillier_ciphertext_r[testnum],
                                 loopargs[i].paillier_ciphertext_a[testnum],
                                 loopargs[i].paillier_ciphertext_b[testnum])
                || !PAILLIER_decrypt(ectx, &r,
                                     loopargs[i].paillier_ciphertext_r[testnum])
                || r != (paillier_plaintext_a + paillier_plaintext_b)
                || !PAILLIER_sub(ectx,
                                 loopargs[i].paillier_ciphertext_r[testnum],
                                 loopargs[i].paillier_ciphertext_a[testnum],
                                 loopargs[i].paillier_ciphertext_b[testnum])
                || !PAILLIER_decrypt(ectx, &r,
                                     loopargs[i].paillier_ciphertext_r[testnum])
                || r != (paillier_plaintext_a - paillier_plaintext_b)
                || !PAILLIER_mul(ectx,
                                 loopargs[i].paillier_ciphertext_r[testnum],
                                 loopargs[i].paillier_ciphertext_b[testnum],
                                 paillier_plaintext_a)
                || !PAILLIER_decrypt(ectx, &r,
                                     loopargs[i].paillier_ciphertext_r[testnum])
                || r != (paillier_plaintext_a * paillier_plaintext_b)) {
                st = 0;
                break;
            }
        }

        if (st == 0) {
            BIO_printf(bio_err, "paillier failure.\n");
            ERR_print_errors(bio_err);
            op_count = 1;
        } else {
            unsigned long j = 0;

            for (j = 0; j < sizeof(paillier_plaintexts) / sizeof(int); j++) {
                paillier_print_message("encrypt",
                                        test_paillier_names[testnum],
                                        paillier_c[testnum][0],
                                        seconds.paillier);
                paillier_decrypt = 0;
                paillier_add = 0;
                paillier_sub = 0;
                paillier_mul = 0;
                paillier_plaintext_b = paillier_plaintexts[j];

                paillier_encrypt = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, PAILLIER_loop, loopargs);
                d = Time_F(STOP);
                paillier_encrypt = 0;

                BIO_printf(bio_err,
                           mr ? "+R18:%ld:%s:%d:%.2f\n" :
                           "%ld %s paillier encrypt(%d) in %.2fs \n",
                           count, test_paillier_names[testnum],
                           paillier_plaintext_b, d);
                paillier_results[testnum][j][1] = (double)count / d;

                paillier_print_message("decrypt",
                                        test_paillier_names[testnum],
                                        paillier_c[testnum][1],
                                        seconds.paillier);
                paillier_decrypt = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, PAILLIER_loop, loopargs);
                d = Time_F(STOP);
                paillier_decrypt = 0;

                BIO_printf(bio_err,
                           mr ? "+R19:%ld:%s:%d:%.2f\n" :
                           "%ld %s paillier decrypt(%d) in %.2fs \n",
                           count, test_paillier_names[testnum],
                           paillier_plaintext_b, d);
                paillier_results[testnum][j][2] = (double)count / d;

                paillier_print_message("add",
                                        test_paillier_names[testnum],
                                        paillier_c[testnum][2],
                                        seconds.paillier);
                paillier_add = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, PAILLIER_loop, loopargs);
                d = Time_F(STOP);
                paillier_add = 0;

                BIO_printf(bio_err,
                           mr ? "+R20:%ld:%s:%d:%d:%.2f\n" :
                           "%ld %s paillier add(%d,%d) in %.2fs \n",
                           count, test_paillier_names[testnum],
                           paillier_plaintext_a, paillier_plaintext_b, d);
                paillier_results[testnum][j][3] = (double)count / d;

                paillier_print_message("sub",
                                        test_paillier_names[testnum],
                                        paillier_c[testnum][3],
                                        seconds.paillier);
                paillier_sub = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, PAILLIER_loop, loopargs);
                d = Time_F(STOP);
                paillier_sub = 0;

                BIO_printf(bio_err,
                           mr ? "+R21:%ld:%s:%d:%d:%.2f\n" :
                           "%ld %s paillier sub(%d,%d) in %.2fs \n",
                           count, test_paillier_names[testnum],
                           paillier_plaintext_a, paillier_plaintext_b, d);
                paillier_results[testnum][j][4] = (double)count / d;

                paillier_print_message("mul",
                                        test_paillier_names[testnum],
                                        paillier_c[testnum][4],
                                        seconds.paillier);
                paillier_mul = 1;
                Time_F(START);
                count = run_benchmark(async_jobs, PAILLIER_loop, loopargs);
                d = Time_F(STOP);
                paillier_mul = 0;

                BIO_printf(bio_err,
                           mr ? "+R22:%ld:%s:%d:%d:%.2f\n" :
                           "%ld %s paillier mul(%d,%d) in %.2fs \n",
                           count, test_paillier_names[testnum],
                           paillier_plaintext_a, paillier_plaintext_b, d);
                paillier_results[testnum][j][5] = (double)count / d;
            }
        }
    }
#endif                         /* OPENSSL_NO_PAILLIER */

#ifndef NO_FORK
 show_res:
#endif
    if (!mr) {
        printf("version: %s\n", OpenSSL_version(OPENSSL_FULL_VERSION_STRING));
        printf("%s\n", OpenSSL_version(OPENSSL_BUILT_ON));
        printf("options: %s\n", BN_options());
        printf("%s\n", OpenSSL_version(OPENSSL_CFLAGS));
        printf("%s\n", OpenSSL_version(OPENSSL_CPU_INFO));
    }

    if (pr_header) {
        if (mr) {
            printf("+H");
        } else {
            printf("The 'numbers' are in 1000s of bytes per second processed.\n");
            printf("type        ");
        }
        for (testnum = 0; testnum < size_num; testnum++)
            printf(mr ? ":%d" : "%7d bytes", lengths[testnum]);
        printf("\n");
    }

    for (k = 0; k < ALGOR_NUM; k++) {
        if (!doit[k])
            continue;
        if (mr)
            printf("+F:%u:%s", k, names[k]);
        else
            printf("%-13s", names[k]);
        for (testnum = 0; testnum < size_num; testnum++) {
            if (results[k][testnum] > 10000 && !mr)
                printf(" %11.2fk", results[k][testnum] / 1e3);
            else
                printf(mr ? ":%.2f" : " %11.2f ", results[k][testnum]);
        }
        printf("\n");
    }
    testnum = 1;
    for (k = 0; k < RSA_NUM; k++) {
        if (!rsa_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%18ssign    verify    sign/s verify/s\n", " ");
            testnum = 0;
        }
        if (mr)
            printf("+F2:%u:%u:%f:%f\n",
                   k, rsa_keys[k].bits, rsa_results[k][0], rsa_results[k][1]);
        else
            printf("rsa %4u bits %8.6fs %8.6fs %8.1f %8.1f\n",
                   rsa_keys[k].bits, 1.0 / rsa_results[k][0], 1.0 / rsa_results[k][1],
                   rsa_results[k][0], rsa_results[k][1]);
    }
    testnum = 1;
    for (k = 0; k < DSA_NUM; k++) {
        if (!dsa_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%18ssign    verify    sign/s verify/s\n", " ");
            testnum = 0;
        }
        if (mr)
            printf("+F3:%u:%u:%f:%f\n",
                   k, dsa_bits[k], dsa_results[k][0], dsa_results[k][1]);
        else
            printf("dsa %4u bits %8.6fs %8.6fs %8.1f %8.1f\n",
                   dsa_bits[k], 1.0 / dsa_results[k][0], 1.0 / dsa_results[k][1],
                   dsa_results[k][0], dsa_results[k][1]);
    }
    testnum = 1;
    for (k = 0; k < OSSL_NELEM(ecdsa_doit); k++) {
        if (!ecdsa_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%30ssign    verify    sign/s verify/s\n", " ");
            testnum = 0;
        }

        if (mr)
            printf("+F4:%u:%u:%f:%f\n",
                   k, ec_curves[k].bits,
                   ecdsa_results[k][0], ecdsa_results[k][1]);
        else
            printf("%4u bits ecdsa (%s) %8.4fs %8.4fs %8.1f %8.1f\n",
                   ec_curves[k].bits, ec_curves[k].name,
                   1.0 / ecdsa_results[k][0], 1.0 / ecdsa_results[k][1],
                   ecdsa_results[k][0], ecdsa_results[k][1]);
    }

    testnum = 1;
    for (k = 0; k < EC_NUM; k++) {
        if (!ecdh_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%30sop      op/s\n", " ");
            testnum = 0;
        }
        if (mr)
            printf("+F5:%u:%u:%f:%f\n",
                   k, ec_curves[k].bits,
                   ecdh_results[k][0], 1.0 / ecdh_results[k][0]);

        else
            printf("%4u bits ecdh (%s) %8.4fs %8.1f\n",
                   ec_curves[k].bits, ec_curves[k].name,
                   1.0 / ecdh_results[k][0], ecdh_results[k][0]);
    }

    testnum = 1;
    for (k = 0; k < OSSL_NELEM(eddsa_doit); k++) {
        if (!eddsa_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%30ssign    verify    sign/s verify/s\n", " ");
            testnum = 0;
        }

        if (mr)
            printf("+F6:%u:%u:%s:%f:%f\n",
                   k, ed_curves[k].bits, ed_curves[k].name,
                   eddsa_results[k][0], eddsa_results[k][1]);
        else
            printf("%4u bits EdDSA (%s) %8.4fs %8.4fs %8.1f %8.1f\n",
                   ed_curves[k].bits, ed_curves[k].name,
                   1.0 / eddsa_results[k][0], 1.0 / eddsa_results[k][1],
                   eddsa_results[k][0], eddsa_results[k][1]);
    }

#ifndef OPENSSL_NO_SM2
    testnum = 1;
    for (k = 0; k < OSSL_NELEM(sm2_doit); k++) {
        if (!sm2_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%30ssign    verify    sign/s verify/s\n", " ");
            testnum = 0;
        }

        if (mr)
            printf("+F7:%u:%u:%s:%f:%f\n",
                   k, sm2_curves[k].bits, sm2_curves[k].name,
                   sm2_results[k][0], sm2_results[k][1]);
        else
            printf("%4u bits SM2 (%s) %8.4fs %8.4fs %8.1f %8.1f\n",
                   sm2_curves[k].bits, sm2_curves[k].name,
                   1.0 / sm2_results[k][0], 1.0 / sm2_results[k][1],
                   sm2_results[k][0], sm2_results[k][1]);
    }
#endif
#ifndef OPENSSL_NO_DH
    testnum = 1;
    for (k = 0; k < FFDH_NUM; k++) {
        if (!ffdh_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%23sop     op/s\n", " ");
            testnum = 0;
        }
        if (mr)
            printf("+F8:%u:%u:%f:%f\n",
                   k, ffdh_params[k].bits,
                   ffdh_results[k][0], 1.0 / ffdh_results[k][0]);

        else
            printf("%4u bits ffdh %8.4fs %8.1f\n",
                   ffdh_params[k].bits,
                   1.0 / ffdh_results[k][0], ffdh_results[k][0]);
    }
#endif /* OPENSSL_NO_DH */

#ifndef OPENSSL_NO_EC_ELGAMAL
    unsigned long j = 0;
    testnum = 1;
    for (k = 0; k < OSSL_NELEM(ec_elgamal_doit); k++) {
        if (!ec_elgamal_doit[k])
            continue;
        if (testnum && !mr) {
            printf("%-20s %15s %15s\n", "EC-ElGamal curve", "init[+](s)", "init[+-](s)");
            testnum = 0;
        }

        if (mr)
            printf("+F9:%u:%s:%f:%f\n", k, test_ec_elgamal_curves[k].name,
                   ec_elgamal_results[k][0][0], ec_elgamal_results[k][1][0]);
        else
            printf("%-20s %15.1f %15.1f\n", test_ec_elgamal_curves[k].name,
                   ec_elgamal_results[k][0][0], ec_elgamal_results[k][1][0]);
    }

    testnum = 1;
    for (k = 0; k < OSSL_NELEM(ec_elgamal_doit); k++) {
        if (!ec_elgamal_doit[k])
            continue;
        if (testnum && !mr) {
            printf("\n%-20s %4s %12s   %12s   %12s %12s %12s %12s\n",
                    "EC-ElGamal curve", "a", "b", "encrypt(b)/s",
                    "decrypt(b)/s", "add(a,b)/s", "sub(a,b)/s", "mul(a,b)/s");
            testnum = 0;
        }

        for (j = 0; j < sizeof(ec_elgamal_plaintexts) / sizeof(int); j++) {
            if (mr)
                printf("+F10:%u:%ld:%s:%d:%d:%f:%f:%f:%f:%f\n", k, j,
                       test_ec_elgamal_curves[k].name, ec_elgamal_plaintext_a,
                       ec_elgamal_plaintexts[j], ec_elgamal_results[k][j][1],
                       ec_elgamal_results[k][j][2], ec_elgamal_results[k][j][3],
                       ec_elgamal_results[k][j][4], ec_elgamal_results[k][j][5]);
            else
                printf("%-20s %4d %12d   %12.1f   %12.1f %12.1f"
                       "%12.1f %12.1f\n", test_ec_elgamal_curves[k].name,
                       ec_elgamal_plaintext_a, ec_elgamal_plaintexts[j],
                       ec_elgamal_results[k][j][1], ec_elgamal_results[k][j][2],
                       ec_elgamal_results[k][j][3], ec_elgamal_results[k][j][4],
                       ec_elgamal_results[k][j][5]);
        }
    }
#endif

#ifndef OPENSSL_NO_PAILLIER
    testnum = 1;
    for (i = 0; i < OSSL_NELEM(paillier_doit); i++) {
        if (!paillier_doit[i])
            continue;
        if (testnum && !mr) {
            printf("\n%-20s %4s %12s   %12s   %12s %12s %12s %12s\n",
                    "paillier type", "a", "b", "encrypt(b)/s",
                    "decrypt(b)/s", "add(a,b)/s", "sub(a,b)/s", "mul(a,b)/s");
            testnum = 0;
        }

        for (k = 0; k < sizeof(paillier_plaintexts) / sizeof(int); k++) {
            if (mr)
                printf("+F11:%u:%d:%s:%d:%d:%f:%f:%f:%f:%f\n", i, k,
                       test_paillier_names[i], paillier_plaintext_a,
                       paillier_plaintexts[k], paillier_results[i][k][1],
                       paillier_results[i][k][2], paillier_results[i][k][3],
                       paillier_results[i][k][4], paillier_results[i][k][5]);
            else
                printf("%-20s %4d %12d   %12.1f   %12.1f %12.1f"
                       "%12.1f %12.1f\n", test_paillier_names[i],
                       paillier_plaintext_a, paillier_plaintexts[k],
                       paillier_results[i][k][1], paillier_results[i][k][2],
                       paillier_results[i][k][3], paillier_results[i][k][4],
                       paillier_results[i][k][5]);
        }
    }
#endif

    ret = 0;

 end:
    ERR_print_errors(bio_err);
    for (i = 0; i < loopargs_len; i++) {
        OPENSSL_free(loopargs[i].buf_malloc);
        OPENSSL_free(loopargs[i].buf2_malloc);

        BN_free(bn);
        EVP_PKEY_CTX_free(genctx);
        for (k = 0; k < RSA_NUM; k++) {
            EVP_PKEY_CTX_free(loopargs[i].rsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].rsa_verify_ctx[k]);
        }
#ifndef OPENSSL_NO_DH
        OPENSSL_free(loopargs[i].secret_ff_a);
        OPENSSL_free(loopargs[i].secret_ff_b);
        for (k = 0; k < FFDH_NUM; k++)
            EVP_PKEY_CTX_free(loopargs[i].ffdh_ctx[k]);
#endif
        for (k = 0; k < DSA_NUM; k++) {
            EVP_PKEY_CTX_free(loopargs[i].dsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].dsa_verify_ctx[k]);
        }
        for (k = 0; k < ECDSA_NUM; k++) {
            EVP_PKEY_CTX_free(loopargs[i].ecdsa_sign_ctx[k]);
            EVP_PKEY_CTX_free(loopargs[i].ecdsa_verify_ctx[k]);
        }
        for (k = 0; k < EC_NUM; k++)
            EVP_PKEY_CTX_free(loopargs[i].ecdh_ctx[k]);
        for (k = 0; k < EdDSA_NUM; k++) {
            EVP_MD_CTX_free(loopargs[i].eddsa_ctx[k]);
            EVP_MD_CTX_free(loopargs[i].eddsa_ctx2[k]);
        }
#ifndef OPENSSL_NO_SM2
        for (k = 0; k < SM2_NUM; k++) {
            EVP_PKEY_CTX *pctx = NULL;

            /* free signing ctx */
            if (loopargs[i].sm2_ctx[k] != NULL
                && (pctx = EVP_MD_CTX_get_pkey_ctx(loopargs[i].sm2_ctx[k])) != NULL)
                EVP_PKEY_CTX_free(pctx);
            EVP_MD_CTX_free(loopargs[i].sm2_ctx[k]);
            /* free verification ctx */
            if (loopargs[i].sm2_vfy_ctx[k] != NULL
                && (pctx = EVP_MD_CTX_get_pkey_ctx(loopargs[i].sm2_vfy_ctx[k])) != NULL)
                EVP_PKEY_CTX_free(pctx);
            EVP_MD_CTX_free(loopargs[i].sm2_vfy_ctx[k]);
            /* free pkey */
            EVP_PKEY_free(loopargs[i].sm2_pkey[k]);
        }
#endif
#ifndef OPENSSL_NO_EC_ELGAMAL
        for (k = 0; k < EC_ELGAMAL_NUM; k++) {
            if (loopargs[i].decrypt_table[k][0] != NULL)
                EC_ELGAMAL_DECRYPT_TABLE_free(loopargs[i].decrypt_table[k][0]);

            if (loopargs[i].decrypt_table[k][1] != NULL)
                EC_ELGAMAL_DECRYPT_TABLE_free(loopargs[i].decrypt_table[k][1]);

            if (loopargs[i].ciphertext_a[k] != NULL)
                EC_ELGAMAL_CIPHERTEXT_free(loopargs[i].ciphertext_a[k]);

            if (loopargs[i].ciphertext_b[k] != NULL)
                EC_ELGAMAL_CIPHERTEXT_free(loopargs[i].ciphertext_b[k]);

            if (loopargs[i].ciphertext_r[k] != NULL)
                EC_ELGAMAL_CIPHERTEXT_free(loopargs[i].ciphertext_r[k]);

            if (loopargs[i].ec_elgamal_key[k] != NULL)
                EC_KEY_free(loopargs[i].ec_elgamal_key[k]);

            if (loopargs[i].ec_elgamal_ctx[k] != NULL)
                EC_ELGAMAL_CTX_free(loopargs[i].ec_elgamal_ctx[k]);
        }
#endif
#ifndef OPENSSL_NO_PAILLIER
        for (k = 0; k < PAILLIER_NUM; k++) {
            if (loopargs[i].paillier_ciphertext_a[k] != NULL)
                PAILLIER_CIPHERTEXT_free(loopargs[i].paillier_ciphertext_a[k]);

            if (loopargs[i].paillier_ciphertext_b[k] != NULL)
                PAILLIER_CIPHERTEXT_free(loopargs[i].paillier_ciphertext_b[k]);

            if (loopargs[i].paillier_ciphertext_r[k] != NULL)
                PAILLIER_CIPHERTEXT_free(loopargs[i].paillier_ciphertext_r[k]);

            if (loopargs[i].paillier_key[k] != NULL)
                PAILLIER_KEY_free(loopargs[i].paillier_key[k]);

            if (loopargs[i].paillier_ctx[k] != NULL)
                PAILLIER_CTX_free(loopargs[i].paillier_ctx[k]);
        }
#endif
        OPENSSL_free(loopargs[i].secret_a);
        OPENSSL_free(loopargs[i].secret_b);
    }
    OPENSSL_free(evp_hmac_name);
    OPENSSL_free(evp_cmac_name);

    if (async_jobs > 0) {
        for (i = 0; i < loopargs_len; i++)
            ASYNC_WAIT_CTX_free(loopargs[i].wait_ctx);
    }

    if (async_init) {
        ASYNC_cleanup_thread();
    }
    OPENSSL_free(loopargs);
    release_engine(e);
    EVP_CIPHER_free(evp_cipher);
    EVP_MAC_free(mac);
    return ret;
}

static void print_message(const char *s, long num, int length, int tm)
{
    BIO_printf(bio_err,
               mr ? "+DT:%s:%d:%d\n"
               : "Doing %s for %ds on %d size blocks: ", s, tm, length);
    (void)BIO_flush(bio_err);
    run = 1;
    alarm(tm);
}

static void pkey_print_message(const char *str, const char *str2, long num,
                               unsigned int bits, int tm)
{
    BIO_printf(bio_err,
               mr ? "+DTP:%d:%s:%s:%d\n"
               : "Doing %u bits %s %s's for %ds: ", bits, str, str2, tm);
    (void)BIO_flush(bio_err);
    run = 1;
    alarm(tm);
}

static void print_result(int alg, int run_no, int count, double time_used)
{
    if (count == -1) {
        BIO_printf(bio_err, "%s error!\n", names[alg]);
        ERR_print_errors(bio_err);
        return;
    }
    BIO_printf(bio_err,
               mr ? "+R:%d:%s:%f\n"
               : "%d %s's in %.2fs\n", count, names[alg], time_used);
    results[alg][run_no] = ((double)count) / time_used * lengths[run_no];
}

#ifndef OPENSSL_NO_EC_ELGAMAL
static void ec_elgamal_print_message(const char *str, const char *str2,
                                     long num, int tm, int flag)
{
# ifdef SIGALRM
    BIO_printf(bio_err,
               mr ? "+DTP:%s:%s:%s:%d\n"
               : "Doing %s ec_elgamal %s with curve %s for %ds: ",
               flag == EC_ELGAMAL_FLAG_TWISTED ? "twisted" : "", str, str2, tm);
    (void)BIO_flush(bio_err);
    run = 1;
    alarm(tm);
# else
    BIO_printf(bio_err,
               mr ? "+DTP:%s:%s:%s:%d\n"
               : "Doing %s ec_elgamal %s with curve %s for %ld times: ",
               flag == EC_ELGAMAL_FLAG_TWISTED ? "twisted" : "", str, str2, num);
    (void)BIO_flush(bio_err);
# endif
}
#endif

#ifndef OPENSSL_NO_PAILLIER
static void paillier_print_message(const char *str, const char *str2,
                                   long num, int tm)
{
# ifdef SIGALRM
    BIO_printf(bio_err,
               mr ? "+DTP:%s:%s:%d\n"
               : "Doing paillier %s with type %s for %ds: ",
               str, str2, tm);
    (void)BIO_flush(bio_err);
    run = 1;
    alarm(tm);
# else
    BIO_printf(bio_err,
               mr ? "+DTP:%s:%s:%d\n"
               : "Doing paillier %s with type %s for %ld times: ",
               str, str2, num);
    (void)BIO_flush(bio_err);
# endif
}
#endif

#ifndef NO_FORK
static char *sstrsep(char **string, const char *delim)
{
    char isdelim[256];
    char *token = *string;

    if (**string == 0)
        return NULL;

    memset(isdelim, 0, sizeof(isdelim));
    isdelim[0] = 1;

    while (*delim) {
        isdelim[(unsigned char)(*delim)] = 1;
        delim++;
    }

    while (!isdelim[(unsigned char)(**string)])
        (*string)++;

    if (**string) {
        **string = 0;
        (*string)++;
    }

    return token;
}

static int do_multi(int multi, int size_num)
{
    int n;
    int fd[2];
    int *fds;
    static char sep[] = ":";

    fds = app_malloc(sizeof(*fds) * multi, "fd buffer for do_multi");
    for (n = 0; n < multi; ++n) {
        if (pipe(fd) == -1) {
            BIO_printf(bio_err, "pipe failure\n");
            exit(1);
        }
        fflush(stdout);
        (void)BIO_flush(bio_err);
        if (fork()) {
            close(fd[1]);
            fds[n] = fd[0];
        } else {
            close(fd[0]);
            close(1);
            if (dup(fd[1]) == -1) {
                BIO_printf(bio_err, "dup failed\n");
                exit(1);
            }
            close(fd[1]);
            mr = 1;
            usertime = 0;
            OPENSSL_free(fds);
            return 0;
        }
        printf("Forked child %d\n", n);
    }

    /* for now, assume the pipe is long enough to take all the output */
    for (n = 0; n < multi; ++n) {
        FILE *f;
        char buf[1024];
        char *p;

        f = fdopen(fds[n], "r");
        while (fgets(buf, sizeof(buf), f)) {
            p = strchr(buf, '\n');
            if (p)
                *p = '\0';
            if (buf[0] != '+') {
                BIO_printf(bio_err,
                           "Don't understand line '%s' from child %d\n", buf,
                           n);
                continue;
            }
            printf("Got: %s from %d\n", buf, n);
            if (strncmp(buf, "+F:", 3) == 0) {
                int alg;
                int j;

                p = buf + 3;
                alg = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);
                for (j = 0; j < size_num; ++j)
                    results[alg][j] += atof(sstrsep(&p, sep));
            } else if (strncmp(buf, "+F2:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                rsa_results[k][0] += d;

                d = atof(sstrsep(&p, sep));
                rsa_results[k][1] += d;
            } else if (strncmp(buf, "+F3:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                dsa_results[k][0] += d;

                d = atof(sstrsep(&p, sep));
                dsa_results[k][1] += d;
            } else if (strncmp(buf, "+F4:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                ecdsa_results[k][0] += d;

                d = atof(sstrsep(&p, sep));
                ecdsa_results[k][1] += d;
            } else if (strncmp(buf, "+F5:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                ecdh_results[k][0] += d;
            } else if (strncmp(buf, "+F6:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                eddsa_results[k][0] += d;

                d = atof(sstrsep(&p, sep));
                eddsa_results[k][1] += d;
# ifndef OPENSSL_NO_SM2
            } else if (strncmp(buf, "+F7:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                sm2_results[k][0] += d;

                d = atof(sstrsep(&p, sep));
                sm2_results[k][1] += d;
# endif /* OPENSSL_NO_SM2 */
# ifndef OPENSSL_NO_DH
            } else if (strncmp(buf, "+F8:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                ffdh_results[k][0] += d;
# endif /* OPENSSL_NO_DH */
# ifndef OPENSSL_NO_EC_ELGAMAL
            } else if (strncmp(buf, "+F9:", 4) == 0) {
                int k;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][0][0] += d;

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][1][0] += d;
            } else if (strncmp(buf, "+F10:", 4) == 0) {
                int k, j;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                j = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);
                sstrsep(&p, sep);
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][j][1] += d;

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][j][2] += d;

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][j][3] += d;

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][j][4] += d;

                d = atof(sstrsep(&p, sep));
                ec_elgamal_results[k][j][5] += d;
# endif /* OPENSSL_NO_EC_ELGAMAL */
# ifndef OPENSSL_NO_PAILLIER
            } else if (strncmp(buf, "+F11:", 4) == 0) {
                int k, j;
                double d;

                p = buf + 4;
                k = atoi(sstrsep(&p, sep));
                j = atoi(sstrsep(&p, sep));
                sstrsep(&p, sep);
                sstrsep(&p, sep);
                sstrsep(&p, sep);

                d = atof(sstrsep(&p, sep));
                paillier_results[k][j][1] += d;

                d = atof(sstrsep(&p, sep));
                paillier_results[k][j][2] += d;

                d = atof(sstrsep(&p, sep));
                paillier_results[k][j][3] += d;

                d = atof(sstrsep(&p, sep));
                paillier_results[k][j][4] += d;

                d = atof(sstrsep(&p, sep));
                paillier_results[k][j][5] += d;
# endif /* OPENSSL_NO_PAILLIER */
            } else if (strncmp(buf, "+H:", 3) == 0) {
                ;
            } else {
                BIO_printf(bio_err, "Unknown type '%s' from child %d\n", buf,
                           n);
            }
        }

        fclose(f);
    }
    OPENSSL_free(fds);
    return 1;
}
#endif

static void multiblock_speed(const EVP_CIPHER *evp_cipher, int lengths_single,
                             const openssl_speed_sec_t *seconds)
{
    static const int mblengths_list[] =
        { 8 * 1024, 2 * 8 * 1024, 4 * 8 * 1024, 8 * 8 * 1024, 8 * 16 * 1024 };
    const int *mblengths = mblengths_list;
    int j, count, keylen, num = OSSL_NELEM(mblengths_list);
    const char *alg_name;
    unsigned char *inp = NULL, *out = NULL, *key, no_key[32], no_iv[16];
    EVP_CIPHER_CTX *ctx = NULL;
    double d = 0.0;

    if (lengths_single) {
        mblengths = &lengths_single;
        num = 1;
    }

    inp = app_malloc(mblengths[num - 1], "multiblock input buffer");
    out = app_malloc(mblengths[num - 1] + 1024, "multiblock output buffer");
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        app_bail_out("failed to allocate cipher context\n");
    if (!EVP_EncryptInit_ex(ctx, evp_cipher, NULL, NULL, no_iv))
        app_bail_out("failed to initialise cipher context\n");

    if ((keylen = EVP_CIPHER_CTX_get_key_length(ctx)) < 0) {
        BIO_printf(bio_err, "Impossible negative key length: %d\n", keylen);
        goto err;
    }
    key = app_malloc(keylen, "evp_cipher key");
    if (!EVP_CIPHER_CTX_rand_key(ctx, key))
        app_bail_out("failed to generate random cipher key\n");
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL))
        app_bail_out("failed to set cipher key\n");
    OPENSSL_clear_free(key, keylen);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_MAC_KEY,
                             sizeof(no_key), no_key))
        app_bail_out("failed to set AEAD key\n");
    if ((alg_name = EVP_CIPHER_get0_name(evp_cipher)) == NULL)
        app_bail_out("failed to get cipher name\n");

    for (j = 0; j < num; j++) {
        print_message(alg_name, 0, mblengths[j], seconds->sym);
        Time_F(START);
        for (count = 0; run && count < INT_MAX; count++) {
            unsigned char aad[EVP_AEAD_TLS1_AAD_LEN];
            EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM mb_param;
            size_t len = mblengths[j];
            int packlen;

            memset(aad, 0, 8);  /* avoid uninitialized values */
            aad[8] = 23;        /* SSL3_RT_APPLICATION_DATA */
            aad[9] = 3;         /* version */
            aad[10] = 2;
            aad[11] = 0;        /* length */
            aad[12] = 0;
            mb_param.out = NULL;
            mb_param.inp = aad;
            mb_param.len = len;
            mb_param.interleave = 8;

            packlen = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_TLS1_1_MULTIBLOCK_AAD,
                                          sizeof(mb_param), &mb_param);

            if (packlen > 0) {
                mb_param.out = out;
                mb_param.inp = inp;
                mb_param.len = len;
                (void)EVP_CIPHER_CTX_ctrl(ctx,
                                          EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT,
                                          sizeof(mb_param), &mb_param);
            } else {
                int pad;

                RAND_bytes(out, 16);
                len += 16;
                aad[11] = (unsigned char)(len >> 8);
                aad[12] = (unsigned char)(len);
                pad = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD,
                                          EVP_AEAD_TLS1_AAD_LEN, aad);
                EVP_Cipher(ctx, out, inp, len + pad);
            }
        }
        d = Time_F(STOP);
        BIO_printf(bio_err, mr ? "+R:%d:%s:%f\n"
                   : "%d %s's in %.2fs\n", count, "evp", d);
        results[D_EVP][j] = ((double)count) / d * mblengths[j];
    }

    if (mr) {
        fprintf(stdout, "+H");
        for (j = 0; j < num; j++)
            fprintf(stdout, ":%d", mblengths[j]);
        fprintf(stdout, "\n");
        fprintf(stdout, "+F:%d:%s", D_EVP, alg_name);
        for (j = 0; j < num; j++)
            fprintf(stdout, ":%.2f", results[D_EVP][j]);
        fprintf(stdout, "\n");
    } else {
        fprintf(stdout,
                "The 'numbers' are in 1000s of bytes per second processed.\n");
        fprintf(stdout, "type                    ");
        for (j = 0; j < num; j++)
            fprintf(stdout, "%7d bytes", mblengths[j]);
        fprintf(stdout, "\n");
        fprintf(stdout, "%-24s", alg_name);

        for (j = 0; j < num; j++) {
            if (results[D_EVP][j] > 10000)
                fprintf(stdout, " %11.2fk", results[D_EVP][j] / 1e3);
            else
                fprintf(stdout, " %11.2f ", results[D_EVP][j]);
        }
        fprintf(stdout, "\n");
    }

 err:
    OPENSSL_free(inp);
    OPENSSL_free(out);
    EVP_CIPHER_CTX_free(ctx);
}
