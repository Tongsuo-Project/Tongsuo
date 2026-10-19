/*
 * uhash.c — VOLEHash (5.4.1) and ZKHash (5.4.2) of SM4th_spec.pdf.
 *
 * Layout notes (Clause 4.5): field elements are LSB-first bit strings,
 * so ToField/FE coincide with the byte layout.  An element of F_{2^64}
 * used inside F_{2^lambdaF} carries the same coefficients (4.5 d)),
 * i.e. the first 8 octets.
 *
 * Both hashes are evaluated with Horner's rule to avoid one inversion
 * per term:  sum_i key^{n-1-i} x[i]  =  ((x[0] k + x[1]) k + ...) ...
 */
#include "uhash.h"

#include <openssl/crypto.h>
#include <string.h>

#define LAM SM4TH_LAMBDA_F       /* 128 */
#define NF SM4TH_N_FIELDS       /* 16 octets */

/* VOLEHash — Clause 5.4.1 (lambdaF = 128, B = 16).
 *
 * n0 = (hat_ell - lambdaF - B)/8 octets      = (2208-128-16)/8 = 258
 * ell' = lambdaF * ceil((hat_ell - lambdaF - B)/lambdaF) bits = 2176
 * h0 has 17 terms (ell'/lambdaF), h1 has 34 terms (ell'/64).
 */
void
vole_hash(const uint8_t *chall1, const uint8_t *x, uint8_t *out)
{
    fe_t eta[4], shat, that64;
    /* D-5 fix: n0 = (hat_ell - lambdaF - B)/8 = (ell + 2*lambdaF)/8 = 258.
     * (The buggy split used ell+lambdaF → 242, matching pre-rev4 code.) */
    unsigned n0 = (SM4TH_ELL + 2 * LAM) / 8;
    unsigned ellp_bytes = (LAM * 17u) / 8u;   /* 272 octets == ceil */
    uint8_t X0[512];
    fe_t h0, h1_64;
    int i;

    /* 5.4.1 a): parse the key */
    for (i = 0; i < 4; i++)
        fe_from_bytes(&eta[i], chall1 + NF * i, NF);
    fe_from_bytes(&shat, chall1 + 4 * NF, NF);
    fe_from_bytes(&that64, chall1 + 5 * NF, 8);      /* F_2^64 view */

    /* 5.4.1 b): X0 = x[0,n0) || 00d (zero padding to ell'/8 octets).
     * n0 = 258 and ell'/8 = 272, so 14 octets of padding.            */
    memset(X0, 0, sizeof(X0));
    memcpy(X0, x, n0);
    (void)ellp_bytes;

    /* 5.4.1 c): h0 = ~s^(17-1-i) term sum over 17 blocks of 16 octets.
     * Also 5.4.1 d): h1 = t^(34-1-i) over 34 blocks of 8 octets,
     * computed in real F_2^64 (fields.h supports nbits = 64).       */
    fe_zero(&h0);
    fe_zero(&h1_64);
    {
        fe_t block;
        for (i = 0; i < 17; i++) {
            fe_from_bytes(&block, X0 + 16 * i, 16);
            if (i == 0) {
                fe_set(&h0, &block);
            } else {
                fe_t t;
                gf_mul(&t, &h0, &shat, LAM);
                fe_xor(&t, &block);
                fe_set(&h0, &t);
            }
        }
        for (i = 0; i < 34; i++) {
            fe_t t;
            fe_from_bytes(&block, X0 + 8 * i, 8);
            if (i == 0) {
                fe_set(&h1_64, &block);
            } else {
                gf_mul(&t, &h1_64, &that64, 64);
                fe_xor(&t, &block);
                fe_set(&h1_64, &t);
            }
        }
    }

    /* 5.4.1 e)-f) */
    {
        fe_t h1inL;                 /* coefficients of h1 in F_2^128 */
        fe_t h2, h3, t;
        fe_zero(&h1inL);
        memcpy(h1inL.b, h1_64.b, 8);

        gf_mul(&h2, &eta[0], &h0, LAM);
        gf_mul(&t, &eta[1], &h1inL, LAM);
        fe_xor(&h2, &t);
        gf_mul(&h3, &eta[2], &h0, LAM);
        gf_mul(&t, &eta[3], &h1inL, LAM);
        fe_xor(&h3, &t);

        /* out = FE(h2) || FE(h3)[0,2)  xor  x[n0, hat_lbytes) */
        memcpy(out, h2.b, NF);
        out[NF] = h3.b[0];
        out[NF + 1] = h3.b[1];
        for (i = 0; i < (int)(NF + 2); i++)
            out[i] ^= x[n0 + i];
        OPENSSL_cleanse(&h1inL, sizeof(h1inL));
        OPENSSL_cleanse(&h2, sizeof(h2));
        OPENSSL_cleanse(&h3, sizeof(h3));
        OPENSSL_cleanse(&t, sizeof(t));
    }
    OPENSSL_cleanse(X0, sizeof(X0));
    OPENSSL_cleanse(&h0, sizeof(h0));
    OPENSSL_cleanse(&h1_64, sizeof(h1_64));
}

/* ZKHash — Clause 5.4.2 */
void
zk_hash(const uint8_t *chall2, const fe_t *x0, int n, fe_t x1, fe_t *out)
{
    fe_t r0, r1, shat, that64, h0, h1;
    int i;

    fe_from_bytes(&r0, chall2, NF);
    fe_from_bytes(&r1, chall2 + NF, NF);
    fe_from_bytes(&shat, chall2 + 2 * NF, NF);
    fe_from_bytes(&that64, chall2 + 3 * NF, 8);

    /* Horner: h0 = x0[0]; h0 = h0*s + x0[i] gives s^{n-1-i} weights */
    fe_zero(&h0);
    fe_zero(&h1);
    for (i = 0; i < n; i++) {
        if (i == 0) {
            fe_set(&h0, &x0[i]);
            fe_set(&h1, &x0[i]);
        } else {
            fe_t t;
            gf_mul(&t, &h0, &shat, LAM);
            fe_xor(&t, &x0[i]);
            fe_set(&h0, &t);
            gf_mul(&t, &h1, &that64, LAM);   /* 64-bit coefficients */
            fe_xor(&t, &x0[i]);
            fe_set(&h1, &t);
        }
    }

    {
        fe_t a, b, c;
        gf_mul(&a, &r0, &h0, LAM);
        gf_mul(&b, &r1, &h1, LAM);
        fe_add(&c, &a, &b);
        fe_add(out, &c, &x1);
        OPENSSL_cleanse(&a, sizeof(a));
        OPENSSL_cleanse(&b, sizeof(b));
        OPENSSL_cleanse(&c, sizeof(c));
    }
    OPENSSL_cleanse(&h0, sizeof(h0));
    OPENSSL_cleanse(&h1, sizeof(h1));
    OPENSSL_cleanse(&x1, sizeof(x1));
}
