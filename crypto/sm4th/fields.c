/*
 * fields.c — arithmetic in F_{2^n}, n in {64, 128, 160}, and F_{2^8}.
 *
 * Every function is written to be auditable against the polynomial
 * definitions of SM4th_spec.pdf Clause 4.5 (Table 2 and 4.5 e)).
 * Elements are bit strings packed LSB-first, matching ToField/FE.
 */
#include "fields.h"
#include <openssl/crypto.h>

/* Fixed iteration counts and mask-based selection for secret operands.
 * nbits is public. All input limbs are loaded before storing r (alias-safe).
 */
void
gf_mul(fe_t *r, const fe_t *a, const fe_t *b, int nbits)
{
    uint64_t x[3] = {0}, y[3] = {0}, acc[3] = {0};
    unsigned low = gf_low_terms(nbits);
    int i, j, nb, limbs, topbits;
    uint64_t topmask;

    if (nbits != 64 && nbits != 128 && nbits != 160)
        return;
    nb = nbits / 8;
    limbs = (nbits + 63) / 64;
    topbits = nbits - 64 * (limbs - 1);
    topmask = UINT64_MAX >> (64 - topbits);
    for (i = 0; i < nb; i++) {
        x[i / 8] |= (uint64_t)a->b[i] << (8 * (i % 8));
        y[i / 8] |= (uint64_t)b->b[i] << (8 * (i % 8));
    }
    for (i = 0; i < nbits; i++) {
        uint64_t mask = UINT64_C(0) - ((y[i / 64] >> (i % 64)) & 1);
        uint64_t carry = x[limbs - 1] >> (topbits - 1);
        for (j = 0; j < limbs; j++)
            acc[j] ^= x[j] & mask;
        for (j = limbs - 1; j > 0; j--)
            x[j] = (x[j] << 1) | (x[j - 1] >> 63);
        x[0] = (x[0] << 1) ^ ((UINT64_C(0) - carry) & low);
        x[limbs - 1] &= topmask;
    }
    fe_zero(r);
    for (i = 0; i < nb; i++)
        r->b[i] = (uint8_t)(acc[i / 8] >> (8 * (i % 8)));
    OPENSSL_cleanse(x, sizeof(x));
    OPENSSL_cleanse(y, sizeof(y));
    OPENSSL_cleanse(acc, sizeof(acc));
}

void
gf_sqr(fe_t *r, const fe_t *a, int nbits)
{
    gf_mul(r, a, a, nbits);
}

void
gf_mul_low(fe_t *r, const fe_t *a, uint64_t c_low, int nbits)
{
    fe_t b;
    int i;
    fe_zero(&b);
    for (i = 0; i < 8; i++)
        b.b[i] = (uint8_t)(c_low >> (8 * i));
    gf_mul(r, a, &b, nbits);
}

void
gf_inv(fe_t *r, const fe_t *a, int nbits)
{
    /* a^(2^n - 2) = (a^(2^(n-1) - 1))^2; the inner exponent is built by
     * the chain  a^(2^k - 1) = (a^(2^(k-1) - 1))^2 * a  (Itoh-style):
     * 2*(2^(k-1) - 1) + 1 = 2^k - 1.                                    */
    fe_t acc, t;
    int k;
    fe_set(&acc, a);         /* a^(2^1 - 1) */
    for (k = 2; k <= nbits - 1; k++) {
        gf_sqr(&t, &acc, nbits);
        gf_mul(&acc, &t, a, nbits);   /* a^(2^k - 1) */
    }
    gf_sqr(r, &acc, nbits);   /* a^(2^n - 2) */
}

void
gf_pow(fe_t *r, const fe_t *base, uint64_t e, int nbits)
{
    fe_t result, base_;
    fe_zero(&result);
    result.b[0] = 1;                    /* 1 */
    fe_set(&base_, base);
    while (e) {
        if (e & 1ULL) {
            fe_t t;
            gf_mul(&t, &result, &base_, nbits);
            fe_set(&result, &t);
        }
        e >>= 1;
        if (e) {
            fe_t t;
            gf_sqr(&t, &base_, nbits);
            fe_set(&base_, &t);
        }
    }
    fe_set(r, &result);
}

/* ------------------------------------------------------------------ */
/* F_{2^8} — SM4 S-box field                                           */
/* ------------------------------------------------------------------ */
uint8_t
gf8_mul(uint8_t a, uint8_t b)
{
    uint8_t acc = 0;
    unsigned i;

    for (i = 0; i < 8; i++) {
        uint8_t mask = (uint8_t)(0u - (a & 1u));
        uint8_t carry = (uint8_t)(b >> 7);
        acc ^= b & mask;
        a >>= 1;
        b = (uint8_t)((b << 1) ^ (GF8_POLY_LOW & (0u - carry)));
    }
    return acc;
}

uint8_t
gf8_pow(uint8_t a, unsigned e)
{
    uint8_t acc = 1; /* convention: a^0 = 1 */
    while (e) {
        if (e & 1u)
            acc = gf8_mul(acc, a);
        e >>= 1;
        if (e)
            a = gf8_mul(a, a);
    }
    return acc;
}

uint8_t
gf8_inv(uint8_t a)
{
    /* The fixed exponent also maps zero to zero, without a special branch. */
    return gf8_pow(a, 254);
}
