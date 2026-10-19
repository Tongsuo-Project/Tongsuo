/*
 * fields.h — arithmetic in F_{2^n} for n in {64, 128, 160}.
 *
 * Element representation (Clause 4.5): an element  sum a_j z^j  is stored
 * LSB-first: bit j of the element is bit (j mod 8) of octet j/8.  "ToField",
 * "FE" and the octet strings of the specification share this layout, so a
 * field element of n bits is simply the first n/8 octets of a bit string.
 *
 * Field polynomials (Table 2):
 *   F_2^64 : z^64  + z^4 + z^3 + z + 1        (low-terms mask 0x1B)
 *   F_2^128: z^128 + z^7 + z^2 + z + 1        (low-terms mask 0x87)
 *   F_2^160: z^160 + z^5 + z^3 + z^2 + 1      (low-terms mask 0x2D)
 */
#ifndef SM4TH_FIELDS_H
#define SM4TH_FIELDS_H

#include <openssl/e_os2.h>
#include <stdint.h>
#include <string.h>

#define FE_MAX_BYTES 20 /* 160 bits */

typedef struct { uint8_t b[FE_MAX_BYTES]; } fe_t;

/* mask of the low-order terms of the modulus z^n + (mask), n in {64,128,160}*/
#define GF_LOW_64   0x1Bu
#define GF_LOW_128  0x87u
#define GF_LOW_160  0x2Du

static ossl_inline unsigned gf_low_terms(int nbits)
{
    return nbits == 64 ? GF_LOW_64 : (nbits == 128 ? GF_LOW_128 : GF_LOW_160);
}

static ossl_inline void fe_zero(fe_t *x) { memset(x->b, 0, FE_MAX_BYTES); }
static ossl_inline void fe_set(fe_t *x, const fe_t *a) { *x = *a; }

static ossl_inline int fe_bit(const fe_t *x, int bit) /* bit < 160 */
{
    return (x->b[bit >> 3] >> (bit & 7)) & 1;
}

static ossl_inline void fe_setbit(fe_t *x, int bit, int v)
{
    if (v)   x->b[bit >> 3] |= (uint8_t)(1u << (bit & 7));
    else     x->b[bit >> 3] &= (uint8_t)~(1u << (bit & 7));
}

static ossl_inline void fe_xor(fe_t *r, const fe_t *a)
{
    int i;
    for (i = 0; i < FE_MAX_BYTES; i++) r->b[i] ^= a->b[i];
}

static ossl_inline int fe_is_zero(const fe_t *x)
{
    int i, acc = 0;
    for (i = 0; i < FE_MAX_BYTES; i++) acc |= x->b[i];
    return acc == 0;
}

static ossl_inline int fe_eq(const fe_t *a, const fe_t *b)
{
    int i;
    for (i = 0; i < FE_MAX_BYTES; i++)
        if (a->b[i] != b->b[i]) return 0;
    return 1;
}

/* fe_is_one: the multiplicative identity (same element in every
 * F_{2^n}); nbits is kept for signature clarity and unused. */
static ossl_inline int fe_is_one(const fe_t *x, int nbits)
{
    int i, acc = 0;
    (void)nbits;
    if (!(x->b[0] & 1))
        return 0;
    acc = x->b[0] & 0xfeu;
    for (i = 1; i < FE_MAX_BYTES; i++) acc |= x->b[i];
    return acc == 0;
}

/* Load the first nbytes of a bit string into an element (identity map). */
static ossl_inline void fe_from_bytes(fe_t *x, const uint8_t *src, int nbytes)
{
    memset(x->b, 0, FE_MAX_BYTES);
    memcpy(x->b, src, (size_t)nbytes);
}

/* r = a + b (= xor). */
static ossl_inline void fe_add(fe_t *r, const fe_t *a, const fe_t *b)
{
    int i;
    for (i = 0; i < FE_MAX_BYTES; i++) r->b[i] = a->b[i] ^ b->b[i];
}

/* Multiplication in F_{2^n}: r := a*b, r may alias a or b. */
void gf_mul(fe_t *r, const fe_t *a, const fe_t *b, int nbits);

/* Squaring: r := a^2. */
void gf_sqr(fe_t *r, const fe_t *a, int nbits);

/* Multiplication by a small constant (bit mask c, c < 2^n) — used for
 * the public constants of the constraints. */
void gf_mul_low(fe_t *r, const fe_t *a, uint64_t c_low, int nbits);

/* Inversion; caller guarantees a != 0. */
void gf_inv(fe_t *r, const fe_t *a, int nbits);

/* Exponentiation: r := base^e (e >= 0) computed by square-and-multiply.
 * If e == 0 the result is 1. */
void gf_pow(fe_t *r, const fe_t *base, uint64_t e, int nbits);

/* ------------------------------------------------------------------ */
/* F_{2^8} = F_2[t]/(t^8+t^7+t^6+t^5+t^4+t^2+1) — Clause 4.5 e).       */
/* An octet u denotes sum u_i t^i with u_0 the LSB bit.                */
/* ------------------------------------------------------------------ */
#define GF8_POLY_LOW 0xF5u /* t^7+t^6+t^5+t^4+t^2+1 (no t^3 term) */

uint8_t gf8_mul(uint8_t a, uint8_t b);
uint8_t gf8_pow(uint8_t a, unsigned e);   /* 0^0 == 1 */
uint8_t gf8_inv(uint8_t a);               /* 0 -> 0 (patched, per 7.1 a) */

#endif /* SM4TH_FIELDS_H */
