/*
 * owf.c — witness extension (8.1) and the non-EM constraint system
 * (7.4 / 9.1 / 9.2 / 9.4) of SM4th_spec.pdf, revision 4.
 *
 * Layered structure:
 *   A. Constants of 7.2/7.4 — solved from their defining linear systems;
 *   B. Witness extension (8.1, Table 5 layout);
 *   C. QuickSilver operations (Table 4) and the constraint driver (9.4)
 *      with the anchor-word gadget (7.4 h)).
 *
 * All bit packing is LSB-first (Clause 4.3 b)); SM4 words inside the
 * witness place byte j at bits p+8j..p+8j+8 (Clause 4.6 c)).
 */
#include <openssl/e_os2.h>
#include "owf.h"
#include "bavc.h"

#include <string.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <stdio.h>

#define LAM SM4TH_LAMBDA_F
#define NF SM4TH_N_FIELDS
#define HATLB (SM4TH_ELL / 8 + 3 * NF + SM4TH_B / 8)
#define DEG SM4TH_DEGREE

typedef struct { fe_t c[4]; fe_t g; int deg; } qs_t;
static qs_t qs_witness_bit(const owf_ctx_t *ctx, unsigned i);

/* Rows of A / A^{-1} (7.1 b); bit j of entry A_ROWS[r] is A[r][j].  These
 * are cross-checked against the GB/T 32907 S-box in test.c.            */
static const uint8_t A_ROWS[8]  = { 0xA7u,0x4Fu,0x9Eu,0x3Du,0x7Au,0xF4u,0xE9u,0xD3u };
static const uint8_t AI_ROWS[8] = { 0x43u,0x86u,0x0Du,0x1Au,0x34u,0x68u,0xD0u,0xA1u };
#define C_AFFINE 0xD3u

static ossl_inline uint32_t rotl32_c(uint32_t x, unsigned n)
{
    return n ? ((x << n) | (x >> (32 - n))) : x;
}

static uint32_t sm4_ck_word(unsigned i)
{
    return ((uint32_t)((4 * i + 0) * 7 % 256) << 24)
         | ((uint32_t)((4 * i + 1) * 7 % 256) << 16)
         | ((uint32_t)((4 * i + 2) * 7 % 256) << 8)
         | (uint32_t)((4 * i + 3) * 7 % 256);
}

/* ------------------------------------------------------------------ */
/* Bit helpers                                                           */
/* ------------------------------------------------------------------ */
static ossl_inline int get_bit(const uint8_t *v, unsigned bit)
{
    return (v[bit >> 3] >> (bit & 7)) & 1;
}

static ossl_inline void set_bit(uint8_t *v, unsigned bit, int b)
{
    uint8_t mask = (uint8_t)(1u << (bit & 7));
    v[bit >> 3] = (uint8_t)((v[bit >> 3] & ~mask)
                          | ((0u - (unsigned)(b & 1)) & mask));
}

/* Set 4 bits starting at 'bit' — used for nibble packing that may
 * straddle an octet boundary (Table 5 rows 2 and 4).                   */
static ossl_inline void put_nib(uint8_t *v, unsigned bit, uint8_t nib)
{
    unsigned t;
    for (t = 0; t < 4; t++)
        set_bit(v, bit + t, (nib >> t) & 1u);
}

/* ------------------------------------------------------------------ */
/* A. Constants of Clause 7.2                                           */
/* ------------------------------------------------------------------ */

/* FE(alpha_8) for lambdaF = 128 — Clause 7.2 a), Table 22 [U-6].      */
static const uint8_t ALPHA8_128[16] = {
    0xb8, 0x4c, 0x7b, 0x2e, 0x8b, 0xa1, 0x14, 0x84,
    0xb9, 0x44, 0x1f, 0xb3, 0xb4, 0x95, 0xa5, 0x51,
};

/* Solve M x = e_rhssel over F_2^128 where M[k][j] = alpha_8^{k * 2^j}.
 * out[j] = the unknown x_j of the solution.                             */
static int
moore_solve_col(fe_t out[8], fe_t moore[8][8], int rhsrow)
{
    fe_t aug[8][9];
    int r, c, k;

    for (r = 0; r < 8; r++) {
        for (c = 0; c < 8; c++)
            fe_set(&aug[r][c], &moore[r][c]);
        fe_zero(&aug[r][8]);
    }
    aug[rhsrow][8].b[0] = 1;

    for (c = 0; c < 8; c++) {
        int piv = -1;
#ifdef OWF_DUMP_MOORE
        if (c == 7)
            for (r = 0; r < 8; r++)
                fprintf(stderr,
                        "  pre-col7 r=%d col7 lsb=[%016llx] msb=[%016llx]\n",
                        r,
                        (unsigned long long)(aug[r][7].b[0])
                        | ((unsigned long long)(aug[r][7].b[1]) << 8)
                        | ((unsigned long long)(aug[r][7].b[2]) << 16)
                        | ((unsigned long long)(aug[r][7].b[3]) << 24)
                        | ((unsigned long long)(aug[r][7].b[4]) << 32),
                        (unsigned long long)(aug[r][7].b[12])
                        | ((unsigned long long)(aug[r][7].b[13]) << 8)
                        | ((unsigned long long)(aug[r][7].b[14]) << 16)
                        | ((unsigned long long)(aug[r][7].b[15]) << 24));
#endif
        for (r = c; r < 8; r++)
            if (!fe_is_zero(&aug[r][c])) { piv = r; break; }
        if (piv < 0) {
            fprintf(stderr, "OWFDBG2: moore_solve rhs=%d col=%d zero-pivot\n",
                    rhsrow, c);
            return -1;
        }
        if (piv != c)
            for (k = 0; k < 9; k++) {
                fe_t t = aug[c][k];
                aug[c][k] = aug[piv][k];
                aug[piv][k] = t;
            }
        {
            fe_t inv;
            gf_inv(&inv, &aug[c][c], LAM);
            for (k = c; k < 9; k++) {
                fe_t t;
                gf_mul(&t, &aug[c][k], &inv, LAM);
                fe_set(&aug[c][k], &t);
            }
        }
#ifdef OWF_DUMP_MOORE
        fprintf(stderr, "after col %d pivot=%d row%d:", c, piv, c);
        for (k = 0; k < 9; k++)
            fprintf(stderr, " %016llx",
                    (unsigned long long)(aug[c][k].b[0])
                    | ((unsigned long long)(aug[c][k].b[1]) << 8)
                    | ((unsigned long long)(aug[c][k].b[2]) << 16)
                    | ((unsigned long long)(aug[c][k].b[3]) << 24));
        fprintf(stderr, "\n");
#endif
        for (r = 0; r < 8; r++) {
            fe_t mult;
            if (r == c)
                continue;
            fe_set(&mult, &aug[r][c]);
            if (fe_is_zero(&mult))
                continue;
            for (k = 0; k < 9; k++) {
                fe_t t;
                gf_mul(&t, &aug[c][k], &mult, LAM);   /* pivot row!   */
                fe_xor(&aug[r][k], &t);
            }
#ifdef OWF_DUMP_MOORE
            if (c == 0) {
                static int once2 = 0;
                if (once2 < 9 * 8) {
                    once2++;
                    fprintf(stderr, "  elim r=%d: mult_lsb=%016llx col0=%016llx col1=%016llx\n",
                            r,
                            (unsigned long long)(mult.b[0])
                            | ((unsigned long long)(mult.b[1]) << 8)
                            | ((unsigned long long)(mult.b[2]) << 16)
                            | ((unsigned long long)(mult.b[3]) << 24)
                            | ((unsigned long long)(mult.b[4]) << 32),
                            (unsigned long long)(aug[r][0].b[0])
                            | ((unsigned long long)(aug[r][0].b[1]) << 8)
                            | ((unsigned long long)(aug[r][0].b[2]) << 16)
                            | ((unsigned long long)(aug[r][0].b[3]) << 24),
                            (unsigned long long)(aug[r][1].b[0])
                            | ((unsigned long long)(aug[r][1].b[1]) << 8)
                            | ((unsigned long long)(aug[r][1].b[2]) << 16)
                            | ((unsigned long long)(aug[r][1].b[3]) << 24));
                }
            }
#endif
        }
    }
    for (c = 0; c < 8; c++)
        fe_set(&out[c], &aug[c][8]);
    return 0;
}

/* Build the InvNorm table (7.4 a) in the constants: for the inversion
 * input x (octet), find the 4-bit decomposition of x^238 in the basis
 * (01, 0c, 50, 2a) = (1, beta, beta^2, beta^3) of Annex A.5 — the same
 * table the SM4 witness extension packs into the nibbles of Table 5.  */
static void
build_invnorm_table(uint8_t tab[256])
{
    unsigned nv, x;
    const uint8_t basis[4] = { 0x01, 0x0c, 0x50, 0x2a };
    uint8_t val[16];

    for (nv = 0; nv < 16; nv++) {
        uint8_t acc = 0;
        if (nv & 1u) acc ^= basis[0];
        if (nv & 2u) acc ^= basis[1];
        if (nv & 4u) acc ^= basis[2];
        if (nv & 8u) acc ^= basis[3];
        val[nv] = acc;
    }
    for (x = 0; x < 256; x++) {
        uint8_t y;
        int found = -1;

        if (x == 0) {
            tab[x] = 0;               /* patched inverse                */
            continue;
        }
        y = gf8_pow((uint8_t)x, 238);
        for (nv = 0; nv < 16; nv++)
            if (val[nv] == y) { found = (int)nv; break; }
        tab[x] = (found >= 0) ? (uint8_t)found : 0;
    }
}

int
owf_consts_init(owf_consts_t *c)
{
    fe_t emb_e[8];        /* Emb(e_k) = alpha_8^k                        */
    fe_t moore[8][8];     /* moore[k][j] = alpha_8^{k * 2^j}             */
    int k, j, r, b, t;

    memset(c, 0, sizeof(*c));

    /* alpha_8[i] = alpha_8^i (Emb(e_i));  alpha_g = alpha_8 itself.
     * FE(alpha_8) is the Table 22 constant;  alpha_8^0 = 1.             */
    fe_from_bytes(&c->alpha_g, ALPHA8_128, 16);
    fe_zero(&c->alpha8[0]);
    c->alpha8[0].b[0] = 1;
    for (k = 1; k < 8; k++)
        gf_mul(&c->alpha8[k], &c->alpha8[k - 1], &c->alpha_g, LAM);

    /* Moore matrix (Emb(e_k))^{2^j} = alpha_8^{k * 2^j}                */
    for (k = 0; k < 8; k++) {
        fe_set(&emb_e[k], &c->alpha8[k]);
        for (j = 0; j < 8; j++) {
            fe_t acc = emb_e[k];
            for (r = 0; r < j; r++)
                gf_sqr(&acc, &acc, LAM);
            fe_set(&moore[k][j], &acc);
        }
    }

#ifdef OWF_DUMP_MOORE
    {
        static int once = 0;
        if (!once) {
            int bb;

            once = 1;
            for (k = 0; k < 8; k++) {
                fprintf(stderr, "moore[%d]:", k);
                for (j = 0; j < 8; j++)
                    for (bb = 0; bb < 16; bb++)
                        fprintf(stderr, "%02x", moore[k][j].b[bb]);
                fprintf(stderr, "\n");
            }
        }
    }
#endif
    /* theta_{b,r} (7.2 g): sum_r theta_{b,r} alpha_8^{k*2^r} = delta_{b,k}
     * — one column solve per b                                          */
    for (b = 0; b < 8; b++)
        if (moore_solve_col(c->theta[b], moore, b) != 0)
            { fprintf(stderr, "OWFDBG: moore_solve_col failed at b=%d\n", b); return -1; }

    /* a-hat_j (7.2 f): sum_j a-hat_j alpha_8^{k*2^j} = Emb(A e_k)      */
    for (k = 0; k < 8; k++)
        fe_set(&emb_e[k], &c->alpha8[0]);      /* reuse emb below        */
    {
        /* column-solve with a custom rhs: reuse the elimination by
         * building the augmented matrix directly                        */
        fe_t aug[8][9];
        for (k = 0; k < 8; k++) {
            fe_t rhs;

            for (j = 0; j < 8; j++)
                fe_set(&aug[k][j], &moore[k][j]);
            /* rhs[k] = Emb(A e_k), where A e_k has bit r = A[r][k]     */
            fe_zero(&rhs);
            for (r = 0; r < 8; r++)
                if ((A_ROWS[r] >> k) & 1u)
                    fe_xor(&rhs, &c->alpha8[r]);
            fe_set(&aug[k][8], &rhs);
        }
        for (j = 0; j < 8; j++) {
            int piv = -1, rr;
            for (rr = j; rr < 8; rr++)
                if (!fe_is_zero(&aug[rr][j])) { piv = rr; break; }
            if (piv < 0)
                { fprintf(stderr, "OWFDBG: a-hat solve pivot failed at j=%d\n", j); return -1; }
            if (piv != j)
                for (r = 0; r < 9; r++) {
                    fe_t tmp = aug[j][r];
                    aug[j][r] = aug[piv][r];
                    aug[piv][r] = tmp;
                }
            {
                fe_t inv;
                gf_inv(&inv, &aug[j][j], LAM);
                for (r = j; r < 9; r++) {
                    fe_t tmp;
                    gf_mul(&tmp, &aug[j][r], &inv, LAM);
                    fe_set(&aug[j][r], &tmp);
                }
            }
            for (rr = 0; rr < 8; rr++) {
                fe_t mult;
                if (rr == j)
                    continue;
                fe_set(&mult, &aug[rr][j]);
                if (fe_is_zero(&mult))
                    continue;
                for (r = 0; r < 9; r++) {
                    fe_t tmp;
                    gf_mul(&tmp, &aug[j][r], &mult, LAM);  /* pivot row j */
                    fe_xor(&aug[rr][r], &tmp);
                }
            }
        }
        for (j = 0; j < 8; j++)
            fe_set(&c->a_hat[0][j], &aug[j][8]);
    }

    /* c-hat = Emb(c) for c = D3                                         */
    for (r = 0; r < 8; r++)
        if ((C_AFFINE >> r) & 1u)
            fe_xor(&c->c_hat, &c->alpha8[r]);

    /* Frobenius copies a-hat^{2^r}, c-hat^{2^r}                          */
    for (r = 0; r < 8; r++) {
        fe_t x = c->c_hat;
        for (k = 0; k < r; k++)
            gf_sqr(&x, &x, LAM);
        fe_set(&c->c_hat_f[r], &x);
        for (j = 0; j < 8; j++) {
            fe_t y = c->a_hat[0][j];
            for (k = 0; k < r; k++)
                gf_sqr(&y, &y, LAM);
            fe_set(&c->a_hat_f[r][j], &y);
        }
    }

    /* b-hat powers: (1, beta, beta^2, beta^3), beta = alpha_8^3+alpha_8^2
     * stored twisted: bhat[r][t] = b-hat_t^{2^r}                        */
    {
        fe_t beta;
        fe_t bvals[4];
        fe_zero(&beta);
        fe_add(&beta, &c->alpha8[3], &c->alpha8[2]);
        fe_zero(&bvals[0]);
        bvals[0].b[0] = 1;
        fe_set(&bvals[1], &beta);
        gf_mul(&bvals[2], &bvals[1], &bvals[1], LAM);
        gf_mul(&bvals[3], &bvals[2], &bvals[1], LAM);
        for (r = 0; r < 4; r++)
            for (t = 0; t < 4; t++) {
                fe_t y = bvals[t];
                for (k = 0; k < r; k++)
                    gf_sqr(&y, &y, LAM);
                fe_set(&c->bhat[r][t], &y);
            }
    }
    build_invnorm_table(c->invnorm_tab);

    /* L / L' / inverses as 32x32 GF(2) basis images; and the
     * Frobenius recombination rows of AffineToConjugates (7.4 b).       */
    return owf_init_linear_maps(c);
}
/* ------------------------------------------------------------------ */
/* A2. Linear maps of Clause 6.2 c) / 7.1 d) / 7.4 b)                   */
/* ------------------------------------------------------------------ */

/* Invert the 32x32 GF(2) map given as basis images m[i] (image of e_i);
 * solve  sum_i y_i * m[i] = e_c  for each c.                            */
static int
inv32_images(const uint32_t m[32], uint32_t inv_out[32])
{
    int i;
    uint64_t rows[32];
    int k, c, r;

    /* rows[k] = (A row k over i) << 32 | e_k, where the image of e_i
     * is m[i]:  equation component k: sum_i y_i * bit_k(m[i]) = e_c[k]  */
    for (k = 0; k < 32; k++) {
        uint64_t left = 0;
        for (i = 0; i < 32; i++)
            if ((m[i] >> k) & 1u)
                left |= 1ull << (32 + i);
        rows[k] = left | (1u << k);
    }

    for (c = 0; c < 32; c++) {
        int piv = -1;
        for (r = c; r < 32; r++)
            if ((rows[r] >> (32 + c)) & 1ull) { piv = r; break; }
        if (piv < 0)
            return -1;
        if (piv != c) {
            uint64_t t = rows[c];
            rows[c] = rows[piv];
            rows[piv] = t;
        }
        for (r = 0; r < 32; r++) {
            if (r == c || !((rows[r] >> (32 + c)) & 1ull))
                continue;
            rows[r] ^= rows[c];
        }
    }

    /* after reduction, row k has left half e_k and right half row k of
     * the inverse matrix; the image of e_c under the inverse map is the
     * c-th column: bit k = right-half bit c of row k.                   */
    for (c = 0; c < 32; c++) {
        uint32_t v = 0;
        for (k = 0; k < 32; k++)
            if ((rows[k] >> c) & 1ull)
                v |= 1u << k;
        inv_out[c] = v;
    }
    return 0;
}

int
owf_init_linear_maps(owf_consts_t *c)
{
    unsigned k, k2;
    /* qw bit k <-> SM4-word bit (k&7)+8*(3-(k>>3)) (BE byte packing of
     * Clause 4.6 c)).  Build L / L' as 32x32 maps in qw bit order so
     * qw_lin can apply them directly.                                  */
#define QW_TO_WORD_BIT(k) (((unsigned)(k) & 7u) + 8u * (3u - ((unsigned)(k) >> 3)))
    for (k = 0; k < 32; k++) {
        uint32_t b = 1u << QW_TO_WORD_BIT(k);
        uint32_t imgL = b ^ rotl32_c(b, 2) ^ rotl32_c(b, 10)
                      ^ rotl32_c(b, 18) ^ rotl32_c(b, 24);
        uint32_t imgP = b ^ rotl32_c(b, 13) ^ rotl32_c(b, 23);
        uint32_t outL = 0, outP = 0;
        for (k2 = 0; k2 < 32; k2++) {
            unsigned wb = QW_TO_WORD_BIT(k2);
            if ((imgL >> wb) & 1u)
                outL |= 1u << k2;
            if ((imgP >> wb) & 1u)
                outP |= 1u << k2;
        }
        c->map_L[k] = outL;
        c->map_Lp[k] = outP;
    }
#undef QW_TO_WORD_BIT
    if (inv32_images(c->map_L, c->map_Linv) != 0)
        { fprintf(stderr, "OWFDBG: inv32_images L failed\n"); return -1; }
    if (inv32_images(c->map_Lp, c->map_Lpinv) != 0)
        { fprintf(stderr, "OWFDBG: inv32_images Lp failed\n"); return -1; }

    /* 7.4 b) recombination (Frobenius iteration matrix)                */
    c->frob_row[0] = (1u << 0) | (1u << 4);
    c->frob_row[1] = (1u << 5) | (1u << 7);
    c->frob_row[2] = (1u << 1) | (1u << 4) | (1u << 5);
    c->frob_row[3] = (1u << 5) | (1u << 6) | (1u << 7);
    c->frob_row[4] = (1u << 2) | (1u << 4) | (1u << 5) | (1u << 6);
    c->frob_row[5] = (1u << 4) | (1u << 5) | (1u << 6);
    c->frob_row[6] = (1u << 3) | (1u << 4) | (1u << 6);
    c->frob_row[7] = (1u << 4) | (1u << 6);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Row packing of matrices (Clause 4.7)                                  */
/* ------------------------------------------------------------------ */
void
owf_row_to_field(const uint8_t *cols, uint64_t r, fe_t *out)
{
    unsigned cbit;
    /* bit c of the packed element = bit r of column c                   */
    fe_zero(out);
    for (cbit = 0; cbit < (unsigned)LAM; cbit++) {
        const uint8_t *col = cols + (size_t)cbit * HATLB;
        unsigned bit = (col[(size_t)(r >> 3)] >> (r & 7)) & 1u;
        out->b[cbit >> 3] |= (uint8_t)(bit << (cbit & 7));
    }
}

/* ------------------------------------------------------------------ */
/* B. Witness extension — Clause 8.1                                     */
/* ------------------------------------------------------------------ */

static uint8_t
affine_in_of_u(uint8_t u)
{
    unsigned r;
    /* x = A u + c (clause 7.1 a)                                        */
    uint8_t pr = 0;
    for (r = 0; r < 8; r++)
        pr |= (uint8_t)((__builtin_popcount((unsigned)(A_ROWS[r] & u)) & 1) << r);
    return (uint8_t)(pr ^ C_AFFINE);
}

void
owf_extend_witness(const owf_consts_t *consts,
                   const uint8_t k[16], const uint8_t in[16],
                   uint8_t w[SM4TH_ELL_BYTES])
{
    int i, j, t, a;
    uint32_t rk[36];
    uint32_t z[36];
    unsigned pN, pF;

    sm4_key_expansion(k, rk);

    memset(w, 0, SM4TH_ELL_BYTES);

    /* Table 5 row 1: kbar[0..4) = BE32 words of rk                       */
    for (i = 0; i < 4; i++) {
        w[4 * i + 0] = (uint8_t)(rk[i] >> 24);
        w[4 * i + 1] = (uint8_t)(rk[i] >> 16);
        w[4 * i + 2] = (uint8_t)(rk[i] >> 8);
        w[4 * i + 3] = (uint8_t)(rk[i]);
    }

    /* key-expansion nibbles and words (Ake = 4,8,...,32; U-19 packing)  */
    pN = 0;
    pF = 0;
    for (i = 4; i <= 35; i++) {
        if ((i & 3) == 0) {
            /* anchor: nibbles for the four bytes of u = kbar[i-3..i-1] ^ CK  */
            uint32_t u = rk[i - 3] ^ rk[i - 2] ^ rk[i - 1]
                        ^ sm4_ck_word((unsigned)i - 4);
            for (j = 0; j < 4; j++) {
                uint8_t ub = (uint8_t)(u >> (8 * (3 - j)));
                uint8_t xin = affine_in_of_u(ub);
                uint8_t nib = consts->invnorm_tab[xin];
                put_nib(w, 128 + 4 * pN, nib);
                pN++;
            }
        } else {
            unsigned octet = 32 + 4 * pF;
            w[octet + 0] = (uint8_t)(rk[i] >> 24);
            w[octet + 1] = (uint8_t)(rk[i] >> 16);
            w[octet + 2] = (uint8_t)(rk[i] >> 8);
            w[octet + 3] = (uint8_t)(rk[i]);
            pF++;
        }
    }
    if (pN != 32 || pF != 24)
        goto out; /* layout invariant */

    /* encryption state chain z                                         */
    {
        uint32_t sw = 0;
        for (t = 0; t < 4; t++)
            z[t] = ((uint32_t)in[4 * t] << 24)
                 | ((uint32_t)in[4 * t + 1] << 16)
                 | ((uint32_t)in[4 * t + 2] << 8)
                 | (uint32_t)in[4 * t + 3];
        for (t = 0; t < 32; t++) {
            uint32_t u = z[t + 1] ^ z[t + 2] ^ z[t + 3] ^ rk[t + 4];
            for (j = 0; j < 4; j++) {
                uint8_t ub = (uint8_t)(u >> (8 * (3 - j)));
                sw |= (uint32_t)sm4_sbox(ub) << (8 * (3 - j));
            }
            z[t + 4] = z[t]
                ^ sw ^ rotl32_c(sw, 2) ^ rotl32_c(sw, 10)
                ^ rotl32_c(sw, 18) ^ rotl32_c(sw, 24);
            sw = 0; /* reset accumulating variable per round              */
        }
    }

    /* encryption nibbles (Aenc = 5,9,...,29) and words                 */
    pN = 0;
    pF = 0;
    for (a = 4; a <= 31; a++) {
        if (((a - 1) & 3) == 0) {      /* a in Aenc: a == 1 (mod 4), a>=5 */
            uint32_t u = z[a - 3] ^ z[a - 2] ^ z[a - 1] ^ rk[a];
            for (j = 0; j < 4; j++) {
                uint8_t ub = (uint8_t)(u >> (8 * (3 - j)));
                uint8_t xin = affine_in_of_u(ub);
                uint8_t nib = consts->invnorm_tab[xin];
                put_nib(w, 1024 + 4 * pN, nib);
                pN++;
            }
        } else {
            unsigned octet = 142 + 4 * pF;
            w[octet + 0] = (uint8_t)(z[a] >> 24);
            w[octet + 1] = (uint8_t)(z[a] >> 16);
            w[octet + 2] = (uint8_t)(z[a] >> 8);
            w[octet + 3] = (uint8_t)(z[a]);
            pF++;
        }
    }
out:
    OPENSSL_cleanse(rk, sizeof(rk));
    OPENSSL_cleanse(z, sizeof(z));
}

/* ------------------------------------------------------------------ */
/* C. QuickSilver operations (Table 4)                                   */
/* ------------------------------------------------------------------ */

/* A commitment: prover polynomial c[0..deg] (deg+1 entries, c[deg] is
 * the committed value) or the verifier evaluation g; the mode of the
 * context selects the maintained side.                                   */
static qs_t
qs_zero(void)
{
    qs_t x;
    memset(&x, 0, sizeof(x));
    return x;
}

static qs_t
qs_const_bit(const owf_ctx_t *ctx, int b)
{
    qs_t x = qs_zero();
    x.deg = 1;
    if (ctx->mode == OWF_PROVER) {
        fe_zero(&x.c[0]);
        x.c[1].b[0] = (uint8_t)(b ? 1 : 0);
    } else {
        if (b)
            fe_set(&x.g, &ctx->delta);
    }
    return x;
}

static qs_t
qs_add(const owf_ctx_t *ctx, const qs_t *x, const qs_t *y)
{
    qs_t r = qs_zero();
    int Dm = (x->deg > y->deg) ? x->deg : y->deg;
    int i;

    r.deg = Dm;
    if (ctx->mode == OWF_PROVER) {
        for (i = 0; i <= Dm; i++) {
            fe_t a, b;
            fe_zero(&a);
            fe_zero(&b);
            if (i >= Dm - x->deg)
                fe_set(&a, &x->c[i - (Dm - x->deg)]);
            if (i >= Dm - y->deg)
                fe_set(&b, &y->c[i - (Dm - y->deg)]);
            fe_add(&r.c[i], &a, &b);
        }
    } else {
        fe_t a, b, dp;
        /* gamma_x * Delta^(D - deg_x) + gamma_y * Delta^(D - deg_y)     */
        fe_set(&a, &x->g);
        fe_set(&b, &y->g);
        dp.b[0] = 1;
        for (i = 0; i < Dm - x->deg; i++)
            gf_mul(&a, &a, &ctx->delta, LAM);   /* a = gamma_x * Delta^k */
        for (i = 0; i < Dm - y->deg; i++)
            gf_mul(&b, &b, &ctx->delta, LAM);
        (void)dp;
        fe_add(&r.g, &a, &b);
    }
    return r;
}

static qs_t
qs_scalar_mul(const owf_ctx_t *ctx, const qs_t *x, const fe_t *k)
{
    qs_t r = qs_zero();
    int i;

    r.deg = x->deg;
    if (ctx->mode == OWF_PROVER) {
        for (i = 0; i <= x->deg; i++)
            gf_mul(&r.c[i], &x->c[i], k, LAM);
    } else {
        gf_mul(&r.g, &x->g, k, LAM);
    }
    return r;
}

static qs_t
qs_mul(const owf_ctx_t *ctx, const qs_t *x, const qs_t *y)
{
    qs_t r = qs_zero();
    int i, j;

    r.deg = x->deg + y->deg;
    if (r.deg > DEG) {
        /* Protocol invariant: products exceeding degree 3 must not hap-
         * pen (spec 6.3 a); abort with a zero of degree -1 sentinel.    */
        r.deg = -1;
        return r;
    }
    if (ctx->mode == OWF_PROVER) {
        for (i = 0; i <= x->deg; i++)
            for (j = 0; j <= y->deg; j++) {
                fe_t t;
                gf_mul(&t, &x->c[i], &y->c[j], LAM);
                fe_xor(&r.c[i + j], &t);
            }
    } else {
        gf_mul(&r.g, &x->g, &y->g, LAM);
    }
    return r;
}

static qs_t
qs_lift(const owf_ctx_t *ctx, const qs_t *x, int target)
{
    qs_t r;
    int i;

    if (x->deg == target || x->deg < 0)
        return *x;
    r = qs_zero();
    r.deg = target;
    if (ctx->mode == OWF_PROVER) {
        for (i = 0; i <= x->deg; i++)
            fe_set(&r.c[i + (target - x->deg)], &x->c[i]);
    } else {
        fe_set(&r.g, &x->g);
        for (i = 0; i < target - x->deg; i++)
            gf_mul(&r.g, &r.g, &ctx->delta, LAM);
    }
    return r;
}

/* Append an entry: lift to degree d first (Clause 6.3 a — the S1
 * remedy), then record the coefficients / evaluation.                  */
static int
qs_append(owf_ctx_t *ctx, qs_t x)
{
    qs_t e;
    int j;

    if (x.deg < 0 || ctx->n_entries >= SM4TH_C_ENTRIES)
        return -1;
    e = qs_lift(ctx, &x, DEG);
    if (e.deg != DEG)
        return -1;
    if (ctx->mode == OWF_PROVER) {
        for (j = 0; j < DEG; j++)
            fe_set(&ctx->a[j][ctx->n_entries], &e.c[j]);
        /* Top coefficient e.c[DEG] is the committed value; must be 0. */
    } else {
        fe_set(&ctx->b[ctx->n_entries], &e.g);
    }
    ctx->n_entries++;
    return 0;
}

/* ---- 32-bit word composites: qw.b[k] = word bit at string position
 * p + k (Clause 4.6 c): byte j of the word occupies k = 8j..8j+8 with
 * bit t == integer bit 8(3-j)+t of the word value.                     */
typedef struct { qs_t b[32]; } qw_t;

static qw_t
qw_const_word(const owf_ctx_t *ctx, uint32_t word)
{
    int k;
    qw_t r = {0};
    for (k = 0; k < 32; k++) {
        int j = k >> 3, t = k & 7;
        int bit = (word >> (8 * (3 - j) + t)) & 1u;
        r.b[k] = qs_const_bit(ctx, bit);
    }
    return r;
}

static qw_t
qw_witness_word(const owf_ctx_t *ctx, unsigned bitbase)
{
    int k;
    qw_t r = {0};
    for (k = 0; k < 32; k++)
        r.b[k] = qs_witness_bit(ctx, bitbase + (unsigned)k);
    return r;
}

static qw_t
qw_add(const owf_ctx_t *ctx, const qw_t *x, const qw_t *y)
{
    int k;
    qw_t r = {0};
    for (k = 0; k < 32; k++)
        r.b[k] = qs_add(ctx, &x->b[k], &y->b[k]);
    return r;
}

static qw_t
qw_add_const(const owf_ctx_t *ctx, const qw_t *x, uint32_t word)
{
    int k;
    qw_t r = {0};
    for (k = 0; k < 32; k++) {
        int j = k >> 3, t = k & 7;
        int bit = (word >> (8 * (3 - j) + t)) & 1u;
        qs_t pub = qs_const_bit(ctx, bit);
        r.b[k] = qs_add(ctx, &x->b[k], &pub);
    }
    return r;
}

/* generic linear map: map[k] = image of basis vector e_k (column k).
 * out = A x with out_i = XOR_k A_{i k} x_k = XOR_k bit_i(map[k]) x_k.  */
static qw_t
qw_lin(const owf_ctx_t *ctx, const uint32_t map[32], const qw_t *x)
{
    int i, k;
    qw_t r = {0};
    for (i = 0; i < 32; i++)
        r.b[i] = qs_const_bit(ctx, 0);
    for (k = 0; k < 32; k++) {
        uint32_t m = map[k];
        for (i = 0; i < 32; i++) {
            if ((m >> (unsigned)i) & 1u)
                r.b[i] = qs_add(ctx, &r.b[i], &x->b[k]);
        }
    }
    return r;
}

/* Witness bit commitment (Clause 6.1 c)                                 */
static qs_t
qs_witness_bit(const owf_ctx_t *ctx, unsigned i)
{
    unsigned j;
    qs_t r = qs_zero();
    r.deg = 1;
    if (ctx->mode == OWF_PROVER) {
        fe_t col0;
        int bit = get_bit(ctx->w, i);
        owf_row_to_field(ctx->v_cols, i, &col0);
        fe_set(&r.c[0], &col0);
        fe_zero(&r.c[1]);
        r.c[1].b[0] = (uint8_t)bit;
    } else {
        fe_t row, dwterm;
        int bit = get_bit(ctx->dw, i);
        owf_row_to_field(ctx->q_cols, i, &row);
        fe_zero(&dwterm);
        for (j = 0; j < NF; j++)
            dwterm.b[j] = ctx->delta.b[j] & (uint8_t)(0u - (unsigned)bit);
        fe_add(&r.g, &row, &dwterm);
    }
    return r;
}

/* ByteCombine — Clause 7.2 b)                                            */
static qs_t
byte_combine(const owf_ctx_t *ctx, const qs_t *bits8)
{
    unsigned i;
    qs_t acc = qs_zero();
    int first = 1;
    for (i = 0; i < 8; i++)
        if (!fe_is_zero(&ctx->consts->alpha8[i]) || 1) {
            qs_t t = qs_scalar_mul(ctx, &bits8[i], &ctx->consts->alpha8[i]);
            if (first) { acc = t; first = 0; }
            else acc = qs_add(ctx, &acc, &t);
        }
    return acc;
}

/* SquareAndCombine — Clause 7.2 d): apply frob_row then ByteCombine      */
static qs_t
square_and_combine(const owf_ctx_t *ctx, const qs_t *bits8)
{
    unsigned t, k;
    const uint8_t *m = ctx->consts->frob_row;
    qs_t yb[8];
    for (t = 0; t < 8; t++) {
        qs_t acc = qs_zero();
        int first = 1;
        for (k = 0; k < 8; k++)
            if ((m[t] >> k) & 1u) {
                if (first) { acc = bits8[k]; first = 0; }
                else acc = qs_add(ctx, &acc, &bits8[k]);
            }
        yb[t] = acc;
    }
    return byte_combine(ctx, yb);
}

/* A u + c on 8 committed bits (7.1 a / 7.4 b first step)                 */
static void
byte_affine_in(const owf_ctx_t *ctx, const qs_t *u8, qs_t *x8)
{
    unsigned r, k;
    for (r = 0; r < 8; r++) {
        qs_t acc = qs_zero();
        int first = 1;
        for (k = 0; k < 8; k++)
            if ((A_ROWS[r] >> k) & 1u) {
                if (first) { acc = u8[k]; first = 0; }
                else acc = qs_add(ctx, &acc, &u8[k]);
            }
        /* + c_r                                                         */
        if ((C_AFFINE >> r) & 1u) {
            qs_t pub = qs_const_bit(ctx, 1);
            acc = qs_add(ctx, &acc, &pub);
        }
        x8[r] = acc;
    }
}

/* A^{-1}(v + c) on 8 committed bits (7.4 f) g)                            */
static void
byte_affine_out_inv(const owf_ctx_t *ctx, const qs_t *v8, qs_t *y8)
{
    unsigned r, k;
    qs_t w8[8];
    for (r = 0; r < 8; r++) {
        w8[r] = v8[r];
        if ((C_AFFINE >> r) & 1u) {
            qs_t pub = qs_const_bit(ctx, 1);
            w8[r] = qs_add(ctx, &w8[r], &pub);
        }
    }
    for (r = 0; r < 8; r++) {
        qs_t acc = qs_zero();
        int first = 1;
        for (k = 0; k < 8; k++)
            if ((AI_ROWS[r] >> k) & 1u) {
                if (first) { acc = w8[k]; first = 0; }
                else acc = qs_add(ctx, &acc, &w8[k]);
            }
        y8[r] = acc;
    }
}

/* AnchorWordM — Clause 7.4 h): consumes the four-byte word u and a
 * 16-bit string n of four nibbles (bits n[4j,4j+4) for byte j), appends
 * 4 entries, returns t = M(s).                                           */
static qw_t
anchor_word_m(owf_ctx_t *ctx, const qw_t *u, const qs_t nbits[16],
              const uint32_t map_M[32])
{
    int j, t, r, jj;
    unsigned bit, k, b;
    qw_t s;
    const owf_consts_t *K = ctx->consts;

    for (j = 0; j < 4; j++) {
        qs_t a_r[8];
        qs_t xcomb[8];       /* x^{2^r} elements                          */
        qs_t hcomb[4];       /* h^{2^r}                                   */
        const qs_t *nib4 = nbits + 4 * j; /* InvNorm bits of byte j       */

        /* affine input a^{(0)} from the j-th byte of u                    */
        byte_affine_in(ctx, &u->b[8 * j], a_r);

        /* x^{2^r} = ByteCombine(a^{(r)});  a^{(r+1)} via frob_row (7.4 b) */
        {
            qs_t a_cur[8];
            for (t = 0; t < 8; t++)
                a_cur[t] = a_r[t];    /* a^{(0)}                        */
            for (r = 0; r < 8; r++) {
                qs_t a_next[8];

                xcomb[r] = byte_combine(ctx, a_cur);
                for (bit = 0; bit < 8; bit++) {
                    qs_t acc = qs_zero();
                    int first = 1;
                    for (k = 0; k < 8; k++)
                        if ((K->frob_row[bit] >> k) & 1u) {
                            if (first) { acc = a_cur[k]; first = 0; }
                            else acc = qs_add(ctx, &acc, &a_cur[k]);
                        }
                    a_next[bit] = acc;
                }
                for (t = 0; t < 8; t++)
                    a_cur[t] = a_next[t];
            }
        }

        /* h^{2^r} = sum_t bhat[r][t] * n_t — InvNormToConjugates (7.4 c) */
        for (r = 0; r < 4; r++) {
            qs_t acc = qs_zero();
            int first = 1;
            for (t = 0; t < 4; t++) {
                qs_t term;

                if (fe_is_zero(&K->bhat[r][t]))
                    continue;
                term = qs_scalar_mul(ctx, &nib4[t], &K->bhat[r][t]);
                if (first) { acc = term; first = 0; }
                else acc = qs_add(ctx, &acc, &term);
            }
            hcomb[r] = acc;
        }

        /* entries: h·x^{16}·x^{2} + x                                    */
        {
            qs_t p1 = qs_mul(ctx, &hcomb[0], &xcomb[4]);   /* h * x^{16}*/
            qs_t p2 = qs_mul(ctx, &p1, &xcomb[1]);         /* * x^{2}   */
            qs_t e = qs_add(ctx, &p2, &xcomb[0]);
            qs_append(ctx, e);
        }

        /* q^{2^r} = x^{2^{(r+4) mod 8}} * h^{2^{r mod 4}}                 */
        {
            qs_t qcomb[8], scomb[8];
            for (r = 0; r < 8; r++) {
                qs_t p = qs_mul(ctx, &xcomb[(r + 4) & 7], &hcomb[r & 3]);
                qcomb[r] = p;
            }
            /* s^{2^r} = sum_j â_j^{2^r} * q^{2^{(j+r) mod 8}} + ĉ^{2^r}
             * (7.4 d).  â_j^{2^r} lives in a_hat_f[r][j]; a_hat[r] for
             * r>0 was never filled (only a_hat[0] is solved).            */
            for (r = 0; r < 8; r++) {
                qs_t acc = qs_zero();
                int first = 1;
                qs_t cc;

                for (jj = 0; jj < 8; jj++) {
                    qs_t term;

                    if (fe_is_zero(&K->a_hat_f[r][jj]))
                        continue;
                    term = qs_scalar_mul(ctx, &qcomb[(jj + r) & 7],
                                         &K->a_hat_f[r][jj]);
                    if (first) { acc = term; first = 0; }
                    else acc = qs_add(ctx, &acc, &term);
                }
                cc = qs_const_bit(ctx, 0);
                /* sum + c_hat^{2^r}: the constant term enters as a
                 * field-element constant (CoefficientToVOLE extended);
                 * per Table 4 this is c·<0> ... Spec's AffineOut adds
                 * c-hat as a public field constant: model it as a
                 * degree-1 commitment of the public constant c-hat.     */
                {
                    qs_t pub;
                    pub = qs_zero();
                    pub.deg = 1;
                    if (ctx->mode == OWF_PROVER) {
                        fe_zero(&pub.c[0]);
                        /* committed value c-hat in coefficient 1          */
                        fe_set(&pub.c[1], &K->c_hat_f[r]);
                    } else {
                        gf_mul(&pub.g, &ctx->delta, &K->c_hat_f[r], LAM);
                    }
                    acc = qs_add(ctx, &acc, &pub);
                }
                (void)cc;
                scomb[r] = acc;
            }
            /* s_b = sum_r theta[b][r] * s^{2^r}                          */
            for (b = 0; b < 8; b++) {
                qs_t acc = qs_zero();
                int first = 1;
                for (r = 0; r < 8; r++) {
                    qs_t term;

                    if (fe_is_zero(&K->theta[b][r]))
                        continue;
                    term = qs_scalar_mul(ctx, &scomb[r], &K->theta[b][r]);
                    if (first) { acc = term; first = 0; }
                    else acc = qs_add(ctx, &acc, &term);
                }
                s.b[8 * j + b] = acc;
            }
        }
    }
    /* t = M(s)                                                            */
    return qw_lin(ctx, map_M, &s);
}

/* The two entries of a non-anchor word — 9.1 c)3) / 9.2 c)3):
 *   Lift( x^2 * y + x ),  Lift( x * y^2 + y )
 * where x = Au+c from the u-word byte and y = A^{-1}(v+c) from v.       */
static int
append_quadratic(owf_ctx_t *ctx, const qw_t *u, const qw_t *v, int j)
{
    qs_t x8[8], y8[8], xe, xsq, ye, ysq;

    byte_affine_in(ctx, &u->b[8 * j], x8);
    xe = byte_combine(ctx, x8);
    xsq = square_and_combine(ctx, x8);

    byte_affine_out_inv(ctx, &v->b[8 * j], y8);
    ye = byte_combine(ctx, y8);
    ysq = square_and_combine(ctx, y8);


    {
        qs_t p1 = qs_mul(ctx, &xsq, &ye);
        qs_t e1 = qs_add(ctx, &p1, &xe);
        if (qs_append(ctx, e1) != 0)
            return -1;
    }
    {
        qs_t p2 = qs_mul(ctx, &xe, &ysq);
        qs_t e2 = qs_add(ctx, &p2, &ye);
        if (qs_append(ctx, e2) != 0)
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 9.4 OWFConstraints — the constraint driver                            */
/* ------------------------------------------------------------------ */
int
owf_constraints(owf_ctx_t *ctx, const uint8_t pk1[16], const uint8_t pk2[16])
{
    int t, j, i2;
    const owf_consts_t *K = ctx->consts;
    qw_t kbar[36];
    qw_t z[36];
    unsigned pN, pF;
    int i, rc = -1;

    ctx->n_entries = 0;

    /* entry 0: keyspace — Lift(w[0] * w[1]) (9.4 a) with the S1 lift    */
    {
        qs_t w0 = qs_witness_bit(ctx, 0);
        qs_t w1 = qs_witness_bit(ctx, 1);
        qs_t p = qs_mul(ctx, &w0, &w1);
        if (qs_append(ctx, p) != 0)
            goto out;
    }

    /* ---- 9.1 KeyExpCstrnts ----                                        */
    for (i = 0; i < 4; i++)
        kbar[i] = qw_witness_word(ctx, (unsigned)(32 * i));

    pN = 0;
    pF = 0;
    for (i = 4; i <= 35; i++) {
        qw_t u = kbar[i - 3];
        qw_t u2;
        uint32_t ckw = sm4_ck_word((unsigned)(i - 4));

        u2 = qw_add(ctx, &u, &kbar[i - 2]);
        u2 = qw_add(ctx, &u2, &kbar[i - 1]);
        u2 = qw_add_const(ctx, &u2, ckw);

        if ((i & 3) == 0) {
            /* anchor — clause 9.1 c)2): wke,N[16pN, 16pN+16)            */
            qs_t nbits[16];
            for (t = 0; t < 16; t++)
                nbits[t] = qs_witness_bit(ctx, 128u + 16u * pN + (unsigned)t);
            {
                qw_t tword = anchor_word_m(ctx, &u2, nbits, K->map_Lp);
                kbar[i] = qw_add(ctx, &kbar[i - 4], &tword);
            }
            pN++;
        } else {
            /* non-anchor full word — 9.1 c)3)                            */
            kbar[i] = qw_witness_word(ctx, 256u + 32u * pF);
            pF++;
            {
                qw_t summed = qw_add(ctx, &kbar[i - 4], &kbar[i]);
                qw_t v = qw_lin(ctx, K->map_Lpinv, &summed);
                for (j = 0; j < 4; j++)
                    if (append_quadratic(ctx, &u2, &v, j) != 0)
                        goto out;
            }
        }
    }
    if (ctx->n_entries != 225u)   /* 1 + 32 + 192                        */
        goto out;

    /* ---- 9.2 EncCstrnts ----                                          */
    for (t = 0; t < 4; t++) {
        uint32_t wv = ((uint32_t)pk1[4 * t] << 24)
                    | ((uint32_t)pk1[4 * t + 1] << 16)
                    | ((uint32_t)pk1[4 * t + 2] << 8)
                    | pk1[4 * t + 3];
        z[t] = qw_const_word(ctx, wv);
        /* out (pk2) loaded reversed: z[32+i] = out[3-i] (I-16)           */
        wv = ((uint32_t)pk2[4 * (3 - t)] << 24)
           | ((uint32_t)pk2[4 * (3 - t) + 1] << 16)
           | ((uint32_t)pk2[4 * (3 - t) + 2] << 8)
           | pk2[4 * (3 - t) + 3];
        z[32 + t] = qw_const_word(ctx, wv);
    }

    pN = 0;
    pF = 0;
    for (i2 = 0; i2 <= 31; i2++) {
        int a = i2 + 4;
        qw_t u = z[i2 + 1];
        qw_t u2;

        u2 = qw_add(ctx, &u, &z[i2 + 2]);
        u2 = qw_add(ctx, &u2, &z[i2 + 3]);
        u2 = qw_add(ctx, &u2, &kbar[a]);

        if (a <= 29 && ((a - 1) & 3) == 0) {
            /* anchor — clause 9.2 c)2); Aenc = {5,9,...,29};
             * wenc,N[16pN, 16pN+16) at bit offset 1024.                 */
            qs_t nbits[16];
            for (t = 0; t < 16; t++)
                nbits[t] = qs_witness_bit(ctx, 1024u + 16u * pN + (unsigned)t);
            {
                qw_t tword = anchor_word_m(ctx, &u2, nbits, K->map_L);
                z[a] = qw_add(ctx, &z[i2], &tword);
            }
            pN++;
        } else {
            if (a < 32) {
                z[a] = qw_witness_word(ctx, 1136u + 32u * pF);
                pF++;
            }
            {
                qw_t summed = qw_add(ctx, &z[i2], &z[a]);
                qw_t v = qw_lin(ctx, K->map_Linv, &summed);
                for (j = 0; j < 4; j++)
                    if (append_quadratic(ctx, &u2, &v, j) != 0)
                        goto out;
            }
        }
    }
    if (ctx->n_entries != SM4TH_C_ENTRIES)
        goto out;
    rc = 0;
out:
    OPENSSL_cleanse(kbar, sizeof(kbar));
    OPENSSL_cleanse(z, sizeof(z));
    return rc;
}
