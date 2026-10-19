/*
 * bavc.c — GGM tree, BAVC and ConvertToVOLE of SM4th_spec.pdf Clause 5.5.
 *
 * Layout review (against the reference behaviour recorded in Annex C):
 *   - BAVC.Open emits co-path seeds with node indices descending
 *     (L-2 down to 0), matching corrective entry D-3;             (v4)
 *   - BAVC.Reconstruct rejects R-B1 (too few seeds) and R-B2
 *     (nonzero unused tail) explicitly;                            (5.5.4)
 *   - DecodeChall reads the challenge LSB-first (U-7) and checks the
 *     grinding bits itself (5.5.6 a)).
 */
#include "bavc.h"
#include "sm4th_hash.h"

#include <stdio.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

#define NB        SM4TH_NB
#define NIV       SM4TH_NIV
#define HATLB     (SM4TH_ELL / 8 + 3 * SM4TH_LAMBDA_F / 8 + SM4TH_B / 8) /* 276 */
#define LAMCOLS   SM4TH_LAMBDA_F   /* 128 VOLE columns                   */

/* ------------------------------------------------------------------ */
int
bavc_init(bavc_t *t, const sm4th_params_t *p)
{
    t->p = p;
    /* Indexed by GGM node id α ∈ [0, 2L-2]; leaves live at α ∈ [L-1, 2L-2]
     * (PosInTree).  Sizing to L entries alone overflowed Open/Commit.   */
    t->node_seeds = (uint8_t *)OPENSSL_malloc((size_t)(2 * p->leaves - 1) * NB);
    t->leaf_coms = (uint8_t *)OPENSSL_malloc((size_t)(2 * p->leaves - 1) * 2 * NB);
    if (!t->node_seeds || !t->leaf_coms) {
        bavc_free(t);
        return -1;
    }
    return 0;
}

void
bavc_free(bavc_t *t)
{
    OPENSSL_clear_free(t->node_seeds, (size_t)(2 * t->p->leaves - 1) * NB);
    OPENSSL_clear_free(t->leaf_coms, (size_t)(2 * t->p->leaves - 1) * 2 * NB);
    t->node_seeds = NULL;
    t->leaf_coms = NULL;
}

/* H1 = SHAKE128(· || 0x01) squeezed to 2*NB = 32 octets.             */
static int
h1_absorb_final(EVP_MD_CTX *s, uint8_t *out /*32*/)
{
    static const uint8_t ds = 0x01;

    return (EVP_DigestUpdate(s, &ds, 1) == 1
            && EVP_DigestSqueeze(s, out, 2 * NB) == 1) ? 0 : -1;
}

static EVP_MD_CTX *
h1_stream_new(const EVP_MD *md)
{
    EVP_MD_CTX *s = EVP_MD_CTX_new();

    if (s == NULL)
        return NULL;
    if (EVP_DigestInit_ex2(s, md, NULL) != 1) {
        EVP_MD_CTX_free(s);
        return NULL;
    }
    return s;
}

/* ------------------------------------------------------------------ */
/* 5.5.2 BAVC.Commit                                                    */
int
bavc_commit(bavc_t *t, const EVP_MD *shake128_md,
            const uint8_t r[NB], const uint8_t iv[NIV],
            uint8_t *com_out)
{
    uint64_t j;
    const sm4th_params_t *p = t->p;
    uint64_t total_nodes = 2 * (uint64_t)p->leaves - 1;
    uint8_t y[2 * NB];
    uint8_t *hi = (uint8_t *)OPENSSL_malloc((size_t)p->tau * 2 * NB);
    uint64_t alpha;
    unsigned i;

    if (!hi)
        return -1;

    memcpy(t->node_seeds, r, NB);

    /* b) internal nodes: alpha = 0..L-2 in this order                 */
    for (alpha = 0; alpha < (uint64_t)p->leaves - 1; alpha++) {
        sm4th_prg(t->node_seeds + alpha * NB, iv, alpha, y, 2 * NB);
        memcpy(t->node_seeds + (2 * alpha + 1) * NB, y, NB);
        memcpy(t->node_seeds + (2 * alpha + 2) * NB, y + NB, NB);
        OPENSSL_cleanse(y, sizeof(y));
    }

    /* c) leaf seeds and leaf commitments                              */
    for (i = 0; i < p->tau; i++) {
        for (j = 0; j < p->ni[i]; j++) {
            uint64_t a = sm4th_pos_in_tree(p, i, j);
            /* commitment of leaf (i,j): PRG(k_a, iv, i+L-1; 2nb)     */
            sm4th_prg(t->node_seeds + a * NB, iv,
                      (uint64_t)i + p->leaves - 1, y, 2 * NB);
            memcpy(t->leaf_coms + a * 2 * NB, y, 2 * NB);
        }
    }

    /* d) + e): per-repetition h_i, then root com                     */
    for (i = 0; i < p->tau; i++) {
        EVP_MD_CTX *s = h1_stream_new(shake128_md);

        if (!s) { OPENSSL_free(hi); return -1; }
        for (j = 0; j < p->ni[i]; j++)
            if (EVP_DigestUpdate(s, t->leaf_coms
                              + sm4th_pos_in_tree(p, i, j) * 2 * NB,
                              2 * NB) != 1) {
                EVP_MD_CTX_free(s);
                OPENSSL_free(hi);
                return -1;
            }
        if (h1_absorb_final(s, hi + i * 2 * NB) != 0) {
            EVP_MD_CTX_free(s);
            OPENSSL_free(hi);
            return -1;
        }
        EVP_MD_CTX_free(s);
    }
    {
        EVP_MD_CTX *s = h1_stream_new(shake128_md);

        if (!s) { OPENSSL_free(hi); return -1; }
        for (i = 0; i < p->tau; i++)
            if (EVP_DigestUpdate(s, hi + i * 2 * NB, 2 * NB) != 1) {
                EVP_MD_CTX_free(s);
                OPENSSL_free(hi);
                return -1;
            }
        if (h1_absorb_final(s, com_out) != 0) {
            EVP_MD_CTX_free(s);
            OPENSSL_free(hi);
            return -1;
        }
        EVP_MD_CTX_free(s);
    }
    OPENSSL_free(hi);
    (void)total_nodes;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 5.5.3 BAVC.Open                                                      */
int
bavc_open(bavc_t *t, const unsigned delta[SM4TH_MAX_TAU], uint8_t *decomI)
{
    uint64_t alpha;
    const sm4th_params_t *p = t->p;
    unsigned char *S;
    uint64_t nh = 0;
    size_t w = 0;
    uint64_t total_nodes = 2 * (uint64_t)p->leaves - 1;
    unsigned tau = p->tau;
    unsigned i;

    S = (unsigned char *)OPENSSL_zalloc((size_t)total_nodes);
    if (!S)
        return -2;

    /* a) hidden-leaf commitments first                                */
    for (i = 0; i < tau; i++) {
        uint64_t a = sm4th_pos_in_tree(p, i, delta[i]);
        if (a >= total_nodes || delta[i] >= p->ni[i]) {
            OPENSSL_free(S);
            return -2;
        }
        memcpy(decomI + (size_t)2 * NB * i,
               t->leaf_coms + a * 2 * NB, 2 * NB);
    }

    /* b) mark the union of paths and count the nodes                  */
    for (i = 0; i < tau; i++) {
        uint64_t a = sm4th_pos_in_tree(p, i, delta[i]);
        S[a] = 1;
        nh++;
        while (a > 0 && S[(a - 1) / 2] == 0) {
            a = (a - 1) / 2;
            S[a] = 1;
            nh++;
        }
    }

    /* c)+d) emit co-path; size check uses the actual emission count
     * (equivalent to nh-2τ+1 when the path mark is correct).          */
    {
        uint8_t *nodes = decomI + (size_t)2 * NB * tau;
        for (alpha = (uint64_t)p->leaves - 1;
             alpha > 0; alpha--) {
            uint64_t a = alpha - 1;
            if ((unsigned)(S[2 * a + 1] ^ S[2 * a + 2]) == 1u) {
                if (w >= (size_t)p->topen) {
                    OPENSSL_free(S);
                    return -1;
                }
                memcpy(nodes + (size_t)NB * w,
                       t->node_seeds + (2 * a + 1 + S[2 * a + 1]) * NB,
                       NB);
                w++;
            }
        }
    }
    if ((int64_t)nh - 2 * (int64_t)tau + 1 != (int64_t)w) {
        /* An internal failure must not trigger another counter attempt. */
        OPENSSL_free(S);
        return -2;
    }
    /* e) zero padding                                                  */
    memset(decomI + (size_t)2 * NB * tau + NB * w, 0,
           (size_t)p->ldecom - 2 * NB * tau - NB * w);
    OPENSSL_free(S);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 5.5.4 BAVC.Reconstruct                                               */
int
bavc_reconstruct(bavc_t *t, const EVP_MD *shake128_md,
                 const uint8_t *decomI,
                 const unsigned delta[SM4TH_MAX_TAU],
                 const uint8_t iv[NIV], uint8_t *com_out)
{
    uint64_t alpha, node, j;
    size_t k;
    const sm4th_params_t *p = t->p;
    unsigned tau = p->tau;
    uint64_t total_nodes = 2 * (uint64_t)p->leaves - 1;
    const uint8_t *nodes = decomI + (size_t)2 * NB * tau;
    size_t nnode_bytes = (size_t)NB * p->topen;
    unsigned char *S;
    uint8_t *hi;
    size_t wpos = 0;
    unsigned i;
    int rc = -1;

    S = (unsigned char *)OPENSSL_zalloc((size_t)total_nodes);
    hi = (uint8_t *)OPENSSL_malloc((size_t)tau * 2 * NB);
    if (!S || !hi)
        goto out;

    /* b) mark hidden leaves                                            */
    for (i = 0; i < tau; i++)
        S[sm4th_pos_in_tree(p, i, delta[i])] = 1;

    /* c) walk nodes descending: mark parents and take the co-path
     * seeds in the same order BAVC.Open emitted them (D-3)            */
    {
        for (alpha = (uint64_t)p->leaves - 1;
             alpha > 0; alpha--) {
            uint64_t a = alpha - 1;
            uint64_t left = 2 * a + 1;
            S[a] = (unsigned char)(S[left] | S[left + 1]);
            if ((unsigned)(S[left] ^ S[left + 1]) == 1u) {
                if (wpos == (size_t)p->topen) {     /* R-B1 */

                    goto out;
                }
                memcpy(t->node_seeds + (left + S[left]) * NB,
                       nodes + NB * wpos, NB);
                wpos++;
            }
        }
    }

    /* d) R-B2: the unused tail must be zero                           */
    for (k = (size_t)NB * wpos; k < nnode_bytes; k++) {
        if (nodes[k] != 0) {
            goto out;
        }
    }

    /* e) expand every unmarked internal node top-down                 */
    {
        uint8_t y[2 * NB];
        for (node = 0; node < (uint64_t)p->leaves - 1; node++) {
            if (!S[node]) {
                sm4th_prg(t->node_seeds + node * NB, iv, node, y, 2 * NB);
                memcpy(t->node_seeds + (2 * node + 1) * NB, y, NB);
                memcpy(t->node_seeds + (2 * node + 2) * NB, y + NB, NB);
                OPENSSL_cleanse(y, sizeof(y));
            }
        }
    }

    /* f) leaf commitments: hidden ones from decomI, others recomputed;
     * per-repetition H1, then root H1                                 */
    for (i = 0; i < tau; i++) {
        EVP_MD_CTX *s = h1_stream_new(shake128_md);
        const uint8_t *comprime_i = decomI + (size_t)2 * NB * i;

        if (!s)
            goto out;
        for (j = 0; j < p->ni[i]; j++) {
            uint64_t a = sm4th_pos_in_tree(p, i, j);

            if (S[a]) {
                if (EVP_DigestUpdate(s, comprime_i, 2 * NB) != 1) {
                    EVP_MD_CTX_free(s);
                    goto out;
                }
            } else {
                uint8_t h[2 * NB];

                sm4th_prg(t->node_seeds + a * NB, iv,
                          (uint64_t)i + p->leaves - 1, h, 2 * NB);
                if (EVP_DigestUpdate(s, h, 2 * NB) != 1) {
                    EVP_MD_CTX_free(s);
                    goto out;
                }
            }
        }
        if (h1_absorb_final(s, hi + (size_t)i * 2 * NB) != 0) {
            EVP_MD_CTX_free(s);
            goto out;
        }
        EVP_MD_CTX_free(s);
    }
    {
        EVP_MD_CTX *s = h1_stream_new(shake128_md);

        if (!s)
            goto out;
        for (i = 0; i < tau; i++)
            if (EVP_DigestUpdate(s, hi + (size_t)i * 2 * NB, 2 * NB) != 1) {
                EVP_MD_CTX_free(s);
                goto out;
            }
        if (h1_absorb_final(s, com_out) != 0) {
            EVP_MD_CTX_free(s);
            goto out;
        }
        EVP_MD_CTX_free(s);
    }
    rc = 0;

out:
    OPENSSL_free(S);
    OPENSSL_free(hi);
    return rc;
}
/* ------------------------------------------------------------------ */
/* 5.5.5 ConvertToVOLE                                                  */
void
convert_to_vole(const uint8_t *const sd[], unsigned d,
                const uint8_t iv[NIV], uint64_t tweak,
                uint8_t *u, uint8_t **v,
                uint8_t *y_scratch, unsigned N)
{
    unsigned j, b, k;
    /* y_j := 0^{hat_ell} if sd_j = ⊥ else PRG(sd_j, iv, twk; hat_ell) */
    for (j = 0; j < N; j++) {
        uint8_t *yj = y_scratch + (size_t)j * HATLB;
        if (sd[j])
            sm4th_prg(sd[j], iv, tweak, yj, HATLB);
        else
            memset(yj, 0, HATLB);
    }

    /* b = 0..d-1: fold y in place, accumulate v_b = XOR of odd slots.
     * Spec 5.5.5 / lo_spec: v_b ⊕= y_{2j+1}; y_j ← y_{2j} ⊕ y_{2j+1}.
     * (Earlier code wrote the XOR back into slot 2j, breaking SoftSpoken.) */
    for (b = 0; b < d; b++) {
        unsigned half = N >> (b + 1);
        uint8_t *vb = v[b];
        memset(vb, 0, HATLB);
        for (j = 0; j < half; j++) {
            uint8_t *yj = y_scratch + (size_t)j * HATLB;
            uint8_t *y2j = y_scratch + (size_t)(2 * j) * HATLB;
            uint8_t *y2j1 = y_scratch + (size_t)(2 * j + 1) * HATLB;
            for (k = 0; k < HATLB; k++)
                vb[k] ^= y2j1[k];
            /* Compact into slot j.  For j=0, yj==y2j so this is ^= .
             * For j>=1, destination j is strictly below 2j, still unread. */
            for (k = 0; k < HATLB; k++)
                yj[k] = (uint8_t)(y2j[k] ^ y2j1[k]);
        }
    }
    memcpy(u, y_scratch, HATLB);   /* u = y_0 after d folds            */
}

/* ------------------------------------------------------------------ */
/* 5.5.6 DecodeChall                                                    */
int
decode_chall(const sm4th_params_t *p, const uint8_t *chall3,
             unsigned delta[SM4TH_MAX_TAU])
{
    unsigned b, i;
    /* a) grinding bits must be zero (bits lambdaF-wgrind .. lambdaF-1
     * of the LSB-first bit string)                                    */
    for (b = SM4TH_LAMBDA_F - p->wgrind; b < (unsigned)SM4TH_LAMBDA_F; b++)
        if ((chall3[b >> 3] >> (b & 7)) & 1u)
            return -1;

    for (i = 0; i < p->tau; i++) {
        unsigned val = 0;
        for (b = 0; b < p->ki[i]; b++) {
            unsigned bitpos = p->oi[i] + b;
            val |= (unsigned)((chall3[bitpos >> 3] >> (bitpos & 7)) & 1u) << b;
        }
        delta[i] = val;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 5.5.7 VOLECommit                                                     */
int
vole_commit(const sm4th_params_t *p, const EVP_MD *shake128_md,
            const uint8_t r[NB],
            const uint8_t iv[NIV], uint8_t *com_out,
            uint8_t **c, uint8_t *u, uint8_t *v_cols,
            bavc_t *tree, uint8_t *vole_scratch)
{
    unsigned b, j, k, col;
    uint8_t *u_i;
    uint8_t **v_bufs;
    const uint8_t **sd;
    unsigned i;
    int rc = -1;

    if (bavc_commit(tree, shake128_md, r, iv, com_out) != 0)
        return -1;

    u_i = (uint8_t *)OPENSSL_malloc(HATLB);
    v_bufs = (uint8_t **)OPENSSL_malloc(sizeof(uint8_t *) * 12);
    sd = (const uint8_t **)OPENSSL_malloc(sizeof(uint8_t *) * (1u << 12));
    if (!u_i || !v_bufs || !sd)
        goto out;

    for (i = 0; i < p->tau; i++) {
        unsigned N = p->ni[i], d = p->ki[i];
        for (b = 0; b < 12; b++)
            v_bufs[b] = vole_scratch + (size_t)N * HATLB
                       + (size_t)b * HATLB;
        for (j = 0; j < N; j++)
            sd[j] = tree->node_seeds
                     + sm4th_pos_in_tree(p, i, j) * NB;
        if (i == 0) {
            convert_to_vole(sd, d, iv, (uint64_t)i + 0x80000000ull,
                            u, v_bufs, vole_scratch, N);
        } else {
            convert_to_vole(sd, d, iv, (uint64_t)i + 0x80000000ull,
                            u_i, v_bufs, vole_scratch, N);
            /* c_i = u ^ u_i                                            */
            for (k = 0; k < HATLB; k++)
                c[i][k] = (uint8_t)(u[k] ^ u_i[k]);
        }
        /* V[oi+b] = v_{i,b}                                            */
        for (b = 0; b < d; b++)
            memcpy(v_cols + (size_t)(p->oi[i] + b) * HATLB,
                   v_bufs[b], HATLB);
    }
    /* zero columns for the grinding range                             */
    for (col = SM4TH_LAMBDA_F - p->wgrind; col < (unsigned)SM4TH_LAMBDA_F;
         col++)
        memset(v_cols + (size_t)col * HATLB, 0, HATLB);

    rc = 0;
out:
    OPENSSL_clear_free(u_i, HATLB);
    OPENSSL_free(v_bufs);
    OPENSSL_free((void *)sd);
    return rc;
}

/* ------------------------------------------------------------------ */
/* 5.5.8 VOLEReconstruct                                                */
int
vole_reconstruct(const sm4th_params_t *p, const EVP_MD *shake128_md,
                 const uint8_t *chall3,
                 const uint8_t *decomI, uint8_t **c,
                 const uint8_t iv[NIV], uint8_t *com_out,
                 uint8_t *q_cols, bavc_t *tree, uint8_t *vole_scratch)
{
    unsigned j, k, col;
    unsigned delta[SM4TH_MAX_TAU];
    uint8_t *u_i;
    uint8_t **v_bufs;
    const uint8_t **sd;
    unsigned i, b;
    int rc = -1;

    /* a) DecodeChall (the grinding bits were also checked upstream)   */
    if (decode_chall(p, chall3, delta) != 0)
        return -1;

    /* b) BAVC.Reconstruct: com and all non-hidden seeds               */
    if (bavc_reconstruct(tree, shake128_md, decomI, delta, iv, com_out) != 0) {
        return -1;
    }

    u_i = (uint8_t *)OPENSSL_malloc(HATLB);
    v_bufs = (uint8_t **)OPENSSL_malloc(sizeof(uint8_t *) * 12);
    sd = (const uint8_t **)OPENSSL_malloc(sizeof(uint8_t *) * (1u << 12));
    if (!u_i || !v_bufs || !sd)
        goto out;

    /* c) per repetition build the XOR-shifted seed list and fold      */
    for (i = 0; i < p->tau; i++) {
        unsigned N = p->ni[i], d = p->ki[i];
        unsigned di = delta[i];

        for (j = 0; j < N; j++)
            sd[j] = (j == 0) ? NULL
                : tree->node_seeds + sm4th_pos_in_tree(
                    p, i, j ^ di) * NB;

        for (b = 0; b < 12; b++)
            v_bufs[b] = vole_scratch + (size_t)N * HATLB
                       + (size_t)b * HATLB;

        /* the reconstructed u'_i itself is not needed by Verify     */
        convert_to_vole(sd, d, iv, (uint64_t)i + 0x80000000ull,
                        u_i, v_bufs, vole_scratch, N);

        /* Q[oi+b] = q_{i,b} xor (c_i if i>=1 and delta_{i,b} = 1)      */
        for (b = 0; b < d; b++) {
            uint8_t *dst = q_cols + (size_t)(p->oi[i] + b) * HATLB;
            memcpy(dst, v_bufs[b], HATLB);
            if (i >= 1 && ((di >> b) & 1u)) {
                for (k = 0; k < HATLB; k++)
                    dst[k] ^= c[i][k];
            }
        }
    }
    /* d) zero grinding columns                                         */
    for (col = SM4TH_LAMBDA_F - p->wgrind; col < (unsigned)SM4TH_LAMBDA_F;
         col++)
        memset(q_cols + (size_t)col * HATLB, 0, HATLB);

    rc = 0;
out:
    OPENSSL_clear_free(u_i, HATLB);
    OPENSSL_free(v_bufs);
    OPENSSL_free((void *)sd);
    return rc;
}
