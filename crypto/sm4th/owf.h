/*
 * owf.h — the non-EM witness extension (Clause 8.1) and the constraint
 * system (Clauses 6-9, 9.1/9.2/9.4 d=3) of SM4th_spec.pdf.
 *
 * The constraint driver runs in two modes producing the same sequence of
 * entries:
 *   PROVER   : maintains signer-side polynomials c[0..deg] (deg <= 3),
 *              collects a_j (X^j coefficients per entry) for ZKHash;
 *   VERIFIER : maintains evaluations gamma, collects b per entry.
 *
 * The S1 repair (Clause 6.3 a): every entry is lifted to degree d = 3
 * before it is appended.  The keyspace entry is the only place where a
 * raw degree-2 product occurs (Clause 9.4 a), followed by the 224 and
 * 228 entries of KeyExpCstrnts/EncCstrnts.
 */
#ifndef SM4TH_OWF_H
#define SM4TH_OWF_H

#include "fields.h"
#include "sm4th_params.h"
#include "blockcipher.h"

#include <stdint.h>

enum { OWF_PROVER = 0, OWF_VERIFIER = 1 };

/* Constants derived once per process (7.2/7.4):
 *   alpha8 : Emb(1) = 1, alpha8[i] = alpha_8^i as F_2^128 elements
 *   emb_mat[j][i] : Emb(e_k) coefficients — the Moore-matrix rows
 *   a_hat[j][r] : a-hat constants of AffineOut (7.2 f), r = 2^r row
 *   theta[b][r] : coefficients of ConjToBits (7.2 g)
 *   c_hat      : c-hat constant (7.2 f)
 *   bhat[r][t] : b-hat_{t}^{2^r} of InvNormToConjugates (7.4 c)
 */
typedef struct {
    fe_t alpha8[8];       /* alpha_8^i (Emb(e_i)); [0] = 1            */
    fe_t alpha_g;          /* alpha_8 itself (Table 22 constant)       */
    fe_t a_hat[8][8];      /* [r][j] = a-hat_j^{2^r}                     */
    fe_t theta[8][8];      /* [b][r] = theta_{b,r}                       */
    fe_t c_hat;
    fe_t c_hat_f[8];       /* c-hat^{2^r}                               */
    fe_t a_hat_f[8][8];    /* same as a_hat (kept for the header spec)   */
    fe_t bhat[4][4];       /* [r][t] = b-hat_t^{2^r}                     */
    uint8_t invnorm_tab[256];   /* InvNorm of 7.4 a)                    */
    uint32_t map_L[32];        /* L as basis images                     */
    uint32_t map_Lp[32];       /* L'                                    */
    uint32_t map_Linv[32];     /* L^{-1} (7.1 d rotation set, verified) */
    uint32_t map_Lpinv[32];    /* L'^{-1}                               */
    uint8_t frob_row[8];       /* AffineToConjugates recombination per
                                   step (7.4 b): out bit t == parity of
                                   a^{(r)} bits in frob_row[t]           */
} owf_consts_t;

/* Fills the 32x32 bit maps and the Frobenius recombination row.
 * Exported because owf_consts_init calls it after the F_2^128 solves. */
int owf_init_linear_maps(owf_consts_t *c);

/* Build the constants by solving the defining linear systems (7.2 f,g)
 * over F_2^128.  Returns 0 or -1 (singular system — should not happen). */
int  owf_consts_init(owf_consts_t *c);

/* 8.1 SM4th.ExtendWitness — k is the secret key, in = pk1 = x. */
void owf_extend_witness(const owf_consts_t *consts,
                        const uint8_t k[16], const uint8_t in[16],
                        uint8_t w[SM4TH_ELL_BYTES]);

typedef struct {
    /* compile-time-ish inputs */
    const sm4th_params_t *p;
    const owf_consts_t *consts;
    int mode;
    fe_t delta;                  /* ToField(chall3)                     */

    /* prover inputs */
    const uint8_t *w;            /* SM4TH_ELL_BYTES  witness (OS(w))     */
    const uint8_t *v_cols;       /* lambdaF*hat_lbytes  V matrix         */

    /* verifier inputs */
    const uint8_t *q_cols;       /* lambdaF*hat_lbytes  Q matrix         */
    const uint8_t *dw;           /* masked witness                       */

    /* outputs: PROVER fills a[j][k] (j = coefficient index, k = entry);
     *          VERIFIER fills b[k].                              */
    fe_t (*a)[SM4TH_C_ENTRIES];  /* caller: fe_t a[3][C]                 */
    fe_t *b;                     /* caller: fe_t b[C]                    */
    unsigned n_entries;          /* = SM4TH_C_ENTRIES when finished      */
} owf_ctx_t;

/* Row packing helpers (Clause 4.7): row r of a matrix M is the lambdaF-bit
 * string whose bit c is bit r of M[c]; ToField(row r) is its element.  */
void owf_row_to_field(const uint8_t *cols, uint64_t r, fe_t *out);

/* 9.4 SM4th.OWFConstraints — drives 9.1 and 9.2 in the order:
 * entry 0 = Lift(w[0]*w[1]) (keyspace), then 224 key-expansion entries,
 * then 228 encryption entries.  Returns 0 or -1 (degree overflow, i.e.
 * an implementation error), and fills the a/b outputs.                  */
int owf_constraints(owf_ctx_t *ctx, const uint8_t pk1[16],
                    const uint8_t pk2[16]);

#endif /* SM4TH_OWF_H */
