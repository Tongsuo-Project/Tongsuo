/*
 * sm4th_params.h — parameter sets of the SM4th signature scheme.
 *
 * Implements the parameter tables of SM4th_spec.pdf (revision 4),
 * Clauses 4 and 12 (Tables 2, 18, 19, 21, 24).  Per the study scope,
 * only the two non-EM sets are provided:
 *
 *   SM4th-s : y = SM4_k(x), d = 3, lambdaF = 128,
 *                   SM4-CTR PRG, tau = 11, wgrind = 7, Topen = 102
 *   SM4th-f : same OWF,         tau = 16, wgrind = 8, Topen = 110
 *
 * The EM-d2 sets, the ti setting (lambdaF = 160, Ballet-256/256 PRG)
 * and the uBlockith / Vistrutith families are out of scope.
 *
 * Copyright (c) 2026 — auxiliary research note; code provided for study.
 * SPDX-License-Identifier: MIT
 */
#ifndef SM4TH_PARAMS_H
#define SM4TH_PARAMS_H

#include <openssl/e_os2.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Global constants (Clause 4.1)                                       */
/* ------------------------------------------------------------------ */
#define SM4TH_LAMBDA      128      /* classical security parameter     */
#define SM4TH_LAMBDA_Q     80      /* quantum target                    */
#define SM4TH_LAMBDA_F    128      /* proof-field degree                */
#define SM4TH_B            16      /* extension length of VOLEHash      */
#define SM4TH_XI          256      /* bit length of signer randomness   */
#define SM4TH_R            32      /* SM4 rounds                        */
#define SM4TH_DEGREE        3      /* d for the non-EM constraint entries*/
#define SM4TH_NBLOCK      128      /* PRG cipher block/key (bits)        */
#define SM4TH_NB           16      /* Nblock / 8                         */
#define SM4TH_LAMBDA_IV   128      /* IV length (bits)                    */
#define SM4TH_NIV          16      /* lambda_iv / 8                      */
#define SM4TH_N_FIELDS     16      /* lambdaF / 8                         */
#define SM4TH_DOMAIN_BYTES 10      /* ASCII "SM4th-v1/s" or "SM4th-v1/f" */

#define SM4TH_MAX_TAU      16
/* Normative message length bound |msg| <= 2^60 (octets). */
#if SIZE_MAX >= (UINT64_C(1) << 60)
# define SM4TH_MAX_MSG   ((size_t)(UINT64_C(1) << 60))
#else
# define SM4TH_MAX_MSG   SIZE_MAX
#endif

/* ------------------------------------------------------------------ */
/* Per-set descriptors (Clause 12).  The derived quantities follow the
 * defining formulas of Clause 12.2 and are checked by self-tests.     */
/* ------------------------------------------------------------------ */
typedef struct {
    const char *name;
    uint8_t domain[SM4TH_DOMAIN_BYTES]; /* protocol ID, no trailing NUL   */
    unsigned tau;              /* repetitions                          */
    unsigned wgrind;           /* grinding bits                         */
    unsigned topen;            /* maximum number of co-path seeds       */

    /* Derived (Clause 12.2 / 4.1); filled by sm4th_params_init().     */
    unsigned k_max;            /* maximum GGM depth                     */
    unsigned tau1, tau0;
    unsigned ki[SM4TH_MAX_TAU];/* depth of repetition i                 */
    unsigned ni[SM4TH_MAX_TAU];/* leaves of repetition i (ki <= 12)   */
    unsigned oi[SM4TH_MAX_TAU];/* first VOLE column of repetition i      */
    unsigned leaves;           /* L = sum ni                            */
    unsigned hat_ell;          /* ell + d*lambdaF + B  = 2208 bits      */
    unsigned hat_lbytes;       /* 276 octets                            */
    unsigned ldecom;           /* (2*tau + topen)*nb                    */
    unsigned sig_len;          /* L_sigma of Table 24                   */

    /* fixed for these sets:                                         */
    int      variant_d3;       /* always 1 here                          */
} sm4th_params_t;

/* Equivalent to the first witness constraint w[0] * w[1] = 0. */
static ossl_inline int sm4th_key_is_valid(const uint8_t key[16])
{
    return ((key[0] ^ 0xA3u) & 3u) != 3u;
}

/* Indices: 0 = SM4th-s, 1 = SM4th-f */
#define SM4TH_NUM_SETS 2

const sm4th_params_t *sm4th_params_get(int set_index);

/* GGM tree constants computed from the parameters. */
uint64_t sm4th_leaves_L(const sm4th_params_t *p);              /* L       */
uint64_t sm4th_nodes_total(const sm4th_params_t *p);           /* 2L - 1  */
uint64_t sm4th_pos_in_tree(const sm4th_params_t *p, unsigned i, uint64_t j);

/* Witness layout constants (Clause 8.1, Table 5) for the non-EM sets. */
#define SM4TH_ELL        1808    /* witness bits                        */
#define SM4TH_ELL_KE     1024    /* key-expansion part (bits)          */
#define SM4TH_ELL_ENC     784    /* encryption part (bits)              */
#define SM4TH_C_ENTRIES  453     /* 1 keyspace + 224 + 228              */
#define SM4TH_ELL_BYTES   226    /* ceil(ELL/8)                          */

#ifdef __cplusplus
}
#endif
#endif /* SM4TH_PARAMS_H */
