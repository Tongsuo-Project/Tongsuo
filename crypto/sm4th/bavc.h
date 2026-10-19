/*
 * bavc.h — the VOLE layer of SM4th_spec.pdf Clause 5.5:
 *   GGM tree layout (5.5.1), BAVC.Commit/Open/Reconstruct (5.5.2-5.5.4),
 *   ConvertToVOLE (5.5.5), DecodeChall (5.5.6), VOLECommit (5.5.7) and
 *   VOLEReconstruct (5.5.8).
 */
#ifndef SM4TH_BAVC_H
#define SM4TH_BAVC_H

#include "sm4th_params.h"
#include "blockcipher.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stddef.h>

/* Working state of the GGM tree: all node seeds and all leaf
 * commitments.  Sign and Verify both use it; Verify leaves the seeds
 * of hidden leaves untouched and re-derives everything else.          */
typedef struct {
    const sm4th_params_t *p;
    uint8_t *node_seeds;     /* (2L-1) * NB                 */
    uint8_t *leaf_coms;      /* (2L-1) * 2*NB (by node id)  */
} bavc_t;

int  bavc_init(bavc_t *t, const sm4th_params_t *p);
void bavc_free(bavc_t *t);

/* 5.5.2: BAVC.Commit — expand the tree from the root seed r; output
 * com into com_out (2*NB octets).  Leaf seeds remain node_seeds.     */
int bavc_commit(bavc_t *t, const EVP_MD *shake128_md,
                const uint8_t r[SM4TH_NB],
                const uint8_t iv[SM4TH_NIV], uint8_t *com_out /*32*/);

/* 5.5.3: BAVC.Open — decomI for the index tuple Delta; returns 0 and
 * writes decomI (ldecom octets), -1 (too many co-path seeds), or -2
 * (allocation failure or an invalid internal index/invariant).       */
int bavc_open(bavc_t *t, const unsigned delta[SM4TH_MAX_TAU],
              uint8_t *decomI);

/* 5.5.4: BAVC.Reconstruct — recompute com and all seeds except the
 * hidden ones.  Returns 0, or -1 (R-B1: too many node seeds; R-B2:
 * nonzero padding).                                                   */
int bavc_reconstruct(bavc_t *t, const EVP_MD *shake128_md,
                     const uint8_t *decomI,
                     const unsigned delta[SM4TH_MAX_TAU],
                     const uint8_t iv[SM4TH_NIV], uint8_t *com_out /*32*/);

/* 5.5.5: ConvertToVOLE — the seeds sd[0..N-1] (sd[j] = NULL means the
 * missing seed); N = 2^d where d <= 12; outputs u and v[0..d-1], each
 * hat_lbytes octets (buffers must hold 2^12 entries worst case).
 * y_scratch must be at least N * hat_lbytes octets by the caller.     */
void convert_to_vole(const uint8_t *const sd[], unsigned d,
                     const uint8_t iv[SM4TH_NIV], uint64_t tweak,
                     uint8_t *u, uint8_t **v /* v[0..d-1], hat_lbytes each */,
                     uint8_t *y_scratch, unsigned N);

/* 5.5.6: DecodeChall — full chall3 (lambdaF/8 octets); writes
 * delta[0..tau-1]; returns -1 if a grinding bit is nonzero.            */
int decode_chall(const sm4th_params_t *p, const uint8_t *chall3,
                 unsigned delta[SM4TH_MAX_TAU]);

/* 5.5.7: VOLECommit — from the root seed r produce com, the correction
 * values c[1..tau-1] (tau-1 buffers of hat_lbytes), u and the V matrix
 * (lambdaF columns of hat_lbytes).  The caller provides the bavc_t
 * state (used for the seeds) and scratch space:
 *   vole_scratch:   max{ N_i } * hat_lbytes octets
 *   v_cols:         lambdaF * hat_lbytes octets (the V matrix)         */
int vole_commit(const sm4th_params_t *p, const EVP_MD *shake128_md,
                const uint8_t r[SM4TH_NB],
                const uint8_t iv[SM4TH_NIV],
                uint8_t *com_out /*32*/,
                uint8_t **c /*c[1..tau-1], hat_lbytes each*/,
                uint8_t *u /*hat_lbytes*/,
                uint8_t *v_cols /*lambdaF*hat_lbytes*/,
                bavc_t *tree,
                uint8_t *vole_scratch);

/* 5.5.8: VOLEReconstruct — outputs com_out and the Q matrix
 * (lambdaF columns of hat_lbytes).  Reuses the caller's bavc_t for
 * scratch.  Returns 0 or -1 (rejection).                              */
int vole_reconstruct(const sm4th_params_t *p, const EVP_MD *shake128_md,
                     const uint8_t *chall3,
                     const uint8_t *decomI, uint8_t **c,
                     const uint8_t iv[SM4TH_NIV],
                     uint8_t *com_out /*32*/,
                     uint8_t *q_cols /*lambdaF*hat_lbytes*/,
                     bavc_t *tree,
                     uint8_t *vole_scratch);

#endif /* SM4TH_BAVC_H */
