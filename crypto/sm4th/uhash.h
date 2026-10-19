/*
 * uhash.h — the universal hash functions of SM4th_spec.pdf Clause 5.4:
 * VOLEHash (5.4.1) and ZKHash (5.4.2).
 */
#ifndef SM4TH_UHASH_H
#define SM4TH_UHASH_H

#include "fields.h"
#include "sm4th_params.h"

#include <stdint.h>
#include <stddef.h>

/* VOLEHash — Clause 5.4.1.
 *   key:  chall1 ((5*lambdaF+64)/8 octets)
 *   x:    hat_ell bits (hat_lbytes octets)
 *   out:  lambdaF/8 + 2 octets
 * Semantics: n0 = (hat_ell-128-16)/8, ell' = 2176 bits,
 *   h2 = eta0*h0 + eta1*h1', h3 = eta2*h0 + eta3*h1',
 *   out = FE(h2) || FE(h3)[0,2) ^ x[n0..hat_lbytes).
 */
void vole_hash(const uint8_t *chall1, const uint8_t *x, uint8_t *out);

/* ZKHash — Clause 5.4.2.
 *   key:   chall2 ((3*lambdaF+64)/8 octets)
 *   x0:    sequence of n field elements (n = number of entries, 453)
 *   x1:    one field element
 *   r0*(sum s^{n-1-i} x0[i]) + r1*(sum t^{n-1-i} x0[i]) + x1
 */
void zk_hash(const uint8_t *chall2, const fe_t *x0, int n, fe_t x1, fe_t *out);

#endif /* SM4TH_UHASH_H */
