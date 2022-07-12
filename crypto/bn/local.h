/*
 * Copyright 2022 The BabaSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the BabaSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/BabaSSL/BabaSSL/blob/master/LICENSE
 */

/*
 * This header file is only used for the --symbol-prefix search export symbol.
 */

void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap,
                         const void *table, const BN_ULONG *np,
                         const BN_ULONG *n0, int num, int power);
void bn_scatter5(const BN_ULONG *inp, size_t num,
                 void *table, size_t power);
void bn_gather5(BN_ULONG *out, size_t num, void *table, size_t power);
void bn_power5(BN_ULONG *rp, const BN_ULONG *ap,
               const void *table, const BN_ULONG *np,
               const BN_ULONG *n0, int num, int power);
int bn_get_bits5(const BN_ULONG *ap, int off);
int bn_from_montgomery(BN_ULONG *rp, const BN_ULONG *ap,
                       const BN_ULONG *not_used, const BN_ULONG *np,
                       const BN_ULONG *n0, int num);

void bn_GF2m_mul_2x2(BN_ULONG *r, BN_ULONG a1, BN_ULONG a0, BN_ULONG b1,
                     BN_ULONG b0);
