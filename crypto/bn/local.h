/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
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

/*
 * See crypto/bn/asm/rsaz-avx2.pl for further details.
 */
void rsaz_1024_norm2red_avx2(void *red, const void *norm);
void rsaz_1024_mul_avx2(void *ret, const void *a, const void *b,
                        const void *n, BN_ULONG k);
void rsaz_1024_sqr_avx2(void *ret, const void *a, const void *n, BN_ULONG k,
                        int cnt);
void rsaz_1024_scatter5_avx2(void *tbl, const void *val, int i);
void rsaz_1024_gather5_avx2(void *val, const void *tbl, int i);
void rsaz_1024_red2norm_avx2(void *norm, const void *red);

/*
 * See crypto/bn/rsaz-x86_64.pl for further details.
 */
void rsaz_512_mul(void *ret, const void *a, const void *b, const void *n,
                  BN_ULONG k);
void rsaz_512_mul_scatter4(void *ret, const void *a, const void *n,
                           BN_ULONG k, const void *tbl, unsigned int power);
void rsaz_512_mul_gather4(void *ret, const void *a, const void *tbl,
                          const void *n, BN_ULONG k, unsigned int power);
void rsaz_512_mul_by_one(void *ret, const void *a, const void *n, BN_ULONG k);
void rsaz_512_sqr(void *ret, const void *a, const void *n, BN_ULONG k,
                  int cnt);
void rsaz_512_scatter4(void *tbl, const BN_ULONG *val, int power);
void rsaz_512_gather4(BN_ULONG *val, const void *tbl, int power);

/*
 * See crypto/bn/asm/rsaz-avx512.pl for further details.
 */
void ossl_rsaz_amm52x20_x1_256(BN_ULONG *res, const BN_ULONG *base,
                               const BN_ULONG *exp, const BN_ULONG *m,
                               BN_ULONG k0);
void ossl_rsaz_amm52x20_x2_256(BN_ULONG *out, const BN_ULONG *a,
                               const BN_ULONG *b, const BN_ULONG *m,
                               const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x20_win5(BN_ULONG *red_Y,
                                       const BN_ULONG *red_table,
                                       int red_table_idx, int tbl_idx);
