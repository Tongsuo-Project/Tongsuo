/*
 * Copyright 2022 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sdf.h>
#include <openssl/self_test.h>
#include "internal/nelem.h"
#include "self_test_rand.h"

#define MATRIX_FORWARD_ELIMINATION 0
#define MATRIX_BACKWARD_ELIMINATION 1

/* SIGNIFICANCE LEVEL */
static double alpha = 0.01;

static double MACHEP = 1.11022302462515654042E-16;  // 2**-53
static double MAXLOG = 7.09782712893383996732224E2; // log(MAXNUM)
static double MAXNUM = 1.7976931348623158E308;      // 2**1024*(1-MACHEP)
static double PI = 3.14159265358979323846;          // pi, duh!

static double big = 4.503599627370496e15;
static double biginv = 2.22044604925031308085e-16;

static double cephes_igam(double a, double x);
static double cephes_igamc(double a, double x);
static double cephes_lgam(double x);
static double cephes_polevl(double x, double *coef, int N);
static double cephes_p1evl(double x, double *coef, int N);
static double psi2(const unsigned char *buf, size_t m, size_t n);
static int get_bit(const unsigned char *buf, int m);
static void set_bit(unsigned char *buf, int m, int bit);
static int compute_rank(int M, int Q, unsigned char **matrix);
static void perform_elementary_row_operations(int flag, int i, int M, int Q,
                                              unsigned char **A);
static int find_unit_element_and_swap(int flag, int i, int M, int Q,
                                      unsigned char **A);
static int determine_rank(int m, int M, int Q, unsigned char **A);
static double cephes_normal(double x);
static int swap_rows(int i, int index, int Q, unsigned char **A);
static void dradf4(int ido, int l1, double *cc, double *ch, double *wa1,
                   double *wa2, double *wa3);
static void dradf2(int ido, int l1, double *cc, double *ch, double *wa1);
static void dradfg(int ido, int ip, int l1, int idl1, double *cc, double *c1,
                   double *c2, double *ch, double *ch2, double *wa);

static double cephes_normal(double x)
{
    double arg, result, sqrt2 = 1.414213562373095048801688724209698078569672;

    if (x > 0) {
        arg = x / sqrt2;
        result = 0.5 * (1 + erf(arg));
    } else {
        arg = -x / sqrt2;
        result = 0.5 * (1 - erf(arg));
    }

    return (result);
}

static int compute_rank(int M, int Q, unsigned char **matrix)
{
    int i, rank, m = M < Q ? M : Q;

    /* FORWARD APPLICATION OF ELEMENTARY ROW OPERATIONS */
    for (i = 0; i < m - 1; i++) {
        if (get_bit(matrix[i], i) == 1)
            perform_elementary_row_operations(MATRIX_FORWARD_ELIMINATION, i, M,
                                              Q, matrix);
        else { /* matrix[i][i] = 0 */
            if (find_unit_element_and_swap(MATRIX_FORWARD_ELIMINATION, i, M, Q,
                                           matrix)
                == 1)
                perform_elementary_row_operations(MATRIX_FORWARD_ELIMINATION, i,
                                                  M, Q, matrix);
        }
    }

    /* BACKWARD APPLICATION OF ELEMENTARY ROW OPERATIONS */
    for (i = m - 1; i > 0; i--) {
        if (get_bit(matrix[i], i) == 1)
            perform_elementary_row_operations(MATRIX_BACKWARD_ELIMINATION, i, M,
                                              Q, matrix);
        else { /* matrix[i][i] = 0 */
            if (find_unit_element_and_swap(MATRIX_BACKWARD_ELIMINATION, i, M, Q,
                                           matrix)
                == 1)
                perform_elementary_row_operations(MATRIX_BACKWARD_ELIMINATION,
                                                  i, M, Q, matrix);
        }
    }

    rank = determine_rank(m, M, Q, matrix);

    return rank;
}

static void perform_elementary_row_operations(int flag, int i, int M, int Q,
                                              unsigned char **A)
{
    int j, k;

    if (flag == MATRIX_FORWARD_ELIMINATION) {
        for (j = i + 1; j < M; j++)
            if (get_bit(A[j], i) == 1)
                for (k = i; k < Q; k++)
                    /* A[j][k] = (A[j][k] + A[i][k]) % 2 */
                    set_bit(A[j], k, (get_bit(A[j], k) + get_bit(A[i], k)) % 2);
    } else {
        for (j = i - 1; j >= 0; j--)
            if (get_bit(A[j], i) == 1)
                for (k = 0; k < Q; k++)
                    /* A[j][k] = (A[j][k] + A[i][k]) % 2 */
                    set_bit(A[j], k, (get_bit(A[j], k) + get_bit(A[i], k)) % 2);
    }
}

static int find_unit_element_and_swap(int flag, int i, int M, int Q,
                                      unsigned char **A)
{
    int index, row_op = 0;

    if (flag == MATRIX_FORWARD_ELIMINATION) {
        index = i + 1;
        while ((index < M) && (get_bit(A[index], i) == 0))
            index++;
        if (index < M)
            row_op = swap_rows(i, index, Q, A);
    } else {
        index = i - 1;
        while ((index >= 0) && (get_bit(A[index], i) == 0))
            index--;
        if (index >= 0)
            row_op = swap_rows(i, index, Q, A);
    }

    return row_op;
}

static int swap_rows(int i, int index, int Q, unsigned char **A)
{
    int p;
    unsigned char temp;

    for (p = 0; p < Q; p++) {
        temp = get_bit(A[i], p);
        set_bit(A[i], p, get_bit(A[index], p));
        set_bit(A[index], p, temp);
    }

    return 1;
}

/* DETERMINE RANK, THAT IS, COUNT THE NUMBER OF NONZERO ROWS */
static int determine_rank(int m, int M, int Q, unsigned char **A)
{
    int i, j, rank, allZeroes;

    rank = m;
    for (i = 0; i < M; i++) {
        allZeroes = 1;
        for (j = 0; j < Q; j++) {
            if (get_bit(A[i], j) == 1) {
                allZeroes = 0;
                break;
            }
        }
        if (allZeroes == 1)
            rank--;
    }

    return rank;
}

static void set_bit(unsigned char *buf, int m, int bit)
{
    if (m < 0)
        return;

    if (bit)
        buf[m / 8] |= 0x80 >> (m % 8);
    else
        buf[m / 8] &= ~(0x80 >> (m % 8));
}

static int get_bit(const unsigned char *buf, int m)
{
    if (m < 0)
        return 0;

    return (buf[m / 8] << (m % 8) >> 7) & 1;
}

static double cephes_igamc(double a, double x)
{
    double ans, ax, c, yc, r, t, y, z;
    double pk, pkm1, pkm2, qk, qkm1, qkm2;

    if (x <= 0 || a <= 0)
        return 1.0;

    if (x < 1.0 || x < a)
        return 1.e0 - cephes_igam(a, x);

    ax = a * log(x) - x - cephes_lgam(a);

    if (ax < -MAXLOG) {
        /* igamc: UNDERFLOW */
        return 0.0;
    }
    ax = exp(ax);

    /* continued fraction */
    y = 1.0 - a;
    z = x + y + 1.0;
    c = 0.0;
    pkm2 = 1.0;
    qkm2 = x;
    pkm1 = x + 1.0;
    qkm1 = z * x;
    ans = pkm1 / qkm1;

    do {
        c += 1.0;
        y += 1.0;
        z += 2.0;
        yc = y * c;
        pk = pkm1 * z - pkm2 * yc;
        qk = qkm1 * z - qkm2 * yc;
        if (qk != 0) {
            r = pk / qk;
            t = fabs((ans - r) / r);
            ans = r;
        } else
            t = 1.0;
        pkm2 = pkm1;
        pkm1 = pk;
        qkm2 = qkm1;
        qkm1 = qk;
        if (fabs(pk) > big) {
            pkm2 *= biginv;
            pkm1 *= biginv;
            qkm2 *= biginv;
            qkm1 *= biginv;
        }
    } while (t > MACHEP);

    return ans * ax;
}

static double cephes_igam(double a, double x)
{
    double ans, ax, c, r;

    if ((x <= 0) || (a <= 0))
        return 0.0;

    if ((x > 1.0) && (x > a))
        return 1.e0 - cephes_igamc(a, x);

    /* Compute  x**a * exp(-x) / gamma(a)  */
    ax = a * log(x) - x - cephes_lgam(a);
    if (ax < -MAXLOG) {
        /* igam: UNDERFLOW */
        return 0.0;
    }
    ax = exp(ax);

    /* power series */
    r = a;
    c = 1.0;
    ans = 1.0;

    do {
        r += 1.0;
        c *= x / r;
        ans += c;
    } while (c / ans > MACHEP);

    return ans * ax / a;
}

/* Logarithm of gamma function */
static double cephes_lgam(double x)
{
#define MAXLGM 2.556348e305
    /* A[]: Stirling's formula expansion of log gamma
     * B[], C[]: log gamma function between 2 and 3
     */
    unsigned short A[] = {0x6661, 0x2733, 0x9850, 0x3f4a, 0xe943,
                          0xb580, 0x7fbd, 0xbf43, 0x5ebb, 0x20dc,
                          0x019f, 0x3f4a, 0xa5a1, 0x16b0, 0xc16c,
                          0xbf66, 0x554b, 0x5555, 0x5555, 0x3fb5};
    unsigned short B[] = {0x6761, 0x8ff3, 0x8901, 0xc095, 0xb93e, 0x355b,
                          0xf234, 0xc0e2, 0x89e5, 0xf890, 0x3d73, 0xc114,
                          0xdb51, 0xf994, 0xbc82, 0xc131, 0xf20b, 0x0219,
                          0x4589, 0xc13a, 0x055e, 0x5418, 0x0c67, 0xc12a};
    static unsigned short C[] = {
        /*0x0000,0x0000,0x0000,0x3ff0,*/
        0x12b2, 0x1cf3, 0xfd0d, 0xc075, 0xd757, 0x7b89, 0xaa0d, 0xc0d0,
        0x4c9b, 0xb974, 0xeb84, 0xc10a, 0x0043, 0x7195, 0x6286, 0xc131,
        0xf34c, 0x892f, 0x5255, 0xc143, 0xe14a, 0x6a11, 0xce4b, 0xc13e};
    double p, q, u, w, z;
    int i;
    int sgngam = 1;

    if (x < -34.0) {
        q = -x;
        w = cephes_lgam(q);
        p = floor(q);
        if (p == q) {
        lgsing:
            goto loverf;
        }
        i = (int)p;
        if ((i & 1) == 0)
            sgngam = -1;
        else
            sgngam = 1;
        z = q - p;
        if (z > 0.5) {
            p += 1.0;
            z = p - q;
        }
        z = q * sin(PI * z);
        if (z == 0.0)
            goto lgsing;

        z = log(PI) - log(z) - w;
        return z;
    }

    if (x < 13.0) {
        z = 1.0;
        p = 0.0;
        u = x;
        while (u >= 3.0) {
            p -= 1.0;
            u = x + p;
            z *= u;
        }
        while (u < 2.0) {
            if (u == 0.0)
                goto lgsing;
            z /= u;
            p += 1.0;
            u = x + p;
        }
        if (z < 0.0) {
            sgngam = -1;
            z = -z;
        } else
            sgngam = 1;
        if (u == 2.0)
            return (log(z));
        p -= 2.0;
        x = x + p;
        p = x * cephes_polevl(x, (double *)B, 5)
            / cephes_p1evl(x, (double *)C, 6);

        return log(z) + p;
    }

    if (x > MAXLGM) {
    loverf:
        /* lgam: OVERFLOW */
        return sgngam * MAXNUM;
    }

    q = (x - 0.5) * log(x) - x + log(sqrt(2 * PI));
    if (x > 1.0e8)
        return q;

    p = 1.0 / (x * x);
    if (x >= 1000.0)
        q +=
            ((7.9365079365079365079365e-4 * p - 2.7777777777777777777778e-3) * p
             + 0.0833333333333333333333)
            / x;
    else
        q += cephes_polevl(p, (double *)A, 4) / x;

    return q;
}

static double cephes_polevl(double x, double *coef, int N)
{
    double ans;
    int i;
    double *p;

    p = coef;
    ans = *p++;
    i = N;

    do {
        ans = ans * x + *p++;
    } while (--i);

    return ans;
}

static double cephes_p1evl(double x, double *coef, int N)
{
    double ans;
    double *p;
    int i;

    p = coef;
    ans = x + *p++;
    i = N - 1;

    do {
        ans = ans * x + *p++;
    } while (--i);

    return ans;
}

static double psi2(const unsigned char *buf, size_t m, size_t n)
{
    size_t i, j, k, pow_len;
    double sum;
    unsigned int *P;

    if (m == 0)
        return 0.0;

    pow_len = (size_t)pow(2, m + 1) - 1;

    if ((P = OPENSSL_zalloc(pow_len * sizeof(unsigned int))) == NULL)
        return 0.0;

    for (i = 1; i < pow_len - 1; i++)
        P[i] = 0;
    for (i = 0; i < n; i++) {
        k = 1;
        for (j = 0; j < m; j++) {
            int bit = get_bit(buf, (i + j) % n);
            if (bit == 0)
                k *= 2;
            else
                k = 2 * k + 1;
        }
        P[k - 1]++;
    }
    sum = 0.0;
    for (i = (size_t)pow(2, m) - 1; i < (size_t)pow(2, m + 1) - 1; i++)
        sum += pow(P[i], 2);
    sum = (sum * pow(2, m) / (double)n) - (double)n;

    OPENSSL_free(P);

    return sum;
}

static void drfti1(int n, double *wa, int *ifac)
{
    static int ntryh[4] = {4, 2, 3, 5};
    static double tpi = 6.28318530717958647692528676655900577;
    double arg, argh, argld, fi;
    int ntry = 0, i, j = -1;
    int k1, l1, l2, ib;
    int ld, ii, ip, is, nq, nr;
    int ido, ipm, nfm1;
    int nl = n;
    int nf = 0;

L101:
    j++;
    if (j < 4)
        ntry = ntryh[j];
    else
        ntry += 2;

L104:
    nq = nl / ntry;
    nr = nl - ntry * nq;
    if (nr != 0)
        goto L101;

    nf++;
    ifac[nf + 1] = ntry;
    nl = nq;
    if (ntry != 2)
        goto L107;
    if (nf == 1)
        goto L107;

    for (i = 1; i < nf; i++) {
        ib = nf - i + 1;
        ifac[ib + 1] = ifac[ib];
    }
    ifac[2] = 2;

L107:
    if (nl != 1)
        goto L104;
    ifac[0] = n;
    ifac[1] = nf;
    argh = tpi / n;
    is = 0;
    nfm1 = nf - 1;
    l1 = 1;

    if (nfm1 == 0)
        return;

    for (k1 = 0; k1 < nfm1; k1++) {
        ip = ifac[k1 + 2];
        ld = 0;
        l2 = l1 * ip;
        ido = n / l2;
        ipm = ip - 1;

        for (j = 0; j < ipm; j++) {
            ld += l1;
            i = is;
            argld = (double)ld * argh;
            fi = 0.0;
            for (ii = 2; ii < ido; ii += 2) {
                fi += 1.0;
                arg = fi * argld;
                wa[i++] = cos(arg);
                wa[i++] = sin(arg);
            }
            is += ido;
        }
        l1 = l2;
    }
}

static void __ogg_fdrffti(int n, double *wsave, int *ifac)
{
    if (n == 1)
        return;
    drfti1(n, wsave + n, ifac);
}

static void dradf2(int ido, int l1, double *cc, double *ch, double *wa1)
{
    int i, k;
    double ti2, tr2;
    int t0, t1, t2, t3, t4, t5, t6;

    t1 = 0;
    t0 = (t2 = l1 * ido);
    t3 = ido << 1;
    for (k = 0; k < l1; k++) {
        ch[t1 << 1] = cc[t1] + cc[t2];
        ch[(t1 << 1) + t3 - 1] = cc[t1] - cc[t2];
        t1 += ido;
        t2 += ido;
    }

    if (ido < 2)
        return;
    if (ido == 2)
        goto L105;

    t1 = 0;
    t2 = t0;
    for (k = 0; k < l1; k++) {
        t3 = t2;
        t4 = (t1 << 1) + (ido << 1);
        t5 = t1;
        t6 = t1 + t1;
        for (i = 2; i < ido; i += 2) {
            t3 += 2;
            t4 -= 2;
            t5 += 2;
            t6 += 2;
            tr2 = wa1[i - 2] * cc[t3 - 1] + wa1[i - 1] * cc[t3];
            ti2 = wa1[i - 2] * cc[t3] - wa1[i - 1] * cc[t3 - 1];
            ch[t6] = cc[t5] + ti2;
            ch[t4] = ti2 - cc[t5];
            ch[t6 - 1] = cc[t5 - 1] + tr2;
            ch[t4 - 1] = cc[t5 - 1] - tr2;
        }
        t1 += ido;
        t2 += ido;
    }

    if (ido % 2 == 1)
        return;

L105:
    t3 = (t2 = (t1 = ido) - 1);
    t2 += t0;
    for (k = 0; k < l1; k++) {
        ch[t1] = -cc[t2];
        ch[t1 - 1] = cc[t3];
        t1 += ido << 1;
        t2 += ido;
        t3 += ido;
    }
}

static void dradf4(int ido, int l1, double *cc, double *ch, double *wa1,
                   double *wa2, double *wa3)
{
    static double hsqt2 = .70710678118654752440084436210485;
    int i, k, t0, t1, t2, t3, t4, t5, t6;
    double ci2, ci3, ci4, cr2, cr3, cr4;
    double ti1, ti2, ti3, ti4, tr1, tr2, tr3, tr4;

    t0 = l1 * ido;
    t1 = t0;
    t4 = t1 << 1;
    t2 = t1 + (t1 << 1);
    t3 = 0;

    for (k = 0; k < l1; k++) {
        tr1 = cc[t1] + cc[t2];
        tr2 = cc[t3] + cc[t4];
        ch[t5 = t3 << 2] = tr1 + tr2;
        ch[(ido << 2) + t5 - 1] = tr2 - tr1;
        ch[(t5 += (ido << 1)) - 1] = cc[t3] - cc[t4];
        ch[t5] = cc[t2] - cc[t1];

        t1 += ido;
        t2 += ido;
        t3 += ido;
        t4 += ido;
    }

    if (ido < 2)
        return;
    if (ido == 2)
        goto L105;

    t1 = 0;
    for (k = 0; k < l1; k++) {
        t2 = t1;
        t4 = t1 << 2;
        t5 = (t6 = ido << 1) + t4;
        for (i = 2; i < ido; i += 2) {
            t3 = (t2 += 2);
            t4 += 2;
            t5 -= 2;

            t3 += t0;
            cr2 = wa1[i - 2] * cc[t3 - 1] + wa1[i - 1] * cc[t3];
            ci2 = wa1[i - 2] * cc[t3] - wa1[i - 1] * cc[t3 - 1];
            t3 += t0;
            cr3 = wa2[i - 2] * cc[t3 - 1] + wa2[i - 1] * cc[t3];
            ci3 = wa2[i - 2] * cc[t3] - wa2[i - 1] * cc[t3 - 1];
            t3 += t0;
            cr4 = wa3[i - 2] * cc[t3 - 1] + wa3[i - 1] * cc[t3];
            ci4 = wa3[i - 2] * cc[t3] - wa3[i - 1] * cc[t3 - 1];

            tr1 = cr2 + cr4;
            tr4 = cr4 - cr2;
            ti1 = ci2 + ci4;
            ti4 = ci2 - ci4;
            ti2 = cc[t2] + ci3;
            ti3 = cc[t2] - ci3;
            tr2 = cc[t2 - 1] + cr3;
            tr3 = cc[t2 - 1] - cr3;

            ch[t4 - 1] = tr1 + tr2;
            ch[t4] = ti1 + ti2;

            ch[t5 - 1] = tr3 - ti4;
            ch[t5] = tr4 - ti3;

            ch[t4 + t6 - 1] = ti4 + tr3;
            ch[t4 + t6] = tr4 + ti3;

            ch[t5 + t6 - 1] = tr2 - tr1;
            ch[t5 + t6] = ti1 - ti2;
        }
        t1 += ido;
    }
    if (ido % 2 == 1)
        return;

L105:

    t2 = (t1 = t0 + ido - 1) + (t0 << 1);
    t3 = ido << 2;
    t4 = ido;
    t5 = ido << 1;
    t6 = ido;

    for (k = 0; k < l1; k++) {
        ti1 = -hsqt2 * (cc[t1] + cc[t2]);
        tr1 = hsqt2 * (cc[t1] - cc[t2]);
        ch[t4 - 1] = tr1 + cc[t6 - 1];
        ch[t4 + t5 - 1] = cc[t6 - 1] - tr1;
        ch[t4] = ti1 - cc[t1 + t0];
        ch[t4 + t5] = ti1 + cc[t1 + t0];
        t1 += ido;
        t2 += ido;
        t4 += t3;
        t6 += ido;
    }
}

static void dradfg(int ido, int ip, int l1, int idl1, double *cc, double *c1,
                   double *c2, double *ch, double *ch2, double *wa)
{
    static double tpi = 6.28318530717958647692528676655900577;
    int idij, ipph, i, j, k, l, ic, ik, is;
    int t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10;
    double dc2, ai1, ai2, ar1, ar2, ds2;
    int nbd;
    double dcp, arg, dsp, ar1h, ar2h;
    int idp2, ipp2;

    arg = tpi / (double)ip;
    dcp = cos(arg);
    dsp = sin(arg);
    ipph = (ip + 1) >> 1;
    ipp2 = ip;
    idp2 = ido;
    nbd = (ido - 1) >> 1;
    t0 = l1 * ido;
    t10 = ip * ido;

    if (ido == 1)
        goto L119;
    for (ik = 0; ik < idl1; ik++)
        ch2[ik] = c2[ik];

    t1 = 0;
    for (j = 1; j < ip; j++) {
        t1 += t0;
        t2 = t1;
        for (k = 0; k < l1; k++) {
            ch[t2] = c1[t2];
            t2 += ido;
        }
    }

    is = -ido;
    t1 = 0;
    if (nbd > l1) {
        for (j = 1; j < ip; j++) {
            t1 += t0;
            is += ido;
            t2 = -ido + t1;
            for (k = 0; k < l1; k++) {
                idij = is - 1;
                t2 += ido;
                t3 = t2;
                for (i = 2; i < ido; i += 2) {
                    idij += 2;
                    t3 += 2;
                    ch[t3 - 1] = wa[idij - 1] * c1[t3 - 1] + wa[idij] * c1[t3];
                    ch[t3] = wa[idij - 1] * c1[t3] - wa[idij] * c1[t3 - 1];
                }
            }
        }
    } else {
        for (j = 1; j < ip; j++) {
            is += ido;
            idij = is - 1;
            t1 += t0;
            t2 = t1;
            for (i = 2; i < ido; i += 2) {
                idij += 2;
                t2 += 2;
                t3 = t2;
                for (k = 0; k < l1; k++) {
                    ch[t3 - 1] = wa[idij - 1] * c1[t3 - 1] + wa[idij] * c1[t3];
                    ch[t3] = wa[idij - 1] * c1[t3] - wa[idij] * c1[t3 - 1];
                    t3 += ido;
                }
            }
        }
    }

    t1 = 0;
    t2 = ipp2 * t0;
    if (nbd < l1) {
        for (j = 1; j < ipph; j++) {
            t1 += t0;
            t2 -= t0;
            t3 = t1;
            t4 = t2;
            for (i = 2; i < ido; i += 2) {
                t3 += 2;
                t4 += 2;
                t5 = t3 - ido;
                t6 = t4 - ido;
                for (k = 0; k < l1; k++) {
                    t5 += ido;
                    t6 += ido;
                    c1[t5 - 1] = ch[t5 - 1] + ch[t6 - 1];
                    c1[t6 - 1] = ch[t5] - ch[t6];
                    c1[t5] = ch[t5] + ch[t6];
                    c1[t6] = ch[t6 - 1] - ch[t5 - 1];
                }
            }
        }
    } else {
        for (j = 1; j < ipph; j++) {
            t1 += t0;
            t2 -= t0;
            t3 = t1;
            t4 = t2;
            for (k = 0; k < l1; k++) {
                t5 = t3;
                t6 = t4;
                for (i = 2; i < ido; i += 2) {
                    t5 += 2;
                    t6 += 2;
                    c1[t5 - 1] = ch[t5 - 1] + ch[t6 - 1];
                    c1[t6 - 1] = ch[t5] - ch[t6];
                    c1[t5] = ch[t5] + ch[t6];
                    c1[t6] = ch[t6 - 1] - ch[t5 - 1];
                }
                t3 += ido;
                t4 += ido;
            }
        }
    }

L119:
    for (ik = 0; ik < idl1; ik++)
        c2[ik] = ch2[ik];

    t1 = 0;
    t2 = ipp2 * idl1;
    for (j = 1; j < ipph; j++) {
        t1 += t0;
        t2 -= t0;
        t3 = t1 - ido;
        t4 = t2 - ido;
        for (k = 0; k < l1; k++) {
            t3 += ido;
            t4 += ido;
            c1[t3] = ch[t3] + ch[t4];
            c1[t4] = ch[t4] - ch[t3];
        }
    }

    ar1 = 1.0;
    ai1 = 0.0;
    t1 = 0;
    t2 = ipp2 * idl1;
    t3 = (ip - 1) * idl1;
    for (l = 1; l < ipph; l++) {
        t1 += idl1;
        t2 -= idl1;
        ar1h = dcp * ar1 - dsp * ai1;
        ai1 = dcp * ai1 + dsp * ar1;
        ar1 = ar1h;
        t4 = t1;
        t5 = t2;
        t6 = t3;
        t7 = idl1;

        for (ik = 0; ik < idl1; ik++) {
            ch2[t4++] = c2[ik] + ar1 * c2[t7++];
            ch2[t5++] = ai1 * c2[t6++];
        }

        dc2 = ar1;
        ds2 = ai1;
        ar2 = ar1;
        ai2 = ai1;

        t4 = idl1;
        t5 = (ipp2 - 1) * idl1;
        for (j = 2; j < ipph; j++) {
            t4 += idl1;
            t5 -= idl1;

            ar2h = dc2 * ar2 - ds2 * ai2;
            ai2 = dc2 * ai2 + ds2 * ar2;
            ar2 = ar2h;

            t6 = t1;
            t7 = t2;
            t8 = t4;
            t9 = t5;
            for (ik = 0; ik < idl1; ik++) {
                ch2[t6++] += ar2 * c2[t8++];
                ch2[t7++] += ai2 * c2[t9++];
            }
        }
    }

    t1 = 0;
    for (j = 1; j < ipph; j++) {
        t1 += idl1;
        t2 = t1;
        for (ik = 0; ik < idl1; ik++)
            ch2[ik] += c2[t2++];
    }

    if (ido < l1)
        goto L132;

    t1 = 0;
    t2 = 0;
    for (k = 0; k < l1; k++) {
        t3 = t1;
        t4 = t2;
        for (i = 0; i < ido; i++)
            cc[t4++] = ch[t3++];
        t1 += ido;
        t2 += t10;
    }

    goto L135;

L132:
    for (i = 0; i < ido; i++) {
        t1 = i;
        t2 = i;
        for (k = 0; k < l1; k++) {
            cc[t2] = ch[t1];
            t1 += ido;
            t2 += t10;
        }
    }

L135:
    t1 = 0;
    t2 = ido << 1;
    t3 = 0;
    t4 = ipp2 * t0;
    for (j = 1; j < ipph; j++) {

        t1 += t2;
        t3 += t0;
        t4 -= t0;

        t5 = t1;
        t6 = t3;
        t7 = t4;

        for (k = 0; k < l1; k++) {
            cc[t5 - 1] = ch[t6];
            cc[t5] = ch[t7];
            t5 += t10;
            t6 += ido;
            t7 += ido;
        }
    }

    if (ido == 1)
        return;
    if (nbd < l1)
        goto L141;

    t1 = -ido;
    t3 = 0;
    t4 = 0;
    t5 = ipp2 * t0;
    for (j = 1; j < ipph; j++) {
        t1 += t2;
        t3 += t2;
        t4 += t0;
        t5 -= t0;
        t6 = t1;
        t7 = t3;
        t8 = t4;
        t9 = t5;
        for (k = 0; k < l1; k++) {
            for (i = 2; i < ido; i += 2) {
                ic = idp2 - i;
                cc[i + t7 - 1] = ch[i + t8 - 1] + ch[i + t9 - 1];
                cc[ic + t6 - 1] = ch[i + t8 - 1] - ch[i + t9 - 1];
                cc[i + t7] = ch[i + t8] + ch[i + t9];
                cc[ic + t6] = ch[i + t9] - ch[i + t8];
            }
            t6 += t10;
            t7 += t10;
            t8 += ido;
            t9 += ido;
        }
    }
    return;

L141:

    t1 = -ido;
    t3 = 0;
    t4 = 0;
    t5 = ipp2 * t0;
    for (j = 1; j < ipph; j++) {
        t1 += t2;
        t3 += t2;
        t4 += t0;
        t5 -= t0;
        for (i = 2; i < ido; i += 2) {
            t6 = idp2 + t1 - i;
            t7 = i + t3;
            t8 = i + t4;
            t9 = i + t5;
            for (k = 0; k < l1; k++) {
                cc[t7 - 1] = ch[t8 - 1] + ch[t9 - 1];
                cc[t6 - 1] = ch[t8 - 1] - ch[t9 - 1];
                cc[t7] = ch[t8] + ch[t9];
                cc[t6] = ch[t9] - ch[t8];
                t6 += t10;
                t7 += t10;
                t8 += ido;
                t9 += ido;
            }
        }
    }
}

static void drftf1(int n, double *c, double *ch, double *wa, int *ifac)
{
    int i, k1, l1, l2;
    int na, kh, nf;
    int ip, iw, ido, idl1, ix2, ix3;

    nf = ifac[1];
    na = 1;
    l2 = n;
    iw = n;

    for (k1 = 0; k1 < nf; k1++) {
        kh = nf - k1;
        ip = ifac[kh + 1];
        l1 = l2 / ip;
        ido = n / l2;
        idl1 = ido * l1;
        iw -= (ip - 1) * ido;
        na = 1 - na;

        if (ip != 4)
            goto L102;

        ix2 = iw + ido;
        ix3 = ix2 + ido;
        if (na != 0)
            dradf4(ido, l1, ch, c, wa + iw - 1, wa + ix2 - 1, wa + ix3 - 1);
        else
            dradf4(ido, l1, c, ch, wa + iw - 1, wa + ix2 - 1, wa + ix3 - 1);
        goto L110;

    L102:
        if (ip != 2)
            goto L104;
        if (na != 0)
            goto L103;

        dradf2(ido, l1, c, ch, wa + iw - 1);
        goto L110;

    L103:
        dradf2(ido, l1, ch, c, wa + iw - 1);
        goto L110;

    L104:
        if (ido == 1)
            na = 1 - na;
        if (na != 0)
            goto L109;

        dradfg(ido, ip, l1, idl1, c, c, c, ch, ch, wa + iw - 1);
        na = 1;
        goto L110;

    L109:
        dradfg(ido, ip, l1, idl1, ch, ch, ch, c, c, wa + iw - 1);
        na = 0;

    L110:
        l2 = l1;
    }

    if (na == 1)
        return;

    for (i = 0; i < n; i++)
        c[i] = ch[i];
}

static void __ogg_fdrfftf(int n, double *r, double *wsave, int *ifac)
{
    if (n == 1)
        return;
    drftf1(n, r, wsave, wsave + n, ifac);
}

/*
 * 单比特频数检测, Frequency (Monobit) Test
 */
int rand_self_test_frequency(const unsigned char *buf, size_t nbit, double *P_value)
{
    size_t i, n = nbit;
    double sum = 0;
    double p_value;

    for (i = 0; i < n; i++)
        sum += 2 * get_bit(buf, i) - 1;

    p_value = erfc(fabs(sum) / sqrt(n) / sqrt(2.0));

    if (P_value)
        *P_value = p_value;

    return p_value >= alpha;
}

/*
 * 块内频数检测, Frequency Test within a Block
 */
int rand_self_test_block_frequency(const unsigned char *buf, size_t nbit,
                                   size_t m, double *P_value)
{
    size_t i, j, N, block_sum;
    double p_value, sum, pi, V;

    N = nbit / m;
    sum = 0.0;

    for (i = 0; i < N; i++) {
        block_sum = 0;
        for (j = 0; j < m; j++)
            block_sum += get_bit(buf, i * m + j);

        pi = (double)block_sum / m;
        sum += pow(pi - 0.5, 2);
    }

    V = 4.0 * m * sum;
    p_value = cephes_igamc(N / 2.0, V / 2.0);

    if (P_value)
        *P_value = p_value;

    return p_value >= alpha;
}

/*
 * 扑克检测
 */
int rand_self_test_poker(const unsigned char *buf, size_t nbit, size_t m,
                         double *P_value)
{
    size_t i, j, n = nbit, N, block_sum;
    double p_value, sum = 0.0, V;
    size_t *F = NULL;

    if (m != 4 && m != 8)
        return 0;

    N = n / m;

    F = OPENSSL_zalloc((size_t)pow(2, m) * sizeof(size_t));
    if (F == NULL)
        return 0;

    for (i = 0; i < N; i++) {
        if (m == 8)
            block_sum = (unsigned int)buf[i];
        else {
            block_sum = 0;
            for (j = 0; j < m; j++)
                block_sum = (block_sum << 1) | get_bit(buf, i * m + j);
        }
        F[block_sum]++;
    }

    for (i = 0; i < (size_t)pow(2, m); i++)
        sum += F[i] * F[i];

    V = pow(2, m) / N * sum - N;

    p_value = cephes_igamc((pow(2, m) - 1) / 2.0, V / 2.0);
    if (P_value)
        *P_value = p_value;

    OPENSSL_free(F);
    return p_value >= alpha;
}

/*
 * 重叠子序列检测, Serial Test
 */
int rand_self_test_serial(const unsigned char *buf, size_t nbit, size_t m,
                          double *P1, double *P2)
{
    double p_value1, p_value2, psim0, psim1, psim2, del1, del2;

    psim0 = psi2(buf, m, nbit);
    psim1 = psi2(buf, m - 1, nbit);
    psim2 = psi2(buf, m - 2, nbit);
    del1 = psim0 - psim1;
    del2 = psim0 - 2.0 * psim1 + psim2;
    p_value1 = cephes_igamc(pow(2, m - 1) / 2, del1 / 2.0);
    p_value2 = cephes_igamc(pow(2, m - 2) / 2, del2 / 2.0);

    if (P1)
        *P1 = p_value1;
    if (P2)
        *P2 = p_value2;

    return p_value1 >= alpha && p_value2 >= alpha;
}

/*
 * 游程总数检测, Runs Test
 */
int rand_self_test_runs(const unsigned char *buf, size_t nbit, double *P)
{
    size_t n = nbit, S = 0, k;
    double pi, Vn, V, p_value;

    for (k = 0; k < n; k++)
        if (get_bit(buf, k))
            S++;

    pi = (double)S / (double)n;
    Vn = 1;
    for (k = 1; k < n; k++)
        if (get_bit(buf, k) != get_bit(buf, k - 1))
            Vn++;

    V = (Vn - 2.0 * n * pi * (1 - pi)) / (2.0 * pi * (1 - pi) * sqrt(n));
    p_value = erfc(fabs(V) / sqrt(2.0));

    if (P)
        *P = p_value;

    return p_value >= alpha;
}

/*
 * 游程分布检测
 */
int rand_self_test_runs_distribution(const unsigned char *buf, size_t nbit, double *P)
{
    size_t n = nbit, i, k = 0, cnt, T = 0;
    int cur, last;
    size_t *B = NULL, *G = NULL;
    double p_value, V = 0.0, e;

    for (i = 1; i <= n; i++)
        if ((n - i + 3) / pow(2, i + 2) >= 5)
            k = i;

    if ((B = OPENSSL_zalloc(k * sizeof(size_t))) == NULL
        || (G = OPENSSL_zalloc(k * sizeof(size_t))) == NULL) {
        if (B != NULL)
            OPENSSL_free(B);
        if (G != NULL)
            OPENSSL_free(G);

        return 0;
    }

    last = get_bit(buf, 0);
    cnt = 1;

    for (i = 1; i < n; i++) {
        cur = get_bit(buf, i);

        if (cur == last) {
            cnt++;
        } else {
            if (cnt > k)
                cnt = k;

            T++;
            if (last == 1)
                B[cnt - 1]++;
            else
                G[cnt - 1]++;

            cnt = 1;
        }

        last = cur;
    }

    if (cnt > k)
        cnt = k;

    T++;
    if (last == 1)
        B[cnt - 1]++;
    else
        G[cnt - 1]++;

    for (i = 0; i < k; i++) {
        if (i != k - 1)
            e = T / pow(2, i + 2);
        else
            e = T / pow(2, k);
        V += (pow(B[i] - e, 2) + pow(G[i] - e, 2)) / e;
    }

    p_value = cephes_igamc(k - 1, V / 2.0);

    OPENSSL_free(B);
    OPENSSL_free(G);

    if (P)
        *P = p_value;

    return p_value >= alpha;
}

/*
 * 块内最大1游程检测, Test for the Longest Run of Ones in a Block
 */
int rand_self_test_longest_run_of_ones(const unsigned char *buf, size_t nbit, double *P)
{
    double pval, chi2, pi[7];
    int run, v_n_obs, V[7];
    size_t n = nbit, N, M, i, j, K;
    unsigned int nu[7] = {0, 0, 0, 0, 0, 0, 0};

    /* n is too short */
    if (n < 128)
        return 0;

    if (n < 6272) {
        K = 3;
        M = 8;
        V[0] = 1;
        V[1] = 2;
        V[2] = 3;
        V[3] = 4;
        pi[0] = 0.2148;
        pi[1] = 0.3672;
        pi[2] = 0.2305;
        pi[3] = 0.1875;
    } else if (n < 750000) {
        K = 5;
        M = 128;
        V[0] = 4;
        V[1] = 5;
        V[2] = 6;
        V[3] = 7;
        V[4] = 8;
        V[5] = 9;
        pi[0] = 0.1174;
        pi[1] = 0.2430;
        pi[2] = 0.2494;
        pi[3] = 0.1752;
        pi[4] = 0.1027;
        pi[5] = 0.1124;
    } else {
        K = 6;
        M = 10000;
        V[0] = 10;
        V[1] = 11;
        V[2] = 12;
        V[3] = 13;
        V[4] = 14;
        V[5] = 15;
        V[6] = 16;
        pi[0] = 0.086632;
        pi[1] = 0.208201;
        pi[2] = 0.248419;
        pi[3] = 0.193913;
        pi[4] = 0.121458;
        pi[5] = 0.068011;
        pi[6] = 0.073366;
    }

    N = n / M;
    for (i = 0; i < N; i++) {
        v_n_obs = 0;
        run = 0;
        for (j = 0; j < M; j++) {
            if (get_bit(buf, i * M + j) == 1) {
                run++;
                if (run > v_n_obs)
                    v_n_obs = run;
            } else
                run = 0;
        }
        if (v_n_obs < V[0])
            nu[0]++;
        for (j = 0; j <= K; j++) {
            if (v_n_obs == V[j])
                nu[j]++;
        }
        if (v_n_obs > V[K])
            nu[K]++;
    }

    chi2 = 0.0;
    for (i = 0; i <= K; i++)
        chi2 += ((nu[i] - N * pi[i]) * (nu[i] - N * pi[i])) / (N * pi[i]);

    pval = cephes_igamc((double)(K / 2.0), chi2 / 2.0);
    if (P)
        *P = pval;

    return pval >= alpha;
}

/*
 * 二元推导检测
 */
int rand_self_test_binary_derivation(const unsigned char *buf, size_t nbit,
                                     size_t k, double *P)
{
    size_t n = nbit, i, j;
    double sum = 0;
    unsigned char *buf1 = NULL, *buf2 = NULL, *tmp;
    double p_value, V;

    if ((buf1 = OPENSSL_malloc((n + 7) / 8)) == NULL
        || (buf2 = OPENSSL_malloc((n + 7) / 8)) == NULL) {
        if (buf1 != NULL)
            OPENSSL_free(buf1);
        if (buf2 != NULL)
            OPENSSL_free(buf2);

        return 0;
    }

    memcpy(buf1, buf, (n + 7) / 8);

    for (i = 1; i <= k; i++) {
        for (j = 0; j < n - i; j++) {
            int b = get_bit(buf1, j) ^ get_bit(buf1, j + 1);
            set_bit(buf2, j, b);

            if (i == k)
                sum += 2 * b - 1;
        }

        tmp = buf1;
        buf1 = buf2;
        buf2 = tmp;
    }

    OPENSSL_free(buf1);
    OPENSSL_free(buf2);

    V = fabs(sum) / sqrt(n - k);

    p_value = erfc(V / sqrt(2.0));
    if (P)
        *P = p_value;

    return p_value >= alpha;
}

/*
 * 自相关检测
 */
int rand_self_test_self_correlation(const unsigned char *buf, size_t nbit,
                                    size_t d, double *P)
{
    size_t n = nbit, i, A = 0;
    double p_value, V;

    if (d < 1 || d > n / 2 || d + 10 >= n)
        return 0;

    for (i = 0; i < n - d; i++)
        A += get_bit(buf, i) ^ get_bit(buf, i + d);

    V = 2.0 * (A - (n - d) / 2.0) / sqrt(n - d);
    p_value = erfc(fabs(V) / sqrt(2.0));

    if (P)
        *P = p_value;

    return p_value >= alpha;
}

/*
 * 矩阵秩检测, Binary Matrix Rank Test
 */
int rand_self_test_binary_matrix_rank(const unsigned char *buf, size_t nbit,
                                      double *P)
{
    int R, F_32 = 0, F_31 = 0;
    size_t n = nbit, N, i, j;
    double V, p_value;
    unsigned char *matrix[32];
    unsigned char m[32][4];

    for (i = 0; i < 32; i++)
        matrix[i] = (unsigned char *)&m[i];

    N = n / (32 * 32);
    if (N == 0) {
        p_value = 0.00;
    } else {
        for (i = 0; i < N; i++) {

            for (j = 0; j < 32; j++)
                memcpy(matrix[j], buf + i * 32 * 4 + j * 4, 4);

            R = compute_rank(32, 32, (unsigned char **)matrix);
            if (R == 32)
                F_32++;
            if (R == 31)
                F_31++;
        }

        V = pow(F_32 - 0.2888 * N, 2) / 0.2888
            + pow(F_31 - 0.5776 * N, 2) / 0.5776
            + pow(N - F_32 - F_31 - 0.1336 * N, 2) / 0.1336;
        V = V / N;

        p_value = cephes_igamc(1, V / 2.0);
    }

    if (P)
        *P = p_value;

    return p_value >= alpha;
}

/*
 * 累加和检测, Cumulative Sums Test
 * P1, 前向检测结果
 * P2, 后向检测结果
 */
int rand_self_test_cumulative_sums(const unsigned char *buf, size_t nbit,
                                   double *P1, double *P2)
{
    size_t n = nbit, i;
    ssize_t S, k, sup, inf, z = 0, zrev = 0;
    double sum1, sum2, p_value;

    S = 0;
    sup = 0;
    inf = 0;
    for (i = 0; i < n; i++) {
        get_bit(buf, i) ? S++ : S--;
        if (S > sup)
            sup++;
        if (S < inf)
            inf--;
        z = (sup > -inf) ? sup : -inf;
        zrev = (sup - S > S - inf) ? sup - S : S - inf;
    }

    /* forward */
    sum1 = 0.0;
    for (k = ((ssize_t)-n / z + 1) / 4; k <= (ssize_t)(n / z - 1) / 4; k++) {
        sum1 += cephes_normal(((4 * k + 1) * z) / sqrt(n));
        sum1 -= cephes_normal(((4 * k - 1) * z) / sqrt(n));
    }
    sum2 = 0.0;
    for (k = ((ssize_t)-n / z - 3) / 4; k <= (ssize_t)(n / z - 1) / 4; k++) {
        sum2 += cephes_normal(((4 * k + 3) * z) / sqrt(n));
        sum2 -= cephes_normal(((4 * k + 1) * z) / sqrt(n));
    }

    p_value = 1.0 - sum1 + sum2;

    if (P1)
        *P1 = p_value;

    if (p_value < alpha)
        return 0;

    /* backwards */
    sum1 = 0.0;
    for (k = ((ssize_t)-n / zrev + 1) / 4;k <= (ssize_t)(n / zrev - 1) / 4; k++)
    {
        sum1 += cephes_normal(((4 * k + 1) * zrev) / sqrt(n));
        sum1 -= cephes_normal(((4 * k - 1) * zrev) / sqrt(n));
    }
    sum2 = 0.0;
    for (k = ((ssize_t)-n / zrev - 3) / 4; k <= (ssize_t)(n / zrev - 1) / 4;
         k++)
    {
        sum2 += cephes_normal(((4 * k + 3) * zrev) / sqrt(n));
        sum2 -= cephes_normal(((4 * k + 1) * zrev) / sqrt(n));
    }
    p_value = 1.0 - sum1 + sum2;

    if (P2)
        *P2 = p_value;

    if (p_value < alpha)
        return 0;

    return 1;
}

/*
 * 近似熵检测, Approximate Entropy Test
 */
int rand_self_test_approximate_entropy(const unsigned char *buf, size_t nbit,
                                       size_t m, double *P)
{
    size_t block;
    size_t n, i, j, k, r;
    double sum, ApEn[2], apen, V, p_value;
    size_t *C;

    n = nbit;
    r = 0;

    for (block = m; block <= m + 1; block++) {
        if (block == 0) {
            ApEn[0] = 0.00;
            r++;
        } else {
            if ((C = (size_t *)OPENSSL_zalloc(pow(2, block) * sizeof(size_t)))
                    == NULL)
                return 0;

            for (i = 0; i < nbit; i++) {
                k = 0;
                for (j = 0; j < block; j++) {
                    k <<= 1;
                    if (get_bit(buf, (i + j) % n) == 1)
                        k++;
                }
                C[k]++;
            }

            sum = 0.0;
            for (i = 0; i < (size_t)pow(2, block); i++) {
                if (C[i] > 0)
                    sum += C[i] * log((double)C[i] / n);
            }
            ApEn[r] = sum / n;
            r++;
            OPENSSL_free(C);
        }
    }

    apen = ApEn[0] - ApEn[1];
    V = 2.0 * n * (log(2) - apen);
    p_value = cephes_igamc(pow(2, m - 1), V / 2.0);

    if (P)
        *P = p_value;

    return p_value >= alpha;
}

/*
 * 线性复杂度检测, Linear Complexity Test
 */
int rand_self_test_linear_complexity(const unsigned char *buf, size_t nbit,
                                     size_t M, double *P_value)
{
    size_t n = nbit, i, ii, j, d, N, L, N_, parity, K = 6;
    int m, sign;
    double p_value, T_, mean, nu[7], V = 0.0;
    double pi[7] = {0.010417, 0.031250, 0.125, 0.500,
                    0.250, 0.062500, 0.020833};
    size_t *T = NULL, *P = NULL, *B_ = NULL, *C = NULL;

    N = n / M;
    if (((B_ = OPENSSL_malloc(M * sizeof(size_t))) == NULL)
        || ((C = OPENSSL_malloc(M * sizeof(size_t))) == NULL)
        || ((P = OPENSSL_malloc(M * sizeof(size_t))) == NULL)
        || ((T = OPENSSL_malloc(M * sizeof(size_t))) == NULL)) {
        if (B_ != NULL)
            OPENSSL_free(B_);
        if (C != NULL)
            OPENSSL_free(C);
        if (P != NULL)
            OPENSSL_free(P);
        if (T != NULL)
            OPENSSL_free(T);
        return 0;
    }

    for (i = 0; i < K + 1; i++)
        nu[i] = 0.00;
    for (ii = 0; ii < N; ii++) {
        for (i = 0; i < M; i++) {
            B_[i] = 0;
            C[i] = 0;
            T[i] = 0;
            P[i] = 0;
        }
        L = 0;
        m = -1;
        d = 0;
        C[0] = 1;
        B_[0] = 1;
        N_ = 0;
        while (N_ < M) {
            d = get_bit(buf, ii * M + N_);
            for (i = 1; i <= L; i++)
                d += C[i] * get_bit(buf, ii * M + N_ - i);
            d = d % 2;
            if (d == 1) {
                for (i = 0; i < M; i++) {
                    T[i] = C[i];
                    P[i] = 0;
                }
                for (j = 0; j < M; j++)
                    if (B_[j] == 1)
                        P[j + N_ - m] = 1;
                for (i = 0; i < M; i++)
                    C[i] = (C[i] + P[i]) % 2;
                if (L <= N_ / 2) {
                    L = N_ + 1 - L;
                    m = N_;
                    for (i = 0; i < M; i++)
                        B_[i] = T[i];
                }
            }
            N_++;
        }
        if ((parity = (M + 1) % 2) == 0)
            sign = -1;
        else
            sign = 1;
        mean = M / 2.0 + (9.0 + sign) / 36.0
               - 1.0 / pow(2, M) * (M / 3.0 + 2.0 / 9.0);
        if ((parity = M % 2) == 0)
            sign = 1;
        else
            sign = -1;
        T_ = sign * (L - mean) + 2.0 / 9.0;

        if (T_ <= -2.5)
            nu[0]++;
        else if (T_ > -2.5 && T_ <= -1.5)
            nu[1]++;
        else if (T_ > -1.5 && T_ <= -0.5)
            nu[2]++;
        else if (T_ > -0.5 && T_ <= 0.5)
            nu[3]++;
        else if (T_ > 0.5 && T_ <= 1.5)
            nu[4]++;
        else if (T_ > 1.5 && T_ <= 2.5)
            nu[5]++;
        else
            nu[6]++;
    }

    for (i = 0; i < K + 1; i++)
        V += pow(nu[i] - N * pi[i], 2) / (N * pi[i]);

    p_value = cephes_igamc(3, V / 2.0);

    if (P_value)
        *P_value = p_value;

    OPENSSL_free(B_);
    OPENSSL_free(P);
    OPENSSL_free(C);
    OPENSSL_free(T);

    return p_value >= alpha;
}

/*
 * Maurer通用统计检测，Maurer's "Universal Statistical" Test
 */
int rand_self_test_maurer_universal_statistical(const unsigned char *buf,
                                                size_t nbit, double *P)
{
    size_t n = nbit, i, j, t, L, Q, K;
    double sigma, V, sum, p_value, c;
    size_t *T;
    double expected_value[17] = {
        0,         0,         0,         0,         0,         0,
        5.2177052, 6.1962507, 7.1836656, 8.1764248, 9.1723243, 10.170032,
        11.168765, 12.168070, 13.167693, 14.167488, 15.167379};
    double variance[17] = {0,     0,     0,     0,     0,     0,
                           2.954, 3.125, 3.238, 3.311, 3.356, 3.384,
                           3.401, 3.410, 3.416, 3.419, 3.421};

    /*
     * THE FOLLOWING REDEFINES L, SHOULD THE CONDITION: n >= 1010*2^L*L
     * NOT BE MET, FOR THE BLOCK LENGTH L.
     */
    L = 5;
    if (n >= 387840)
        L = 6;
    if (n >= 904960)
        L = 7;
    if (n >= 2068480)
        L = 8;
    if (n >= 4654080)
        L = 9;
    if (n >= 10342400)
        L = 10;
    if (n >= 22753280)
        L = 11;
    if (n >= 49643520)
        L = 12;
    if (n >= 107560960)
        L = 13;
    if (n >= 231669760)
        L = 14;
    if (n >= 496435200)
        L = 15;
    if (n >= 1059061760)
        L = 16;

    Q = 10 * (size_t)pow(2, L);
    K = n / L - Q;

    if ((T = OPENSSL_zalloc(pow(2, L) * sizeof(size_t))) == NULL) {
        return 0;
    }

    /* COMPUTE THE EXPECTED:  Formula 16, in Marsaglia's Paper */
    c = 0.7 - 0.8 / L + (4 + 32 / (double)L) * pow(K, -3 / (double)L) / 15;
    sigma = c * sqrt(variance[L] / (double)K);
    sum = 0.0;

    for (i = 1; i <= Q; i++) {
        j = 0;
        for (t = 0; t < L; t++) {
            j <<= 1;
            if (get_bit(buf, (i - 1) * L + t))
                j++;
        }
        T[j] = i;
    }
    for (i = Q + 1; i <= Q + K; i++) {
        j = 0;
        for (t = 0; t < L; t++) {
            j <<= 1;
            if (get_bit(buf, (i - 1) * L + t))
                j++;
        }
        sum += log2(i - T[j]);
        T[j] = i;
    }

    V = (sum / (double)K - expected_value[L]) / sigma;
    p_value = erfc(fabs(V) / sqrt(2));

    if (P)
        *P = p_value;

    OPENSSL_free(T);

    return p_value >= alpha;
}

/*
 * 离散傅里叶检测, Discrete Fourier Transform (Spectral) Test
 */
int rand_self_test_discrete_fourier_transform(const unsigned char *buf,
                                              size_t nbit, double *P)
{
    size_t n = nbit, i, count;
    double p_value, T, N1, N0, V;
    double *m = NULL, *X = NULL, *wsave = NULL;
    int ifac[15];

    if (((X = OPENSSL_zalloc((n + 1) * sizeof(double))) == NULL)
        || ((wsave = OPENSSL_zalloc(2 * n * sizeof(double))) == NULL)
        || ((m = OPENSSL_zalloc((n / 2 + 1) * sizeof(double))) == NULL)) {
        if (X != NULL)
            OPENSSL_free(X);
        if (wsave != NULL)
            OPENSSL_free(wsave);
        if (m != NULL)
            OPENSSL_free(m);
        return 0;
    }

    for (i = 0; i < n; i++)
        X[i] = 2 * get_bit(buf, i) - 1;

    /* INITIALIZE WORK ARRAYS */
    __ogg_fdrffti(n, wsave, ifac);
    /* APPLY FORWARD FFT */
    __ogg_fdrfftf(n, X, wsave, ifac);

    m[0] = sqrt(X[0] * X[0]);
    for (i = 0; i < n / 2; i++)
        m[i + 1] = sqrt(pow(X[2 * i + 1], 2) + pow(X[2 * i + 2], 2));

    count = 0;
    T = sqrt(2.995732274 * n);

    for (i = 0; i < n / 2; i++)
        if (m[i] < T)
            count++;

    N1 = (double)count;
    N0 = 0.95 * n / 2.0;
    V = (N1 - N0) / sqrt(0.95 * 0.05 * n / 3.8);
    p_value = erfc(fabs(V) / sqrt(2.0));

    if (P)
        *P = p_value;

    OPENSSL_free(X);
    OPENSSL_free(wsave);
    OPENSSL_free(m);

    return p_value >= alpha;
}

int smtc_rand_delivery_test(OSSL_SELF_TEST *st, int sdf)
{
    int nbit = 1000000;
    unsigned char buf[nbit / 8];
    int fail[15] = {0};
    size_t i = 0, j, k;
    int retry = 1, res = 0;
    void *hDeviceHandle = NULL, *hSessionHandle = NULL;

    if (sdf)
        OSSL_SELF_TEST_onbegin(st, "Delivery_Test", "Randomness for device");
    else
        OSSL_SELF_TEST_onbegin(st, "Delivery_Test", "Randomness");

    if (sdf) {
        if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != 0)
            goto end;

        if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != 0)
            goto end;
    }

    while (i++ < 50) {
        if (sdf) {
            if (TSAPI_SDF_GenerateRandom(hSessionHandle, nbit / 8, buf) != 0)
                goto end;
        } else {
            if (RAND_bytes(buf, nbit / 8) != 1)
                goto end;
        }

        j = 0;
        fail[j++] += rand_self_test_frequency(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_block_frequency(buf, nbit, 10000, NULL) ^ 1;
        fail[j++] += rand_self_test_poker(buf, nbit, 8, NULL) ^ 1;
        fail[j++] += rand_self_test_serial(buf, nbit, 5, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_runs(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_runs_distribution(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_longest_run_of_ones(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_derivation(buf, nbit, 7, NULL) ^ 1;
        fail[j++] += rand_self_test_self_correlation(buf, nbit, 16, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_matrix_rank(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_cumulative_sums(buf, nbit, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_approximate_entropy(buf, nbit, 5, NULL) ^ 1;
        fail[j++] += rand_self_test_linear_complexity(buf, nbit, 1000, NULL) ^ 1;
        fail[j++] += rand_self_test_maurer_universal_statistical(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_discrete_fourier_transform(buf, nbit, NULL) ^ 1;

        for (k = 0; k < OSSL_NELEM(fail); k++) {
            if (fail[k] >= 3) {
                if (--retry < 0)
                    goto end;

                i = 0;
                memset(fail, 0, sizeof(fail));
                break;
            }
        }
    }

    res = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
    OSSL_SELF_TEST_onend(st, res);
    return 1;
}

int smtc_rand_poweron_test(OSSL_SELF_TEST *st, int sdf)
{
    int nbit = 1000000;
    unsigned char buf[nbit / 8];
    int fail[15] = {0};
    size_t i = 0, j, k;
    int retry = 1, res = 0;
    void *hDeviceHandle = NULL, *hSessionHandle = NULL;

    if (sdf)
        OSSL_SELF_TEST_onbegin(st, "Poweron_Test", "Randomness for device");
    else
        OSSL_SELF_TEST_onbegin(st, "Poweron_Test", "Randomness");

    if (sdf) {
        if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != 0)
            goto end;

        if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != 0)
            goto end;
    }

    while(i++ < 20) {
        if (sdf) {
            if (TSAPI_SDF_GenerateRandom(hSessionHandle, nbit / 8, buf) != 0)
                goto end;
        } else {
            if (RAND_bytes(buf, nbit / 8) != 1)
                goto end;
        }

        j = 0;
        fail[j++] += rand_self_test_frequency(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_block_frequency(buf, nbit, 10000, NULL) ^ 1;
        fail[j++] += rand_self_test_poker(buf, nbit, 8, NULL) ^ 1;
        fail[j++] += rand_self_test_serial(buf, nbit, 5, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_runs(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_runs_distribution(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_longest_run_of_ones(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_derivation(buf, nbit, 7, NULL) ^ 1;
        fail[j++] += rand_self_test_self_correlation(buf, nbit, 16, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_matrix_rank(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_cumulative_sums(buf, nbit, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_approximate_entropy(buf, nbit, 5, NULL) ^ 1;
        fail[j++] += rand_self_test_linear_complexity(buf, nbit, 1000, NULL) ^ 1;
        fail[j++] += rand_self_test_maurer_universal_statistical(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_discrete_fourier_transform(buf, nbit, NULL) ^ 1;

        for (k = 0; k < OSSL_NELEM(fail); k++) {
            if (fail[k] >= 2) {
                if (--retry < 0)
                    goto end;

                i = 0;
                memset(fail, 0, sizeof(fail));
                break;
            }
        }
    }

    res = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
    OSSL_SELF_TEST_onend(st, res);
    return 1;
}

int smtc_rand_cyclical_test(OSSL_SELF_TEST *st, int sdf)
{
    int nbit = 20000;
    unsigned char buf[nbit / 8];
    int fail[12] = {0};
    size_t i = 0, j, k;
    int retry = 1, res = 0;
    void *hDeviceHandle = NULL, *hSessionHandle = NULL;

    if (sdf)
        OSSL_SELF_TEST_onbegin(st, "Cyclical_Test", "Randomness for device");
    else
        OSSL_SELF_TEST_onbegin(st, "Cyclical_Test", "Randomness");

    while(i++ < 20) {
        if (sdf) {
            if (TSAPI_SDF_GenerateRandom(hSessionHandle, nbit / 8, buf) != 0)
                goto end;
        } else {
            if (RAND_bytes(buf, nbit / 8) != 1)
                goto end;
        }

        j = 0;

        fail[j++] += rand_self_test_frequency(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_block_frequency(buf, nbit, 1000, NULL) ^ 1;
        fail[j++] += rand_self_test_poker(buf, nbit, 8, NULL) ^ 1;
        fail[j++] += rand_self_test_serial(buf, nbit, 5, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_runs(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_runs_distribution(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_longest_run_of_ones(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_derivation(buf, nbit, 7, NULL) ^ 1;
        fail[j++] += rand_self_test_self_correlation(buf, nbit, 16, NULL) ^ 1;
        fail[j++] += rand_self_test_binary_matrix_rank(buf, nbit, NULL) ^ 1;
        fail[j++] += rand_self_test_cumulative_sums(buf, nbit, NULL, NULL) ^ 1;
        fail[j++] += rand_self_test_approximate_entropy(buf, nbit, 5, NULL) ^ 1;

        for (k = 0; k < OSSL_NELEM(fail); k++) {
            if (fail[k] >= 2) {
                if (--retry < 0)
                    goto end;

                i = 0;
                memset(fail, 0, sizeof(fail));
                break;
            }
        }
    }

    res = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
    OSSL_SELF_TEST_onend(st, res);
    return 1;
}

int smtc_rand_single_test(OSSL_SELF_TEST *st, int sdf)
{
    int nbit = 256;
    unsigned char buf[nbit / 8];
    int retry = 1, res = 0;
    void *hDeviceHandle = NULL, *hSessionHandle = NULL;

    if (sdf)
        OSSL_SELF_TEST_onbegin(st, "Single_Test", "Randomness for device");
    else
        OSSL_SELF_TEST_onbegin(st, "Single_Test", "Randomness");

    if (sdf) {
        if (TSAPI_SDF_OpenDevice(&hDeviceHandle) != 0)
            goto end;

        if (TSAPI_SDF_OpenSession(hDeviceHandle, &hSessionHandle) != 0)
            goto end;
    }

    do {
        if (sdf) {
            if (TSAPI_SDF_GenerateRandom(hSessionHandle, nbit / 8, buf) != 0)
                goto end;
        } else {
            if (RAND_bytes(buf, nbit / 8) != 1)
                goto end;
        }

        if (rand_self_test_poker(buf, nbit, 2, NULL) == 1)
            break;
        else
            retry--;
    } while (retry >= 0);

    res = 1;
end:
    TSAPI_SDF_CloseSession(hSessionHandle);
    TSAPI_SDF_CloseDevice(hDeviceHandle);
    OSSL_SELF_TEST_onend(st, res);
    return 1;
}
