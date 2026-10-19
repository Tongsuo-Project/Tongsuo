/*
 * sign.c — SM4th.KeyGen / Sign / Verify (Clauses 10-11 of SM4th_spec.pdf).
 * H2/H4 additionally bind the protocol domain from the Chinese spec v1.
 *
 * Structure:
 *   sign_ctx: scratch allocations shared by Sign/Verify;
 *   the message digest is streamed; fixed-size challenge transcripts
 *   use bounded staging buffers per Clause 10.5 and Table 3;
 *   the QuickSilver responses (10.3 l) and the verifier recomputation
 *   (10.4 l)) use d = 3 as written in the specification.
 */
#include "sign.h"
#include "uhash.h"
#include "sm4th_hash.h"

#include <openssl/rand.h>
#include <string.h>

int
sm4th_rand_default(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    if (!out || len == 0)
        return 0;
    return RAND_priv_bytes_ex(NULL, out, len, 0) == 1;
}

#define LAM SM4TH_LAMBDA_F
#define NF SM4TH_N_FIELDS
#define HATLB (SM4TH_ELL / 8 + 3 * NF + SM4TH_B / 8)
#define UHASH_OUT (NF + 2)
#define CHALL1_LEN ((5 * LAM + 64) / 8)
#define CHALL2_LEN ((3 * LAM + 64) / 8)
#define DEG 3

static owf_consts_t g_consts;
static int g_consts_ok = 0;

static CRYPTO_ONCE consts_once = CRYPTO_ONCE_STATIC_INIT;

static void init_consts_once(void)
{
    g_consts_ok = owf_consts_init(&g_consts) == 0;
}

static const owf_consts_t *
sm4th_consts(void)
{
    if (!CRYPTO_THREAD_run_once(&consts_once, init_consts_once) || !g_consts_ok)
        return NULL;
    return &g_consts;
}

static void
fe_store(uint8_t *dst, const fe_t *x)
{
    memcpy(dst, x->b, (size_t)NF);
}

static void
fe_load(fe_t *x, const uint8_t *src)
{
    fe_from_bytes(x, src, NF);
}

/* v*_j = sum_{i<lambdaF} ToField(V| ell + j*lambdaF + i) * z^i (10.3 k) */
static void
rowpack_weighted(const uint8_t *cols, unsigned row0, fe_t *out)
{
    fe_t acc, zpow, zz, rowel;
    unsigned i;

    fe_zero(&acc);
    fe_zero(&zz);
    zz.b[0] = 2;                    /* the generator z                   */
    fe_zero(&zpow);
    zpow.b[0] = 1;                  /* z^0                               */
    for (i = 0; i < LAM; i++) {
        fe_t term;
        owf_row_to_field(cols, (uint64_t)(row0 + i), &rowel);
        gf_mul(&term, &rowel, &zpow, LAM);
        fe_xor(&acc, &term);
        OPENSSL_cleanse(&term, sizeof(term));
        {
            fe_t t;
            gf_mul(&t, &zpow, &zz, LAM);
            fe_set(&zpow, &t);
        }
    }
    fe_set(out, &acc);
    OPENSSL_cleanse(&acc, sizeof(acc));
    OPENSSL_cleanse(&rowel, sizeof(rowel));
}

/* ------------------------------------------------------------------ */
/* KeyGen                                                               */
/* ------------------------------------------------------------------ */
int
sm4th_core_keygen(const sm4th_params_t *p, sm4th_rand_fn rnd, void *rndctx,
             uint8_t sk[32], uint8_t pk[32])
{
    uint8_t k[16], x[16], y[16];
    int rc = -1;

    (void)p;
    if (rnd == NULL || sk == NULL || pk == NULL)
        return -1;
    /* I-19, repair (i): reject keys violating w[0]*w[1]=0, where
     * w[0],w[1] are bits 0,1 of octet 0 of k0 ^ FK0.  FK0 = A3B1BAC6,
     * octet 0 (of the big-endian word) is A3 whose low two bits are
     * (1,1); hence w[0]=k[0]_0^1, w[1]=k[0]_1^1 and the constraint
     * fails exactly when both low bits of k[0] are 0.                */
    /* Reject-sample only k; then sample x once (matches SM4th.KeyGen). */
    for (;;) {
        if (!rnd(rndctx, k, 16))
            goto out;
        /* accept iff (w0,w1) != (1,1), i.e. (k[0]^0xA3)&3 != 3        */
        if (((uint8_t)(k[0] ^ 0xA3u) & 3u) != 3u)
            break;
    }
    if (!rnd(rndctx, x, 16))
        goto out;
    sm4_enc(k, x, y);
    memcpy(sk, x, 16);
    memcpy(sk + 16, k, 16);
    memcpy(pk, x, 16);
    memcpy(pk + 16, y, 16);
    rc = 0;
out:
    OPENSSL_cleanse(k, sizeof(k));
    OPENSSL_cleanse(x, sizeof(x));
    OPENSSL_cleanse(y, sizeof(y));
    return rc;
}

/* ------------------------------------------------------------------ */
/* Shared scratch                                                        */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t *u;          /* hat_lbytes                                */
    uint8_t *cols;       /* lambdaF * hat_lbytes (V or Q)               */
    uint8_t *scratch;    /* 2^12 * hat_lbytes + 12 * hat_lbytes        */
    uint8_t *c[SM4TH_MAX_TAU]; /* c[1..tau-1]                           */
    uint8_t *decomI;     /* ldecom                                     */
    bavc_t tree;
    int have_tree;
    uint8_t com[32];
    uint8_t mu[32];
    uint8_t chall1[CHALL1_LEN];
    uint8_t chall2[CHALL2_LEN];
    uint8_t chall3[NF];
    uint8_t utilde[UHASH_OUT];
    uint8_t dw[SM4TH_ELL_BYTES];
    /* ã responses / recomputations                                     */
    fe_t at[DEG];
} sm4th_ctx_t;

static int
ctx_alloc(sm4th_ctx_t *c, const sm4th_params_t *p)
{
    unsigned i;
    memset(c, 0, sizeof(*c));
    c->u = (uint8_t *)OPENSSL_malloc(HATLB);
    c->cols = (uint8_t *)OPENSSL_malloc((size_t)LAM * HATLB);
    c->scratch = (uint8_t *)OPENSSL_malloc((size_t)4096 * HATLB + 12 * HATLB);
    c->decomI = (uint8_t *)OPENSSL_malloc(p->ldecom);
    if (!c->u || !c->cols || !c->scratch || !c->decomI)
        return -1;
    for (i = 0; i < p->tau; i++) {
        if (i == 0) { c->c[i] = NULL; continue; }
        c->c[i] = (uint8_t *)OPENSSL_malloc(HATLB);
        if (!c->c[i])
            return -1;
    }
    return 0;
}

static void
ctx_free(sm4th_ctx_t *c, const sm4th_params_t *p)
{
    unsigned i;
    for (i = 0; i < p->tau; i++)
        OPENSSL_clear_free(c->c[i], HATLB);
    OPENSSL_clear_free(c->u, HATLB);
    OPENSSL_clear_free(c->cols, (size_t)LAM * HATLB);
    OPENSSL_clear_free(c->scratch, (size_t)(4096 + 12) * HATLB);
    OPENSSL_clear_free(c->decomI, p->ldecom);
    if (c->have_tree)
        bavc_free(&c->tree);
    OPENSSL_cleanse(c, sizeof(*c));
}

/* mu = H4(D_p || pk || msg); D_p binds family, version and parameter set. */
static int
hash_mu(EVP_MD_CTX *hctx, const EVP_MD *md,
        const sm4th_params_t *p,
        const uint8_t pk[32], const uint8_t *msg, size_t msg_len,
        uint8_t mu[32])
{
    static const uint8_t ds = 0x08;

    /* Stream D_p || pk || msg || ds without a message-sized staging copy. */
    return EVP_DigestInit_ex2(hctx, md, NULL) == 1
        && EVP_DigestUpdate(hctx, p->domain, sizeof(p->domain)) == 1
        && EVP_DigestUpdate(hctx, pk, 32) == 1
        && (msg_len == 0 || EVP_DigestUpdate(hctx, msg, msg_len) == 1)
        && EVP_DigestUpdate(hctx, &ds, 1) == 1
        && EVP_DigestSqueeze(hctx, mu, 32) == 1;
}

/* chall1 = H2_1(mu||com||c_1..||iv)                                      */
static int
hash_chall1(EVP_MD_CTX *hctx, const EVP_MD *md,
            const sm4th_params_t *p, const uint8_t mu[32],
            const uint8_t com[32], uint8_t **cbufs,
            const uint8_t iv[SM4TH_NIV], uint8_t *chall1)
{
    unsigned q;
    size_t off = 0;
    size_t need = 32 + 32 + (size_t)(p->tau - 1) * HATLB + SM4TH_NIV;
    uint8_t *buf = (uint8_t *)OPENSSL_malloc(need);
    if (!buf)
        return -1;
    memcpy(buf + off, mu, 32); off += 32;
    memcpy(buf + off, com, 32); off += 32;
    for (q = 1; q < p->tau; q++) {
        if (!cbufs[q]) { OPENSSL_clear_free(buf, need); return -1; }
        memcpy(buf + off, cbufs[q], HATLB); off += HATLB;
    }
    memcpy(buf + off, iv, SM4TH_NIV); off += SM4TH_NIV;
    if (off != need) { OPENSSL_clear_free(buf, need); return -1; }
    if (!sm4th_hash_H(hctx, md, buf, off, 0x09, CHALL1_LEN, chall1)) {
        OPENSSL_clear_free(buf, need);
        return -1;
    }
    OPENSSL_clear_free(buf, need);
    return 0;
}

/* chall2 = H2_2(chall1||utilde||V[c]||dw)                                   */
static int
hash_chall2(EVP_MD_CTX *hctx, const EVP_MD *md,
            const uint8_t chall1[CHALL1_LEN], const uint8_t utilde[UHASH_OUT],
            const uint8_t *vtilde /* lambdaF x UHASH_OUT */,
            const uint8_t dw[SM4TH_ELL_BYTES], uint8_t *chall2)
{
    unsigned c;
    size_t off = 0;
    size_t need = (size_t)CHALL1_LEN + UHASH_OUT
                + (size_t)LAM * UHASH_OUT + SM4TH_ELL_BYTES;
    uint8_t *buf = (uint8_t *)OPENSSL_malloc(need);
    if (!buf)
        return -1;
    memcpy(buf + off, chall1, CHALL1_LEN); off += CHALL1_LEN;
    memcpy(buf + off, utilde, UHASH_OUT); off += UHASH_OUT;
    for (c = 0; c < LAM; c++) {
        memcpy(buf + off, vtilde + (size_t)c * UHASH_OUT, UHASH_OUT);
        off += UHASH_OUT;
    }
    memcpy(buf + off, dw, SM4TH_ELL_BYTES); off += SM4TH_ELL_BYTES;
    if (off != need) { OPENSSL_clear_free(buf, need); return -1; }
    if (!sm4th_hash_H(hctx, md, buf, off, 0x0A, CHALL2_LEN, chall2)) {
        OPENSSL_clear_free(buf, need);
        return -1;
    }
    OPENSSL_clear_free(buf, need);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Sign                                                                  */
/* ------------------------------------------------------------------ */
int
sm4th_core_sign(const sm4th_params_t *p, const EVP_MD *shake128_md,
           const uint8_t *msg, size_t msg_len,
           const uint8_t sk[32],
           const uint8_t seed[32],
           uint8_t *sigma)
{
    unsigned col, i, q, j;
    const owf_consts_t *K = sm4th_consts();
    const uint8_t *x = sk;
    const uint8_t *k = sk != NULL ? sk + 16 : NULL;
    sm4th_ctx_t c;
    EVP_MD_CTX *hctx = NULL;
    uint8_t pk[32];
    uint8_t zbuf[32];
    uint8_t r[SM4TH_NB], iv[SM4TH_NIV];
    uint8_t w[SM4TH_ELL_BYTES];
    fe_t a_coef[DEG][SM4TH_C_ENTRIES];
    owf_ctx_t ctx;
    uint8_t *vtilde = NULL;
    uint32_t ctr = 0;
    int rc = -1;

    if (!K || p == NULL || shake128_md == NULL || sk == NULL
        || seed == NULL || sigma == NULL || (msg == NULL && msg_len != 0)
        || !sm4th_key_is_valid(k))
        return -1;
    if (msg_len > SM4TH_MAX_MSG)
        return -1;
    hctx = EVP_MD_CTX_new();
    if (hctx == NULL)
        return -1;

    /* pk = x || SM4.Enc(k, x); Sign takes sk only                      */
    memcpy(pk, x, 16);
    sm4_enc(k, x, pk + 16);

    if (ctx_alloc(&c, p) != 0)
        goto out;

    /* a) mu = H4(D_p || x || y || msg)                                 */
    if (!hash_mu(hctx, shake128_md, p, pk, msg, msg_len, c.mu))
        goto out;

    /* b) Z = H2(D_p || k || mu || seed) -> r, ivpre                    */
    {
        uint8_t buf[SM4TH_DOMAIN_BYTES + 80];
        int hash_ok;

        memcpy(buf, p->domain, SM4TH_DOMAIN_BYTES);
        memcpy(buf + SM4TH_DOMAIN_BYTES, k, 16);
        memcpy(buf + SM4TH_DOMAIN_BYTES + 16, c.mu, 32);
        memcpy(buf + SM4TH_DOMAIN_BYTES + 48, seed, 32);
        hash_ok = sm4th_hash_H(hctx, shake128_md, buf, sizeof(buf),
                               0x03, 32, zbuf);
        OPENSSL_cleanse(buf, sizeof(buf));
        if (!hash_ok)
            goto out;
        memcpy(r, zbuf, SM4TH_NB);        /* ivpre stays at zbuf+16..32   */
    }
    /* c) iv                                                            */
    if (!sm4th_hash_H(hctx, shake128_md, zbuf + SM4TH_NB, SM4TH_NIV,
                      0x04, SM4TH_NIV, iv))
        goto out;

    /* d) VOLECommit — leaves c.tree with all seeds                     */
    if (bavc_init(&c.tree, p) != 0)
        goto out;
    c.have_tree = 1;
    if (vole_commit(p, shake128_md, r, iv, c.com, c.c, c.u, c.cols, &c.tree,
                    c.scratch) != 0)
        goto out;

    /* e) chall1                                                        */
    if (hash_chall1(hctx, shake128_md, p, c.mu, c.com, c.c, iv, c.chall1) != 0)
        goto out;

    /* f) utilde and the column hashes                                  */
    vtilde = (uint8_t *)OPENSSL_malloc((size_t)LAM * UHASH_OUT);
    if (!vtilde)
        goto out;
    vole_hash(c.chall1, c.u, c.utilde);
    for (col = 0; col < LAM; col++)
        vole_hash(c.chall1, c.cols + (size_t)col * HATLB,
                  vtilde + (size_t)col * UHASH_OUT);

    /* g)-h) witness and dw                                             */
    owf_extend_witness(K, k, x, w);
    for (i = 0; i < SM4TH_ELL_BYTES; i++)
        c.dw[i] = (uint8_t)(w[i] ^ c.u[i]);

    /* i) chall2                                                        */
    if (hash_chall2(hctx, shake128_md, c.chall1, c.utilde, vtilde, c.dw,
                    c.chall2) != 0)
        goto out;

    /* j) constraints (prover side)                                     */
    memset(&ctx, 0, sizeof(ctx));
    ctx.p = p;
    ctx.consts = K;
    ctx.mode = OWF_PROVER;
    ctx.w = w;
    ctx.v_cols = c.cols;
    ctx.dw = NULL;
    ctx.q_cols = NULL;
    ctx.a = a_coef;
    ctx.b = NULL;
    if (owf_constraints(&ctx, pk, pk + 16) != 0)
        goto out;

    /* k)-l) masks and responses                                        */
    {
        fe_t us0, us1, vs0, vs1;
        fe_load(&us0, c.u + SM4TH_ELL_BYTES);
        fe_load(&us1, c.u + SM4TH_ELL_BYTES + NF);
        rowpack_weighted(c.cols, SM4TH_ELL, &vs0);
        rowpack_weighted(c.cols, SM4TH_ELL + LAM, &vs1);

        {
            fe_t v1_plus_u0;
            fe_add(&v1_plus_u0, &vs1, &us0);
            zk_hash(c.chall2, a_coef[0], SM4TH_C_ENTRIES, vs0, &c.at[0]);
            zk_hash(c.chall2, a_coef[1], SM4TH_C_ENTRIES, v1_plus_u0,
                    &c.at[1]);
            zk_hash(c.chall2, a_coef[2], SM4TH_C_ENTRIES, us1, &c.at[2]);
            OPENSSL_cleanse(&v1_plus_u0, sizeof(v1_plus_u0));
        }
        OPENSSL_cleanse(&us0, sizeof(us0));
        OPENSSL_cleanse(&us1, sizeof(us1));
        OPENSSL_cleanse(&vs0, sizeof(vs0));
        OPENSSL_cleanse(&vs1, sizeof(vs1));
    }

    /* m) grinding                                                      */
    {
        unsigned delta[SM4TH_MAX_TAU];
        uint8_t hbuf[CHALL2_LEN + 3 * NF + 4];
        size_t off = 0;

        memcpy(hbuf + off, c.chall2, CHALL2_LEN); off += CHALL2_LEN;
        fe_store(hbuf + off, &c.at[0]); off += NF;
        fe_store(hbuf + off, &c.at[1]); off += NF;
        fe_store(hbuf + off, &c.at[2]); off += NF;
        /* ctr bytes appended per iteration                              */

        for (ctr = 0; ; ctr++) {
            uint8_t buf[CHALL2_LEN + 3 * NF + 4];
            memcpy(buf, hbuf, off);
            buf[off] = (uint8_t)(ctr & 0xff);
            buf[off + 1] = (uint8_t)((ctr >> 8) & 0xff);
            buf[off + 2] = (uint8_t)((ctr >> 16) & 0xff);
            buf[off + 3] = (uint8_t)((ctr >> 24) & 0xff);
            if (!sm4th_hash_H(hctx, shake128_md, buf, off + 4, 0x0B, NF,
                              c.chall3))
                goto out;

            if (decode_chall(p, c.chall3, delta) == 0) {
                int opened = bavc_open(&c.tree, delta, c.decomI);
                if (opened == 0)
                    break;
                if (opened != -1)
                    goto out;
            }
            if (ctr == 0xffffffffu)
                goto out;
        }
    }

    /* n) serialisation (Table 17)                                      */
    {
        size_t off = 0;
        for (q = 1; q < p->tau; q++) {
            memcpy(sigma + off, c.c[q], HATLB);
            off += HATLB;
        }
        memcpy(sigma + off, c.utilde, UHASH_OUT); off += UHASH_OUT;
        memcpy(sigma + off, c.dw, SM4TH_ELL_BYTES); off += SM4TH_ELL_BYTES;
        for (j = 1; j < DEG; j++) {
            fe_store(sigma + off, &c.at[j]);
            off += NF;
        }
        memcpy(sigma + off, c.decomI, p->ldecom); off += p->ldecom;
        memcpy(sigma + off, c.chall3, NF); off += NF;
        memcpy(sigma + off, zbuf + SM4TH_NB, SM4TH_NIV); /* ivpre */
        off += SM4TH_NIV;
        sigma[off] = (uint8_t)(ctr & 0xff);
        sigma[off + 1] = (uint8_t)((ctr >> 8) & 0xff);
        sigma[off + 2] = (uint8_t)((ctr >> 16) & 0xff);
        sigma[off + 3] = (uint8_t)((ctr >> 24) & 0xff);
        off += 4;
        if (off != p->sig_len) {
            rc = -1;
            goto out;
        }
    }
    rc = 0;

out:
    OPENSSL_clear_free(vtilde, (size_t)LAM * UHASH_OUT);
    OPENSSL_cleanse(w, sizeof(w));
    OPENSSL_cleanse(r, sizeof(r));
    OPENSSL_cleanse(zbuf, sizeof(zbuf));
    OPENSSL_cleanse(a_coef, sizeof(a_coef));
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    ctx_free(&c, p);
    EVP_MD_CTX_free(hctx);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Verify                                                                */
/* ------------------------------------------------------------------ */
int
sm4th_core_verify(const sm4th_params_t *p, const EVP_MD *shake128_md,
             const uint8_t *msg, size_t msg_len,
             const uint8_t *pk, size_t pk_len,
             const uint8_t *sigma, size_t sigma_len)
{
    unsigned wb, col, byte_idx;
    const owf_consts_t *K = sm4th_consts();
    const uint8_t *pk_x, *pk_y, *ivpre;
    sm4th_ctx_t c;
    EVP_MD_CTX *hctx = NULL;
    size_t off = 0;
    uint8_t iv[SM4TH_NIV];
    unsigned q;

    if (!K || p == NULL || shake128_md == NULL || sigma == NULL
        || (msg == NULL && msg_len != 0))
        return 0;
    hctx = EVP_MD_CTX_new();
    if (hctx == NULL)
        return 0;
    /* V-0: |sigma| = L_sigma, |pk| = 32, |msg| <= 2^60 */
    if (sigma_len != (size_t)p->sig_len) {
        EVP_MD_CTX_free(hctx);
        return 0;
    }
    if (pk == NULL || pk_len != 32) {
        EVP_MD_CTX_free(hctx);
        return 0;
    }
    if (msg_len > SM4TH_MAX_MSG) {
        EVP_MD_CTX_free(hctx);
        return 0;
    }
    pk_x = pk;
    pk_y = pk + 16;

    if (ctx_alloc(&c, p) != 0) {
        goto reject;
    }

    /* b) parse                                                          */
    for (q = 1; q < p->tau; q++) {
        if (c.c[q]) memcpy(c.c[q], sigma + off, HATLB);
        off += HATLB;
    }
    memcpy(c.utilde, sigma + off, UHASH_OUT); off += UHASH_OUT;
    memcpy(c.dw, sigma + off, SM4TH_ELL_BYTES); off += SM4TH_ELL_BYTES;
    {
        fe_t at1, at2;
        fe_load(&at1, sigma + off); off += NF;
        fe_load(&at2, sigma + off); off += NF;
        fe_set(&c.at[1], &at1);
        fe_set(&c.at[2], &at2);
    }
    memcpy(c.decomI, sigma + off, p->ldecom);
    off += p->ldecom;
    memcpy(c.chall3, sigma + off, NF); off += NF;
    ivpre = sigma + off; off += SM4TH_NIV;
    off += 4;
    if (off != (size_t)p->sig_len)
        goto reject;                    /* parsing invariant            */

    /* V-1 grinding bits                                                  */
    {
        unsigned bad = 0;
        for (wb = LAM - p->wgrind; wb < LAM; wb++)
            if ((c.chall3[wb >> 3] >> (wb & 7)) & 1u)
                bad = 1;
        if (bad) {
            goto reject;
        }
    }

    /* c) mu  d) iv                                                      */
    if (!hash_mu(hctx, shake128_md, p, pk, msg, msg_len, c.mu))
        goto reject;
    if (!sm4th_hash_H(hctx, shake128_md, ivpre, SM4TH_NIV, 0x04, SM4TH_NIV, iv))
        goto reject;

    /* f) VOLEReconstruct — V-2                                         */
    if (bavc_init(&c.tree, p) != 0) {
        goto reject;
    }
    c.have_tree = 1;
    if (vole_reconstruct(p, shake128_md, c.chall3, c.decomI, c.c, iv,
                         c.com, c.cols, &c.tree, c.scratch) != 0) {
        goto reject;
    }

    /* g) chall1 (over the recomputed com)                              */
    if (hash_chall1(hctx, shake128_md, p, c.mu, c.com, c.c, iv, c.chall1) != 0) {
        goto reject;
    }

    /* h) Vtilde'_c = Qtilde_c xor (bit c of chall3 ? utilde : 0)       */
    {
        uint8_t *qtilde = (uint8_t *)OPENSSL_malloc((size_t)LAM * UHASH_OUT);
        if (!qtilde)
            goto reject;
        for (col = 0; col < LAM; col++)
            vole_hash(c.chall1, c.cols + (size_t)col * HATLB,
                      qtilde + (size_t)col * UHASH_OUT);
        for (col = 0; col < LAM; col++) {
            if ((c.chall3[col >> 3] >> (col & 7)) & 1u) {
                for (byte_idx = 0; byte_idx < UHASH_OUT; byte_idx++)
                    qtilde[(size_t)col * UHASH_OUT + byte_idx] ^= c.utilde[byte_idx];
            }
        }

        /* i) chall2                                                     */
        if (hash_chall2(hctx, shake128_md, c.chall1, c.utilde, qtilde, c.dw,
                        c.chall2) != 0) {
            OPENSSL_clear_free(qtilde, (size_t)LAM * UHASH_OUT);
            goto reject;
        }
        OPENSSL_clear_free(qtilde, (size_t)LAM * UHASH_OUT);
    }

    /* j) constraints (verifier side)                                   */
    {
        fe_t b_entries[SM4TH_C_ENTRIES];
        owf_ctx_t ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.p = p;
        ctx.consts = K;
        ctx.mode = OWF_VERIFIER;
        ctx.w = NULL;
        ctx.v_cols = NULL;
        ctx.dw = c.dw;
        ctx.q_cols = c.cols;
        ctx.a = NULL;
        ctx.b = b_entries;
        fe_load(&ctx.delta, c.chall3);      /* Delta = ToField(chall3)  */
        if (owf_constraints(&ctx, pk_x, pk_y) != 0) {
            goto reject;
        }

        /* k) q* = q*_0 + q*_1 * Delta  (10.4 k))                        */
        {
            fe_t qs0, qs1, qstar, dpow, t;
            rowpack_weighted(c.cols, SM4TH_ELL, &qs0);
            rowpack_weighted(c.cols, SM4TH_ELL + LAM, &qs1);
            gf_mul(&t, &qs1, &ctx.delta, LAM);
            fe_add(&qstar, &qs0, &t);
            (void)dpow;

           /* l) atilde'_0 = ZKHash(chall2, (b, q*)) +
             *      atilde_1*Delta + atilde_2*Delta^2                    */
            {
                fe_t zk, at0p, d2, term1, term2;
                zk_hash(c.chall2, b_entries, SM4TH_C_ENTRIES, qstar, &zk);
                gf_mul(&term1, &c.at[1], &ctx.delta, LAM);
                dpow = ctx.delta;
                gf_mul(&d2, &ctx.delta, &dpow, LAM);
                gf_mul(&term2, &c.at[2], &d2, LAM);
                fe_add(&at0p, &zk, &term1);
                fe_add(&at0p, &at0p, &term2);

                /* m) recompute chall3' and compare (V-3)                 */
                {
                    uint8_t hbuf[CHALL2_LEN + 3 * NF + 4];
                    size_t off2 = 0;
                    uint8_t chall3p[NF];
                    unsigned diff = 0, k;

                    memcpy(hbuf + off2, c.chall2, CHALL2_LEN);
                    off2 += CHALL2_LEN;
                    fe_store(hbuf + off2, &at0p); off2 += NF;
                    fe_store(hbuf + off2, &c.at[1]); off2 += NF;
                    fe_store(hbuf + off2, &c.at[2]); off2 += NF;
                    memcpy(hbuf + off2, sigma + (p->sig_len - 4), 4);
                    off2 += 4;
                    if (!sm4th_hash_H(hctx, shake128_md, hbuf, off2, 0x0B, NF,
                                      chall3p))
                        goto reject;

                    for (k = 0; k < NF; k++)
                        diff |= (unsigned)(chall3p[k] ^ c.chall3[k]);
                    if (diff)
                        goto reject;
                }
            }
        }
    }

    ctx_free(&c, p);
    EVP_MD_CTX_free(hctx);
    return 1;

reject:
    ctx_free(&c, p);
    EVP_MD_CTX_free(hctx);
    return 0;
}
