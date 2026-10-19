/*
 * sm4th_params.c — parameter-set tables (Clause 12 of SM4th_spec.pdf rev.4).
 *
 * In scope: the two non-EM sets (SM4th-s, SM4th-f).
 */
#include "params.h"

#include <string.h>
#include <openssl/crypto.h>

static sm4th_params_t g_sets[SM4TH_NUM_SETS];
static CRYPTO_ONCE params_once = CRYPTO_ONCE_STATIC_INIT;

static void
sm4th_params_init(sm4th_params_t *p, const char *name,
                  const uint8_t domain[SM4TH_DOMAIN_BYTES], unsigned tau,
                  unsigned wgrind, unsigned topen)
{
    unsigned i;

    memset(p, 0, sizeof(*p));
    p->name = name;
    memcpy(p->domain, domain, sizeof(p->domain));
    p->tau = tau;
    p->wgrind = wgrind;
    p->topen = topen;

    /* Clause 12.2: k = floor((lambdaF - wgrind)/tau) + 1,
     * tau1 = (lambdaF - wgrind) mod tau, tau0 = tau - tau1.           */
    p->k_max = (SM4TH_LAMBDA_F - wgrind) / tau + 1;
    p->tau1 = (SM4TH_LAMBDA_F - wgrind) % tau;
    p->tau0 = tau - p->tau1;

    p->leaves = 0;
    {
        unsigned o = 0;
        for (i = 0; i < tau; i++) {
            p->ki[i] = (i < p->tau1) ? p->k_max : (p->k_max - 1);
            p->ni[i] = 1u << p->ki[i];      /* ki <= 12 for both sets   */
            p->oi[i] = o;
            o += p->ki[i];
            p->leaves += p->ni[i];
        }
    }

    p->hat_ell = SM4TH_ELL + SM4TH_DEGREE * SM4TH_LAMBDA_F + SM4TH_B;
    p->hat_lbytes = p->hat_ell / 8;         /* 2208/8 = 276           */
    p->ldecom = (2 * tau + topen) * SM4TH_NB;

    /* Table 17: L_sigma = (tau*hat_ell + (2*tau+topen)*Nblock
     *                      + lambdaF + lambda_iv + 32)/8             */
    p->sig_len = (tau * p->hat_ell + (2 * tau + topen) * SM4TH_NBLOCK
                  + SM4TH_LAMBDA_F + SM4TH_LAMBDA_IV + 32) / 8;

    p->variant_d3 = 1;
}

uint64_t
sm4th_leaves_L(const sm4th_params_t *p)
{
    return p->leaves;
}

uint64_t
sm4th_nodes_total(const sm4th_params_t *p)
{
    return 2 * (uint64_t)p->leaves - 1;
}

uint64_t
sm4th_pos_in_tree(const sm4th_params_t *p, unsigned i, uint64_t j)
{
    uint64_t L = p->leaves;
    unsigned k = p->k_max;

    /* Clause 5.5.1, Eq. (1) */
    if (j < ((uint64_t)1 << (k - 1))) {
        return L - 1 + (uint64_t)p->tau * j + i;
    }
    return L - 1 + (uint64_t)p->tau * ((uint64_t)1 << (k - 1))
           + (uint64_t)p->tau1 * ((j & (((uint64_t)1 << (k - 1)) - 1))) + i;
}

static void init_params_once(void)
{
    /* Chinese specification v1: exact ASCII octets, independent of aliases
     * and the execution character set; neither includes a NUL terminator. */
    static const uint8_t domains[2][SM4TH_DOMAIN_BYTES] = {
        {0x53, 0x4d, 0x34, 0x74, 0x68, 0x2d, 0x76, 0x31, 0x2f, 0x73},
        {0x53, 0x4d, 0x34, 0x74, 0x68, 0x2d, 0x76, 0x31, 0x2f, 0x66}
    };

    sm4th_params_init(&g_sets[0], "SM4th-s", domains[0], 11, 7, 102);
    sm4th_params_init(&g_sets[1], "SM4th-f", domains[1], 16, 8, 110);
}

const sm4th_params_t *
sm4th_params_get(int set_index)
{
    if (set_index < 0 || set_index >= SM4TH_NUM_SETS
        || !CRYPTO_THREAD_run_once(&params_once, init_params_once))
        return NULL;
    return &g_sets[set_index];
}

/* Tongsuo_bak-compatible accessors (F = fast, S = small). */
const sm4th_params_t *
sm4th_params_d3_f(void)
{
    return sm4th_params_get(1);
}

const sm4th_params_t *
sm4th_params_d3_s(void)
{
    return sm4th_params_get(0);
}
