#include <stdint.h>
#include "params.h"
#include "sign.h"

#include <stdio.h>
#include <string.h>

#include "fips202x4.h"
#include "hybrid.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "keccak4x/symmetric.h"
#include "keccak4x/fips202.h"
#include "pspm.h"
#include "rejsample.h"
#include "ntt/ntt.h"

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    unsigned int i;
    ALIGN(32) uint8_t seedbuf[2* SEEDBYTES + CRHBYTES];
    ALIGN(32) uint8_t tr[CRHBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl s1;
    polyvecl rowbuf[2];
    polyvecl *row = rowbuf;
    polyveck s2;
    poly t1, t0;

    /* Get randomness for rho, rhoprime and key */
    randombytes(seedbuf, SEEDBYTES);
    shake256(seedbuf, 2* SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES);
    rho = seedbuf;
    rhoprime = seedbuf + SEEDBYTES;
    key = seedbuf + SEEDBYTES + CRHBYTES;

    /* Store rho, key */
    for (i = 0; i < SEEDBYTES; ++i) pk[i] = rho[i];
    for (i = 0; i < SEEDBYTES; ++i) sk[i] = rho[i];
    for (i = 0; i < SEEDBYTES; ++i) sk[SEEDBYTES + i] = key[i];

    /* Sample short vectors s1 and s2 and Pack secret vectors*/
    ExpandS_with_pack(&s1, &s2, sk + 2 * SEEDBYTES + CRHBYTES, (uint64_t *) rhoprime);

    /* Transform s1 */
    polyvecl_ntt_bo(&s1);

    for (i = 0; i < K; i++) {
        /* Expand matrix row */
        ExpandA_row(&row, rowbuf, rho, i);

        /* Compute inner-product */
        polyvecl_pointwise_acc_montgomery(&t1, row, &s1);
        poly_intt_bo(&t1);

        /* Add error polynomial */
        poly_add(&t1, &t1, &s2.vec[i]);

        /* Round t and pack t1, t0 */
        poly_caddq(&t1);
        poly_power2round(&t1, &t0, &t1);
        polyt1_pack(pk + SEEDBYTES + i * POLYT1_PACKEDBYTES, &t1);
        polyt0_pack(sk + 2 * SEEDBYTES + CRHBYTES + (L + K) * POLYETA_PACKEDBYTES + i * POLYT0_PACKEDBYTES, &t0);
    }

    /* Compute CRH(rho, t1) and store in secret key */
    crh(tr, pk, CRYPTO_PUBLICKEYBYTES);
    for (i = 0; i < CRHBYTES; ++i) sk[2 * SEEDBYTES + i] = tr[i];

    return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig: pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    unsigned int i, j, n, pos;
    ALIGN(32) uint8_t seedbuf[3 * SEEDBYTES + 2 * CRHBYTES];
    uint8_t *rho, *tr, *key, *mu, *rhoprime, *rnd;
    uint8_t *hint = sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES;
    uint64_t nonce = 0;
    polyvecl mat[K], y, z;
    polyveck t0, w1, w0, tmp;
    poly h, c;
    sword s1list[L][3 * N];
    sword s2list[K][3 * N];
    uint8_t *buf = (uint8_t *) malloc(CRHBYTES + mlen);
    if (buf == NULL) return 1;

    loop_queue loop;
    loop.start = 0;
    loop.size = 0;

    tr = buf;
    rho = seedbuf;
    key = rho + SEEDBYTES;
    rnd = key + SEEDBYTES;
    mu = rnd + SEEDBYTES;
    rhoprime = mu + CRHBYTES;
    unpack_sk(rho, tr, key, &t0, s1list, s2list, sk);
    memcpy(buf + CRHBYTES, m, mlen);
    randombytes(rnd, SEEDBYTES);

    hybrid_hash_ExpandA_shuffled(mu, CRHBYTES, buf, CRHBYTES + mlen, &mat[0].vec[0], &mat[0].vec[1], &mat[0].vec[2], rho, 0,
                                 1, 2);
    crh(rhoprime, key, SEEDBYTES + SEEDBYTES + CRHBYTES);

    ExpandA_shuffled_part(mat, rho, &loop, rhoprime, nonce);
#if K==4 || K==8
    nonce += 3;
#elif K==6
    nonce++;
#endif

    int count = 0;
rej:
    /* Sample intermediate vector y */
    while (loop.size < L) {
        poly_generate_random_gamma1_4x(&loop, rhoprime, nonce, nonce + 1, nonce + 2, nonce + 3);
        nonce += 4;
        count++;
    }
    for (i = 0; i < L; ++i) polyz_unpack(&y.vec[i], loop_dequeue(&loop));

    /* Save y and transform it */
    z = y;
    polyvecl_ntt_so(&y);

    for (i = 0; i < K; i++) {
        /* Compute inner-product */
        polyvecl_pointwise_acc_montgomery(&w1.vec[i], &mat[i], &y);
        poly_intt_so_avx2(&w1.vec[i]);

        /* Decompose w and use sig as temporary buffer for packed w1 */
        poly_caddq(&w1.vec[i]);
        poly_decompose(&w1.vec[i], &w0.vec[i], &w1.vec[i]);
        polyw1_pack(sig + i * POLYW1_PACKEDBYTES, &w1.vec[i]);
    }
    /* Call the random oracle */
    hybrid_challenge_and_ExpandRand_x3(sig, mu, sig, &loop, rhoprime, nonce);
    nonce += 3;

    poly_challenge(&c, sig);

    /* Check that subtracting cs2 does not change high bits of w and low bits
     * do not reveal secret information */
    for (i = 0; i < K; i++) {
        poly_emulate_cs(&h, &c, s2list[i]);
        poly_sub(&w0.vec[i], &w0.vec[i], &h);
        if (poly_chknorm(&w0.vec[i], GAMMA2 - BETA)) goto rej;
    }

    /* Compute z, reject if it reveals secret */
    for (i = 0; i < L; i++) {
        poly_emulate_cs(&h, &c, s1list[i]);
        poly_add(&z.vec[i], &z.vec[i], &h);
        if (poly_chknorm(&z.vec[i], GAMMA1 - BETA)) goto rej;
    }

    /* Zero hint in signature */
    n = pos = 0;
    memset(hint, 0, OMEGA);

    for (i = 0; i < K; i++) {
        poly_emulate_ct(&tmp.vec[i], &c, &t0.vec[i]);
        if (poly_chknorm(&tmp.vec[i], GAMMA2)) goto rej;
    }

    /* Compute hints */
    for (i = 0; i < K; i++) {
        poly_add(&w0.vec[i], &w0.vec[i], &tmp.vec[i]);
        poly_caddq(&w0.vec[i]);
        n += poly_make_hint(&tmp.vec[i], &w0.vec[i], &w1.vec[i]);
        if (n > OMEGA) goto rej;
    }

    /* Pack z into signature */
    for (i = 0; i < L; i++) polyz_pack(sig + CTILDEBYTES + i * POLYZ_PACKEDBYTES, &z.vec[i]);

    for (i = 0; i < K; i++) {
        /* Store hints in signature */
        for (j = 0; j < N; ++j) if (tmp.vec[i].coeffs[j] != 0) hint[pos++] = j;
        hint[OMEGA + i] = pos;
    }

    *siglen = CRYPTO_BYTES;
    free(buf);
    return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    size_t i;

    for (i = 0; i < mlen; ++i) sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
    *smlen += mlen;
    return 0;
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    unsigned int i, j, pos = 0;
    ALIGN(32) uint8_t buf[K * POLYW1_PACKEDBYTES];
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    const uint8_t *hint = sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES;
    polyvecl z;
    poly cp, w1, t1, h;
    keccak_state state;
    polyvecl mat[K];
    const uint8_t *rho = pk;
    if (siglen != CRYPTO_BYTES) return -1;
    hybrid_hash_pk_and_ExpandA(mu, pk, mat, rho);
    hybrid_ExpandA_and_hashof_mu_and_challenge(mat, rho, mu, mu, m, mlen, &cp, sig);

    poly_ntt_bo(&cp);

    /* Unpack z; shortness follows from unpacking */
    polyvecl_unpack_z(&z, sig);
    polyvecl_ntt_bo(&z);
    for (i = 0; i < K; i++) {
        /* Compute i-th row of Az - c2^Dt1 */
        polyvecl_pointwise_acc_montgomery(&w1, &mat[i], &z);

        polyt1_unpack(&t1, pk + SEEDBYTES + i * POLYT1_PACKEDBYTES);
        poly_shiftl(&t1);
        poly_ntt_bo(&t1);
        poly_pointwise_montgomery(&t1, &cp, &t1);

        poly_sub(&w1, &w1, &t1);
        poly_reduce(&w1);
        poly_intt_bo(&w1);

        /* Get hint polynomial and reconstruct w1 */
        memset(h.vec, 0, sizeof(poly));

        if (hint[OMEGA + i] < pos || hint[OMEGA + i] > OMEGA) return -1;

        for (j = pos; j < hint[OMEGA + i]; ++j) {
            /* Coefficients are ordered for strong unforgeability */
            if (j > pos && hint[j] <= hint[j - 1]) return -1;
            h.coeffs[hint[j]] = 1;
        }
        pos = hint[OMEGA + i];

        poly_caddq(&w1);
        poly_use_hint(&w1, &w1, &h);
        polyw1_pack(buf + i * POLYW1_PACKEDBYTES, &w1);
    }
    /* Extra indices are zero for strong unforgeability */
    for (j = pos; j < OMEGA; ++j) if (hint[j]) return -1;

    /* Call random oracle and verify challenge */
    shake256_init(&state);
    shake256_absorb(&state, mu, CRHBYTES);
    shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
    shake256_finalize(&state);
    shake256_squeeze(c, CTILDEBYTES, &state);
    for (i = 0; i < CTILDEBYTES; ++i) if (c[i] != sig[i]) return -1;


    return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk) {
    size_t i;

    if (smlen < CRYPTO_BYTES) goto badsig;

    *mlen = smlen - CRYPTO_BYTES;
    if (crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk)) goto badsig;
    else {
        /* All good, copy msg, return 0 */
        for (i = 0; i < *mlen; ++i) m[i] = sm[CRYPTO_BYTES + i];
        return 0;
    }

badsig:
    /* Signature verification failed */
    *mlen = -1;
    for (i = 0; i < smlen; ++i) m[i] = 0;

    return -1;
}
