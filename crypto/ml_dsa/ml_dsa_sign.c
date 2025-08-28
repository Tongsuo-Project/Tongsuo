#include <stdint.h>
#include <string.h>

#include <openssl/rand.h>

#include "ml_dsa_local.h"
#include "ml_dsa_packing.h"
#include "ml_dsa_polyvec.h"
#include "ml_dsa_poly.h"
#include "ml_dsa_symmetric.h"
#include "ml_dsa_fips202.h"

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of ML_DSA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of ML_DSA_SECRETKEYBYTES bytes)
*              - uint8_t *seed: pointer to input & output seed (allocated
*                             array of ML_DSA_SEEDBYTES bytes)
*              - int rand_seed: if 0, use the seed in *seed, otherwise
*                             generate a new random seed
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk, uint8_t *seed, int rand_seed) {
  uint8_t seedbuf[2*ML_DSA_SEEDBYTES + ML_DSA_CRHBYTES];
  uint8_t tr[ML_DSA_TRBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[ML_DSA_K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  /* Get randomness for rho, rhoprime and key */
  if (rand_seed)
    RAND_bytes(seed, ML_DSA_SEEDBYTES);
  memcpy(seedbuf, seed, ML_DSA_SEEDBYTES);
  seedbuf[ML_DSA_SEEDBYTES+0] = ML_DSA_K;
  seedbuf[ML_DSA_SEEDBYTES+1] = ML_DSA_L;
  shake256(seedbuf, 2*ML_DSA_SEEDBYTES + ML_DSA_CRHBYTES, seedbuf, ML_DSA_SEEDBYTES+2);
  rho = seedbuf;
  rhoprime = rho + ML_DSA_SEEDBYTES;
  key = rhoprime + ML_DSA_CRHBYTES;

  /* Expand matrix */
  polyvec_matrix_expand(mat, rho);

  /* Sample short vectors s1 and s2 */
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, ML_DSA_L);

  /* Matrix-vector multiplication */
  s1hat = s1;
  polyvecl_ntt(&s1hat);
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  polyveck_reduce(&t1);
  polyveck_invntt_tomont(&t1);

  /* Add error vector s2 */
  polyveck_add(&t1, &t1, &s2);

  /* Extract t1 and write public key */
  polyveck_caddq(&t1);
  polyveck_power2round(&t1, &t0, &t1);
  pack_pk(pk, rho, &t1);

  /* Compute H(rho, t1) and write secret key */
  shake256(tr, ML_DSA_TRBYTES, pk, ML_DSA_PUBLICKEYBYTES);
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

  return 0;
}

/*************************************************
* Name:        crypto_sign_signature_internal
*
* Description: Computes signature. Internal API.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length ML_DSA_SIGBYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *pre:   pointer to prefix string
*              - size_t prelen:  length of prefix string
*              - uint8_t *rnd:   pointer to random seed
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature_internal(uint8_t *sig,
                                   size_t *siglen,
                                   const uint8_t *mu,
                                   const uint8_t rnd[ML_DSA_RNDBYTES],
                                   const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[2*ML_DSA_SEEDBYTES + ML_DSA_TRBYTES + ML_DSA_CRHBYTES];
  uint8_t *rho, *tr, *key, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[ML_DSA_K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + ML_DSA_SEEDBYTES;
  key = tr + ML_DSA_TRBYTES;
  rhoprime = key + ML_DSA_SEEDBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute rhoprime = CRH(key, rnd, mu) */
  shake256_init(&state);
  shake256_absorb(&state, key, ML_DSA_SEEDBYTES);
  shake256_absorb(&state, rnd, ML_DSA_RNDBYTES);
  shake256_absorb(&state, mu, ML_DSA_CRHBYTES);
  shake256_finalize(&state);
  shake256_squeeze(rhoprime, ML_DSA_CRHBYTES, &state);

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, ML_DSA_CRHBYTES);
  shake256_absorb(&state, sig, ML_DSA_K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, ML_DSA_CTILDEBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, ML_DSA_GAMMA1 - ML_DSA_BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, ML_DSA_GAMMA2 - ML_DSA_BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, ML_DSA_GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > ML_DSA_OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = ML_DSA_SIGBYTES;
  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length ML_DSA_SIGBYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *ctx:   pointer to contex string
*              - size_t ctxlen:  length of contex string
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *ctx,
                          size_t ctxlen,
                          const int deterministic,
                          const uint8_t *sk)
{
  size_t i;
  uint8_t pre[ML_DSA_CONTEXT_STRING_BYTES+2];
  uint8_t rnd[ML_DSA_RNDBYTES];
  uint8_t seedbuf[2*ML_DSA_SEEDBYTES + ML_DSA_TRBYTES + ML_DSA_CRHBYTES];
  uint8_t *rho, *tr, *key, *mu;
  polyvecl s1;
  polyveck s2, t0;
  keccak_state state;

  if(ctxlen > ML_DSA_CONTEXT_STRING_BYTES)
    return -1;

  /* Prepare pre = (0, ctxlen, ctx) */
  pre[0] = 0;
  pre[1] = ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  rho = seedbuf;
  tr = rho + ML_DSA_SEEDBYTES;
  key = tr + ML_DSA_TRBYTES;
  mu = key + ML_DSA_SEEDBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute mu = CRH(tr, pre, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, ML_DSA_TRBYTES);
  shake256_absorb(&state, pre, 2+ctxlen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, ML_DSA_CRHBYTES, &state);

  if (deterministic) {
    for(i=0;i<ML_DSA_RNDBYTES;i++)
      rnd[i] = 0;
  }
  else {
    RAND_bytes(rnd, ML_DSA_RNDBYTES);
  }

  crypto_sign_signature_internal(sig,siglen,mu,rnd,sk);
  return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with ML_DSA_SIGBYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success) or -1 (context string too long)
**************************************************/
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *ctx,
                size_t ctxlen,
                const uint8_t *sk)
{
  int ret;
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[ML_DSA_SIGBYTES + mlen - 1 - i] = m[mlen - 1 - i];
  ret = crypto_sign_signature(sm, smlen, sm + ML_DSA_SIGBYTES, mlen, ctx, ctxlen, 0, sk);
  *smlen += mlen;
  return ret;
}

/*************************************************
* Name:        crypto_sign_verify_internal
*
* Description: Verifies signature. Internal API.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pre: pointer to prefix string
*              - size_t prelen: length of prefix string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify_internal(const uint8_t *sig,
                                size_t siglen,
                                const uint8_t *mu,
                                const uint8_t *pk)
{
  unsigned int i;
  uint8_t buf[ML_DSA_K*POLYW1_PACKEDBYTES];
  uint8_t rho[ML_DSA_SEEDBYTES];
  uint8_t c[ML_DSA_CTILDEBYTES];
  uint8_t c2[ML_DSA_CTILDEBYTES];
  poly cp;
  polyvecl mat[ML_DSA_K], z;
  polyveck t1, w1, h;
  keccak_state state;

  if(siglen != ML_DSA_SIGBYTES)
    return -1;

  unpack_pk(rho, &t1, pk);
  if(unpack_sig(c, &z, &h, sig))
    return -1;
  if(polyvecl_chknorm(&z, ML_DSA_GAMMA1 - ML_DSA_BETA))
    return -1;

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
  polyveck_use_hint(&w1, &w1, &h);
  polyveck_pack_w1(buf, &w1);

  /* Call random oracle and verify challenge */
  shake256_init(&state);
  shake256_absorb(&state, mu, ML_DSA_CRHBYTES);
  shake256_absorb(&state, buf, ML_DSA_K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, ML_DSA_CTILDEBYTES, &state);
  for(i = 0; i < ML_DSA_CTILDEBYTES; ++i)
    if(c[i] != c2[i])
      return -1;

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
*              - const uint8_t *ctx: pointer to context string
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t *pk)
{
  size_t i;
  uint8_t pre[ML_DSA_CONTEXT_STRING_BYTES+2];
  uint8_t mu[ML_DSA_CRHBYTES];
  keccak_state state;

  if(ctxlen > ML_DSA_CONTEXT_STRING_BYTES)
    return -1;

  pre[0] = 0;
  pre[1] = ctxlen;
  for(i = 0; i < ctxlen; i++)
    pre[2 + i] = ctx[i];

  /* Compute CRH(H(rho, t1), pre, msg) */
  shake256(mu, ML_DSA_TRBYTES, pk, ML_DSA_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, ML_DSA_TRBYTES);
  shake256_absorb(&state, pre, 2+ctxlen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, ML_DSA_CRHBYTES, &state);

  return crypto_sign_verify_internal(sig,siglen,mu,pk);
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
*              - const uint8_t *ctx: pointer to context tring
*              - size_t ctxlen: length of context string
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *ctx,
                     size_t ctxlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < ML_DSA_SIGBYTES)
    goto badsig;

  *mlen = smlen - ML_DSA_SIGBYTES;
  if(crypto_sign_verify(sm, ML_DSA_SIGBYTES, sm + ML_DSA_SIGBYTES, *mlen, ctx, ctxlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[ML_DSA_SIGBYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = 0;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
