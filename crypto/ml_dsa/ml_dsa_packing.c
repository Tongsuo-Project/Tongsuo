#include "ml_dsa_local.h"
#include "ml_dsa_packing.h"
#include "ml_dsa_polyvec.h"
#include "ml_dsa_poly.h"

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/
void pack_pk(uint8_t pk[ML_DSA_PUBLICKEYBYTES],
             const uint8_t rho[ML_DSA_SEEDBYTES],
             const polyveck *t1)
{
  unsigned int i;

  for(i = 0; i < ML_DSA_SEEDBYTES; ++i)
    pk[i] = rho[i];
  pk += ML_DSA_SEEDBYTES;

  for(i = 0; i < ML_DSA_K; ++i)
    polyt1_pack(pk + i*POLYT1_PACKEDBYTES, &t1->vec[i]);
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
void unpack_pk(uint8_t rho[ML_DSA_SEEDBYTES],
               polyveck *t1,
               const uint8_t pk[ML_DSA_PUBLICKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < ML_DSA_SEEDBYTES; ++i)
    rho[i] = pk[i];
  pk += ML_DSA_SEEDBYTES;

  for(i = 0; i < ML_DSA_K; ++i)
    polyt1_unpack(&t1->vec[i], pk + i*POLYT1_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/
void pack_sk(uint8_t sk[ML_DSA_SECRETKEYBYTES],
             const uint8_t rho[ML_DSA_SEEDBYTES],
             const uint8_t tr[ML_DSA_TRBYTES],
             const uint8_t key[ML_DSA_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2)
{
  unsigned int i;

  for(i = 0; i < ML_DSA_SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += ML_DSA_SEEDBYTES;

  for(i = 0; i < ML_DSA_SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += ML_DSA_SEEDBYTES;

  for(i = 0; i < ML_DSA_TRBYTES; ++i)
    sk[i] = tr[i];
  sk += ML_DSA_TRBYTES;

  for(i = 0; i < ML_DSA_L; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += ML_DSA_L*POLYETA_PACKEDBYTES;

  for(i = 0; i < ML_DSA_K; ++i)
    polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += ML_DSA_K*POLYETA_PACKEDBYTES;

  for(i = 0; i < ML_DSA_K; ++i)
    polyt0_pack(sk + i*POLYT0_PACKEDBYTES, &t0->vec[i]);
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
void unpack_sk(uint8_t rho[ML_DSA_SEEDBYTES],
               uint8_t tr[ML_DSA_TRBYTES],
               uint8_t key[ML_DSA_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[ML_DSA_SECRETKEYBYTES])
{
  unsigned int i;

  for(i = 0; i < ML_DSA_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += ML_DSA_SEEDBYTES;

  for(i = 0; i < ML_DSA_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += ML_DSA_SEEDBYTES;

  for(i = 0; i < ML_DSA_TRBYTES; ++i)
    tr[i] = sk[i];
  sk += ML_DSA_TRBYTES;

  for(i=0; i < ML_DSA_L; ++i)
    polyeta_unpack(&s1->vec[i], sk + i*POLYETA_PACKEDBYTES);
  sk += ML_DSA_L*POLYETA_PACKEDBYTES;

  for(i=0; i < ML_DSA_K; ++i)
    polyeta_unpack(&s2->vec[i], sk + i*POLYETA_PACKEDBYTES);
  sk += ML_DSA_K*POLYETA_PACKEDBYTES;

  for(i=0; i < ML_DSA_K; ++i)
    polyt0_unpack(&t0->vec[i], sk + i*POLYT0_PACKEDBYTES);
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length ML_DSA_SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
void pack_sig(uint8_t sig[ML_DSA_SIGBYTES],
              const uint8_t c[ML_DSA_CTILDEBYTES],
              const polyvecl *z,
              const polyveck *h)
{
  unsigned int i, j, k;

  for(i=0; i < ML_DSA_CTILDEBYTES; ++i)
    sig[i] = c[i];
  sig += ML_DSA_CTILDEBYTES;

  for(i = 0; i < ML_DSA_L; ++i)
    polyz_pack(sig + i*POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += ML_DSA_L*POLYZ_PACKEDBYTES;

  /* Encode h */
  for(i = 0; i < ML_DSA_OMEGA + ML_DSA_K; ++i)
    sig[i] = 0;

  k = 0;
  for(i = 0; i < ML_DSA_K; ++i) {
    for(j = 0; j < ML_DSA_N; ++j)
      if(h->vec[i].coeffs[j] != 0)
        sig[k++] = j;

    sig[ML_DSA_OMEGA + i] = k;
  }
}

/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
int unpack_sig(uint8_t c[ML_DSA_CTILDEBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[ML_DSA_SIGBYTES])
{
  unsigned int i, j, k;

  for(i = 0; i < ML_DSA_CTILDEBYTES; ++i)
    c[i] = sig[i];
  sig += ML_DSA_CTILDEBYTES;

  for(i = 0; i < ML_DSA_L; ++i)
    polyz_unpack(&z->vec[i], sig + i*POLYZ_PACKEDBYTES);
  sig += ML_DSA_L*POLYZ_PACKEDBYTES;

  /* Decode h */
  k = 0;
  for(i = 0; i < ML_DSA_K; ++i) {
    for(j = 0; j < ML_DSA_N; ++j)
      h->vec[i].coeffs[j] = 0;

    if(sig[ML_DSA_OMEGA + i] < k || sig[ML_DSA_OMEGA + i] > ML_DSA_OMEGA)
      return 1;

    for(j = k; j < sig[ML_DSA_OMEGA + i]; ++j) {
      /* Coefficients are ordered for strong unforgeability */
      if(j > k && sig[j] <= sig[j-1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }

    k = sig[ML_DSA_OMEGA + i];
  }

  /* Extra indices are zero for strong unforgeability */
  for(j = k; j < ML_DSA_OMEGA; ++j)
    if(sig[j])
      return 1;

  return 0;
}
