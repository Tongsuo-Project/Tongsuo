#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "ml_dsa_local.h"
#include "ml_dsa_polyvec.h"

#define pack_pk ML_DSA_NAMESPACE(pack_pk)
void pack_pk(uint8_t pk[ML_DSA_PUBLICKEYBYTES], const uint8_t rho[ML_DSA_SEEDBYTES], const polyveck *t1);

#define pack_sk ML_DSA_NAMESPACE(pack_sk)
void pack_sk(uint8_t sk[ML_DSA_SECRETKEYBYTES],
             const uint8_t rho[ML_DSA_SEEDBYTES],
             const uint8_t tr[ML_DSA_TRBYTES],
             const uint8_t key[ML_DSA_SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

#define pack_sig ML_DSA_NAMESPACE(pack_sig)
void pack_sig(uint8_t sig[ML_DSA_SIGBYTES], const uint8_t c[ML_DSA_CTILDEBYTES], const polyvecl *z, const polyveck *h);

#define unpack_pk ML_DSA_NAMESPACE(unpack_pk)
void unpack_pk(uint8_t rho[ML_DSA_SEEDBYTES], polyveck *t1, const uint8_t pk[ML_DSA_PUBLICKEYBYTES]);

#define unpack_sk ML_DSA_NAMESPACE(unpack_sk)
void unpack_sk(uint8_t rho[ML_DSA_SEEDBYTES],
               uint8_t tr[ML_DSA_TRBYTES],
               uint8_t key[ML_DSA_SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[ML_DSA_SECRETKEYBYTES]);

#define unpack_sig ML_DSA_NAMESPACE(unpack_sig)
int unpack_sig(uint8_t c[ML_DSA_CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[ML_DSA_SIGBYTES]);

#endif
