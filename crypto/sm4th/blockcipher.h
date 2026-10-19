/*
 * blockcipher.h — SM4 (GB/T 32907-2016) and the tweakable counter-mode
 * PRG of SM4th_spec.pdf Clause 5.2.1/5.3.
 *
 * The ti setting (Ballet-256/256) is out of scope; this implementation
 * covers the in-scope parameter sets only, where E = SM4 and nb = 16.
 */
#ifndef SM4TH_BLOCKCIPHER_H
#define SM4TH_BLOCKCIPHER_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_BYTES 16
#define SM4_ROUNDS 32

/* WireSpace S-box (the map of Clause 7.1). */
uint8_t sm4_sbox(uint8_t u);

void sm4_key_expansion(const uint8_t key[16], uint32_t rk[36]);
/* z[i+4] = z[i] ^ L(SubWord(z[i+1]^z[i+2]^z[i+3]^rk[i+4])),
 * out = (z[35], z[34], z[33], z[32]) — Clause 5.2.1 e). */
void sm4_encrypt_block(const uint32_t rk[36], const uint8_t in[16], uint8_t out[16]);

/* one-shot: SM4_K(X) — Clause 5.2.1 */
void sm4_enc(const uint8_t K[16], const uint8_t X[16], uint8_t out[16]);

/* PRG — Clause 5.3:  tweak added to the *last* four octets of the IV
 * (LE32, mod 2^32), block counter added to the *first* four octets;
 * output m octets of E_sd(X_i).  In scope: E = SM4, nb = niv = 16. */
void sm4th_prg(const uint8_t *sd, const uint8_t *iv, uint64_t tweak,
              uint8_t *out, size_t m_octets);

#endif /* SM4TH_BLOCKCIPHER_H */
