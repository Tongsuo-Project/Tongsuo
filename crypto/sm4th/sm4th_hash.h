/*
 * sm4th_hash.h — SHAKE128 helpers for SM4th H_1..H_7
 * (same style as crypto/ml_dsa/ml_dsa_hash.h).
 *
 * H_i(M) = SHAKE128(M || ds_i; n_i) per sm4th_sf_spec.
 */
#ifndef SM4TH_HASH_H
# define SM4TH_HASH_H

# include <openssl/evp.h>
# include <stddef.h>
# include <stdint.h>

/* Absorb |in|, squeeze |out_len| (XOF). */
static ossl_inline ossl_unused int
shake_xof(EVP_MD_CTX *ctx, const EVP_MD *md,
          const uint8_t *in, size_t in_len,
          uint8_t *out, size_t out_len)
{
    return EVP_DigestInit_ex2(ctx, md, NULL) == 1
        && (in_len == 0 || EVP_DigestUpdate(ctx, in, in_len) == 1)
        && EVP_DigestSqueeze(ctx, out, out_len) == 1;
}

/*
 * Domain-separated H_i: absorb |msg| then |separator|, squeeze |n_out|.
 * Separators match the spec table (0x01/0x03/0x04/0x08/0x09/0x0A/0x0B).
 */
static ossl_inline ossl_unused int
sm4th_hash_H(EVP_MD_CTX *ctx, const EVP_MD *md,
             const uint8_t *msg, size_t msg_len,
             uint8_t separator, size_t n_out, uint8_t *out)
{
    return EVP_DigestInit_ex2(ctx, md, NULL) == 1
        && (msg_len == 0 || EVP_DigestUpdate(ctx, msg, msg_len) == 1)
        && EVP_DigestUpdate(ctx, &separator, 1) == 1
        && EVP_DigestSqueeze(ctx, out, n_out) == 1;
}

#endif /* SM4TH_HASH_H */
