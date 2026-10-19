/*
 * blockcipher.c — SM4 and the PRG, per Clauses 5.2.1/5.3 of
 * SM4th_spec.pdf (revision 4). Block encryption and the PRG use the
 * Tongsuo SM4 backend. Witness construction uses the standard S-box
 * table and exposes the round states needed by the constraint system.
 */
#include <openssl/e_os2.h>
#include "blockcipher.h"
#include "crypto/sm4.h"
#include "sm4th_params.h"

#include <openssl/crypto.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SM4                                                                 */
/* ------------------------------------------------------------------ */

/* Standard SM4 S-box (GB/T 32907), also used in crypto/sm4/sm4.c.
 * A local copy exposes byte substitutions for the witness state trace.
 */
static const uint8_t SM4_S[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48
};

uint8_t
sm4_sbox(uint8_t u)
{
    return SM4_S[u];
}

static ossl_inline uint32_t subword(uint32_t w)
{
    return ((uint32_t)sm4_sbox((uint8_t)(w >> 24)) << 24)
         | ((uint32_t)sm4_sbox((uint8_t)(w >> 16)) << 16)
         | ((uint32_t)sm4_sbox((uint8_t)(w >> 8)) << 8)
         | (uint32_t)sm4_sbox((uint8_t)w);
}

static ossl_inline uint32_t rol32(uint32_t x, unsigned n)
{
    return n ? ((x << n) | (x >> (32 - n))) : x;
}

static ossl_inline uint32_t L_sm4(uint32_t b)
{
    return b ^ rol32(b, 2) ^ rol32(b, 10) ^ rol32(b, 18) ^ rol32(b, 24);
}

static ossl_inline uint32_t Lp_sm4(uint32_t b)
{
    return b ^ rol32(b, 13) ^ rol32(b, 23);
}

static const uint32_t SM4_FK[4] = {
    0xA3B1BAC6u, 0x56AA3350u, 0x677D9197u, 0xB27022DCu,
};

static uint32_t sm4_ck(unsigned i)
{
    /* byte j of CK_i is (4i+j)*7 mod 256 — Clause 5.2.1 c) */
    return ((uint32_t)((4 * i + 0) * 7 % 256) << 24)
         | ((uint32_t)((4 * i + 1) * 7 % 256) << 16)
         | ((uint32_t)((4 * i + 2) * 7 % 256) << 8)
         | (uint32_t)((4 * i + 3) * 7 % 256);
}

void
sm4_key_expansion(const uint8_t key[16], uint32_t rk[36])
{
    uint32_t k[4];
    int i;

    for (i = 0; i < 4; i++)
        k[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16)
             | ((uint32_t)key[4 * i + 2] << 8) | (uint32_t)key[4 * i + 3];

    for (i = 0; i < 4; i++)
        rk[i] = k[i] ^ SM4_FK[i];
    for (i = 0; i < 32; i++)
        rk[i + 4] = rk[i] ^ Lp_sm4(subword(rk[i + 1] ^ rk[i + 2] ^ rk[i + 3]
                                          ^ sm4_ck((unsigned)i)));
    OPENSSL_cleanse(k, sizeof(k));
}

void
sm4_encrypt_block(const uint32_t rk[36], const uint8_t in[16], uint8_t out[16])
{
    uint32_t z[40];
    int i;

    for (i = 0; i < 4; i++)
        z[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16)
             | ((uint32_t)in[4 * i + 2] << 8) | (uint32_t)in[4 * i + 3];

    for (i = 0; i < 32; i++)
        z[i + 4] = z[i] ^ L_sm4(subword(z[i + 1] ^ z[i + 2] ^ z[i + 3]
                                        ^ rk[i + 4]));

    for (i = 0; i < 4; i++) {
        out[4 * i]     = (uint8_t)(z[35 - i] >> 24);
        out[4 * i + 1] = (uint8_t)(z[35 - i] >> 16);
        out[4 * i + 2] = (uint8_t)(z[35 - i] >> 8);
        out[4 * i + 3] = (uint8_t)(z[35 - i]);
    }
    OPENSSL_cleanse(z, sizeof(z));
}

void
sm4_enc(const uint8_t K[16], const uint8_t X[16], uint8_t out[16])
{
    SM4_KEY ks;

    ossl_sm4_set_key(K, &ks);
    ossl_sm4_encrypt(X, out, &ks);
    OPENSSL_cleanse(&ks, sizeof(ks));
}

/* ------------------------------------------------------------------ */
/* PRG — Clause 5.3                                                    */
/* ------------------------------------------------------------------ */

void
sm4th_prg(const uint8_t *sd, const uint8_t *iv, uint64_t tweak,
         uint8_t *out, size_t m_octets)
{
    uint8_t ivp[SM4TH_NIV];
    uint8_t block[SM4TH_NB], encrypted[SM4TH_NB];
    SM4_KEY ks;
    uint32_t base_ctr, tweak32;

    if (m_octets == 0)
        return;

    /* iv' = iv[0,niv-4) || LE32(LE32^{-1}(iv[niv-4,niv)) + twk mod 2^32) */
    {
        uint32_t v;
        memcpy(ivp, iv, SM4TH_NIV);
        tweak32 = (uint32_t)tweak;
        v = ((uint32_t)ivp[SM4TH_NIV - 4])
          | ((uint32_t)ivp[SM4TH_NIV - 3] << 8)
          | ((uint32_t)ivp[SM4TH_NIV - 2] << 16)
          | ((uint32_t)ivp[SM4TH_NIV - 1] << 24);
        v += tweak32;                    /* mod 2^32                       */
        ivp[SM4TH_NIV - 4] = (uint8_t)(v & 0xffu);
        ivp[SM4TH_NIV - 3] = (uint8_t)((v >> 8) & 0xffu);
        ivp[SM4TH_NIV - 2] = (uint8_t)((v >> 16) & 0xffu);
        ivp[SM4TH_NIV - 1] = (uint8_t)((v >> 24) & 0xffu);
        base_ctr = ((uint32_t)ivp[0]) | ((uint32_t)ivp[1] << 8)
                 | ((uint32_t)ivp[2] << 16) | ((uint32_t)ivp[3] << 24);
    }

    {
        size_t nblocks = m_octets / SM4TH_NB + (m_octets % SM4TH_NB != 0);
        size_t i;
        ossl_sm4_set_key(sd, &ks);
        for (i = 0; i < nblocks; i++) {
            uint32_t ctr = base_ctr + (uint32_t)i;
            size_t take = m_octets - i * SM4TH_NB;
            if (take > SM4TH_NB)
                take = SM4TH_NB;
            block[0] = (uint8_t)(ctr & 0xffu);
            block[1] = (uint8_t)((ctr >> 8) & 0xffu);
            block[2] = (uint8_t)((ctr >> 16) & 0xffu);
            block[3] = (uint8_t)((ctr >> 24) & 0xffu);
            memcpy(block + 4, ivp + 4, (size_t)(SM4TH_NIV - 4));
            ossl_sm4_encrypt(block, encrypted, &ks);
            memcpy(out + i * SM4TH_NB, encrypted, take);
        }
    }
    OPENSSL_cleanse(&ks, sizeof(ks));
    OPENSSL_cleanse(encrypted, sizeof(encrypted));
}
