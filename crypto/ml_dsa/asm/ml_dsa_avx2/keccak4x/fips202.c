#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fips202.h"

static void keccak_reset(KECCAK1600_CTX *ctx)
{
    memset(ctx->A, 0, sizeof(ctx->A));
    ctx->bufsz = 0;
    ctx->xof_state = XOF_STATE_INIT;
}

static void shake_init(keccak_state *state, size_t bitlen)
{
    (void)ossl_keccak_init(&state->ctx, 0x1f, bitlen, 0);
    keccak_reset(&state->ctx);
}

static void sha3_init(KECCAK1600_CTX *ctx, size_t bitlen)
{
    (void)ossl_sha3_init(ctx, 0x06, bitlen);
    keccak_reset(ctx);
}

void shake128_init(keccak_state *state)
{
    shake_init(state, 128);
}

void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
    (void)ossl_sha3_update(&state->ctx, in, inlen);
}

void shake128_finalize(keccak_state *state)
{
    (void)state;
}

void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    (void)ossl_sha3_squeeze(&state->ctx, out, nblocks * SHAKE128_RATE);
}

void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    (void)ossl_sha3_squeeze(&state->ctx, out, outlen);
}

void shake256_init(keccak_state *state)
{
    shake_init(state, 256);
}

void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
{
    (void)ossl_sha3_update(&state->ctx, in, inlen);
}

void shake256_finalize(keccak_state *state)
{
    (void)state;
}

void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
{
    (void)ossl_sha3_squeeze(&state->ctx, out, nblocks * SHAKE256_RATE);
}

void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
{
    (void)ossl_sha3_squeeze(&state->ctx, out, outlen);
}

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    keccak_state state;

    shake128_init(&state);
    shake128_absorb(&state, in, inlen);
    shake128_squeeze(out, outlen, &state);
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    keccak_state state;

    shake256_init(&state);
    shake256_absorb(&state, in, inlen);
    shake256_squeeze(out, outlen, &state);
}

void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
{
    KECCAK1600_CTX ctx;

    sha3_init(&ctx, 256);
    (void)ossl_sha3_update(&ctx, in, inlen);
    (void)ossl_sha3_final(&ctx, h, 32);
}

void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
{
    KECCAK1600_CTX ctx;

    sha3_init(&ctx, 512);
    (void)ossl_sha3_update(&ctx, in, inlen);
    (void)ossl_sha3_final(&ctx, h, 64);
}
