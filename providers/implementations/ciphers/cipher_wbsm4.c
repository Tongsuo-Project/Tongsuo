/* Dispatch functions for cast cipher modes ecb, cbc, ofb, cfb */

#include "cipher_wbsm4.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

#ifndef OPENSSL_NO_WBSM4_XIAO_STKEY
static OSSL_FUNC_cipher_freectx_fn wbsm4_xiao_stkey_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_xiao_stkey_dupctx;

static void wbsm4_xiao_stkey_freectx(void *vctx)
{
    PROV_WBSM4_XIAO_STKEY_CTX *ctx = (PROV_WBSM4_XIAO_STKEY_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_xiao_stkey_dupctx(void *ctx)
{
    PROV_WBSM4_XIAO_STKEY_CTX *in = (PROV_WBSM4_XIAO_STKEY_CTX *)ctx;
    PROV_WBSM4_XIAO_STKEY_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_wbsm4_xiao_stkey128ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_xiao_stkey, WBSM4_XIAO_STKEY, ecb, ECB, 0, 128, 128, 0, block);
IMPLEMENT_generic_cipher(wbsm4_xiao_stkey, WBSM4_XIAO_STKEY, cbc, CBC, 0, 128, 128, 128, block);
IMPLEMENT_generic_cipher(wbsm4_xiao_stkey, WBSM4_XIAO_STKEY, ctr, CTR, 0, 128, 8, 128, stream);
IMPLEMENT_generic_cipher(wbsm4_xiao_stkey, WBSM4_XIAO_STKEY, ofb128, OFB, 0, 128, 8, 128, stream);
IMPLEMENT_generic_cipher(wbsm4_xiao_stkey, WBSM4_XIAO_STKEY, cfb128, CFB, 0, 128, 8, 128, stream);
#endif

#ifndef OPENSSL_NO_WBSM4_JIN_STKEY
static OSSL_FUNC_cipher_freectx_fn wbsm4_jin_stkey_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_jin_stkey_dupctx;

static void wbsm4_jin_stkey_freectx(void *vctx)
{
    PROV_WBSM4_JIN_STKEY_CTX *ctx = (PROV_WBSM4_JIN_STKEY_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_jin_stkey_dupctx(void *ctx)
{
    PROV_WBSM4_JIN_STKEY_CTX *in = (PROV_WBSM4_JIN_STKEY_CTX *)ctx;
    PROV_WBSM4_JIN_STKEY_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_wbsm4_jin_stkey128ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_jin_stkey, WBSM4_JIN_STKEY, ecb, ECB, 0, 128, 128, 0, block);
IMPLEMENT_generic_cipher(wbsm4_jin_stkey, WBSM4_JIN_STKEY, cbc, CBC, 0, 128, 128, 128, block);
IMPLEMENT_generic_cipher(wbsm4_jin_stkey, WBSM4_JIN_STKEY, ctr, CTR, 0, 128, 8, 128, stream);
IMPLEMENT_generic_cipher(wbsm4_jin_stkey, WBSM4_JIN_STKEY, ofb128, OFB, 0, 128, 8, 128, stream);
IMPLEMENT_generic_cipher(wbsm4_jin_stkey, WBSM4_JIN_STKEY, cfb128, CFB, 0, 128, 8, 128, stream);
#endif

#ifndef OPENSSL_NO_WBSM4_XIAO_DYKEY
static OSSL_FUNC_cipher_freectx_fn wbsm4_xiao_dykey_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_xiao_dykey_dupctx;

static void wbsm4_xiao_dykey_freectx(void *vctx)
{
    PROV_WBSM4_XIAO_DYKEY_CTX *ctx = (PROV_WBSM4_XIAO_DYKEY_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_xiao_dykey_dupctx(void *ctx)
{
    PROV_WBSM4_XIAO_DYKEY_CTX *in = (PROV_WBSM4_XIAO_DYKEY_CTX *)ctx;
    PROV_WBSM4_XIAO_DYKEY_CTX *ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}

/* ossl_wbsm4_xiao_dykey128ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, ecb, ECB, 0, 128, 128, 0, block);
IMPLEMENT_generic_cipher(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, cbc, CBC, 0, 128, 128, 128, block);
IMPLEMENT_generic_cipher(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, ctr, CTR, 0, 128, 8, 128, stream);
IMPLEMENT_generic_cipher(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, ofb128, OFB, 0, 128, 8, 128, stream);
IMPLEMENT_generic_cipher(wbsm4_xiao_dykey, WBSM4_XIAO_DYKEY, cfb128, CFB, 0, 128, 8, 128, stream);
#endif
