/* Dispatch functions for cast cipher modes ecb, cbc, ofb, cfb */

#include "cipher_wbsm4.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

// xiaolai
static OSSL_FUNC_cipher_freectx_fn wbsm4_xiaolai_freectx;
static OSSL_FUNC_cipher_dupctx_fn wbsm4_xiaolai_dupctx;

static void wbsm4_xiaolai_freectx(void *vctx)
{
    PROV_WBSM4_XIAOLAI_CTX *ctx = (PROV_WBSM4_XIAOLAI_CTX *)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX *)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *wbsm4_xiaolai_dupctx(void *ctx)
{
    PROV_WBSM4_XIAOLAI_CTX *in = (PROV_WBSM4_XIAOLAI_CTX *)ctx;
    PROV_WBSM4_XIAOLAI_CTX *ret;

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

/* ossl_wbsm4_xiaolai1225984ecb_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, ecb, ECB, 0, 1225984, 128, 0, block);
/* ossl_wbsm4_xiaolai1225984cbc_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, cbc, CBC, 0, 1225984, 128, 128, block);
/* ossl_wbsm4_xiaolai1225984ctr_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, ctr, CTR, 0, 1225984, 8, 128, stream);
/* ossl_wbsm4_xiaolai1225984ofb128_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, ofb128, OFB, 0, 1225984, 8, 128, stream);
/* ossl_wbsm4_xiaolai1225984cfb128_functions */
IMPLEMENT_generic_cipher(wbsm4_xiaolai, WBSM4_XIAOLAI, cfb128, CFB, 0, 1225984, 8, 128, stream);