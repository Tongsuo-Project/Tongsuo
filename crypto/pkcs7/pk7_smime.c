/*
 * Copyright 1999-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple PKCS#7 processing functions */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "pk7_local.h"

#define BUFFERSIZE 4096


static int pkcs7_copy_existing_digest(PKCS7 *p7, PKCS7_SIGNER_INFO *si);

PKCS7 *PKCS7_sign_ex(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                     BIO *data, int flags, OSSL_LIB_CTX *libctx,
                     const char *propq)
{
    PKCS7 *p7;
    int i;

    if ((p7 = PKCS7_new_ex(libctx, propq)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    //2023年6月11日23:48:06 沈雪冰 begin add,根据pkey类型设置SM2 PKCS7的类型,即GMT 0010-2012 SM2密码算法加密签名消息语法规范中的要求的oid
    if (pkey)
    {
        int type = EVP_PKEY_base_id(pkey);
        if (type == EVP_PKEY_SM2 || type == EVP_PKEY_EC) {
            if (!PKCS7_set_type(p7, NID_pkcs7_sm2_signed)) //1.2.156.10197.6.1.4.2.2
                goto err;

            if (!PKCS7_content_new(p7, NID_pkcs7_sm2_data)) //1.2.156.10197.6.1.4.2.1
                goto err;
        }
        else
        {
            if (!PKCS7_set_type(p7, NID_pkcs7_signed))
                goto err;

            if (!PKCS7_content_new(p7, NID_pkcs7_data))
                goto err;
        }
    }
    else if (flags & PKCS7_SM2_GMT0010)
    {
        if (!PKCS7_set_type(p7, NID_pkcs7_sm2_signed)) //1.2.156.10197.6.1.4.2.2
            goto err;

        if (!PKCS7_content_new(p7, NID_pkcs7_sm2_data)) //1.2.156.10197.6.1.4.2.1
            goto err;
    }  
    //2023年6月11日23:48:06 沈雪冰 end add,根据pkey类型设置SM2 PKCS7的类型,即GMT 0010-2012 SM2密码算法加密签名消息语法规范中的要求的oid
    else
    {
        if (!PKCS7_set_type(p7, NID_pkcs7_signed))
            goto err;

        if (!PKCS7_content_new(p7, NID_pkcs7_data))
            goto err;
    }

    if (pkey && !PKCS7_sign_add_signer(p7, signcert, pkey, NULL, flags)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_PKCS7_ADD_SIGNER_ERROR);
        goto err;
    }

    if (!(flags & PKCS7_NOCERTS)) {
        for (i = 0; i < sk_X509_num(certs); i++) {
            if (!PKCS7_add_certificate(p7, sk_X509_value(certs, i)))
                goto err;
        }
    }

    if (flags & PKCS7_DETACHED)
        PKCS7_set_detached(p7, 1);

    if (flags & (PKCS7_STREAM | PKCS7_PARTIAL))
        return p7;

    if (PKCS7_final(p7, data, flags))
        return p7;

 err:
    PKCS7_free(p7);
    return NULL;
}

PKCS7 *PKCS7_sign(X509 *signcert, EVP_PKEY *pkey, STACK_OF(X509) *certs,
                  BIO *data, int flags)
{
    return PKCS7_sign_ex(signcert, pkey, certs, data, flags, NULL, NULL);
}


int PKCS7_final(PKCS7 *p7, BIO *data, int flags)
{
    BIO *p7bio;
    int ret = 0;
	int hashType = 0;
	if (flags & PKCS7_SM2_HASH)
	{
		hashType = 1; //外送hash值
	}
	else if (flags & PKCS7_SM2_ADDHASH_Z)
	{
		hashType = 0; //计算Z值到P7摘要中
	}
	else
	{
		hashType = 2;//原文裸签
	}
    if ((p7bio = PKCS7_dataInit(p7, NULL, hashType)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    SMIME_crlf_copy(data, p7bio, flags);

    (void)BIO_flush(p7bio);

    if (!PKCS7_dataFinal(p7, p7bio,hashType)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_PKCS7_DATASIGN);
        goto err;
    }
    ret = 1;
err:
    BIO_free_all(p7bio);

    return ret;

}

/* Check to see if a cipher exists and if so add S/MIME capabilities */

static int add_cipher_smcap(STACK_OF(X509_ALGOR) *sk, int nid, int arg)
{
    if (EVP_get_cipherbynid(nid))
        return PKCS7_simple_smimecap(sk, nid, arg);
    return 1;
}

static int add_digest_smcap(STACK_OF(X509_ALGOR)* sk, int nid, int arg)
{
	if (EVP_get_digestbynid(nid))
		return PKCS7_simple_smimecap(sk, nid, arg);
	return 1;
}

PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7, X509 *signcert,
                                         EVP_PKEY *pkey, const EVP_MD *md,
                                         int flags)
{
    PKCS7_SIGNER_INFO *si = NULL;
    STACK_OF(X509_ALGOR) *smcap = NULL;

    if (!X509_check_private_key(signcert, pkey)) {
        ERR_raise(ERR_LIB_PKCS7,
                  PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return NULL;
    }

    if ((si = PKCS7_add_signature(p7, signcert, pkey, md)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_PKCS7_ADD_SIGNATURE_ERROR);
        return NULL;
    }

    si->ctx = ossl_pkcs7_get0_ctx(p7);
    if (!(flags & PKCS7_NOCERTS)) {
        if (!PKCS7_add_certificate(p7, signcert))
            goto err;
    }

    if (!(flags & PKCS7_NOATTR)) {
        if (!PKCS7_add_attrib_content_type(si, NULL))
            goto err;
        /* Add SMIMECapabilities */
        if (!(flags & PKCS7_NOSMIMECAP)) {
            if ((smcap = sk_X509_ALGOR_new_null()) == NULL) {
                ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
                goto err;
            }
			if (!add_cipher_smcap(smcap, NID_sm4_ecb, -1)
				|| !add_cipher_smcap(smcap, NID_sm4_cbc, -1)
				|| !add_digest_smcap(smcap, NID_sm3, -1)
                || !add_cipher_smcap(smcap, NID_aes_256_cbc, -1)
                || !add_cipher_smcap(smcap, NID_aes_192_cbc, -1)
                || !add_cipher_smcap(smcap, NID_aes_128_cbc, -1)
                || !add_cipher_smcap(smcap, NID_des_ede3_cbc, -1)
                || !add_cipher_smcap(smcap, NID_des_cbc, -1)
                || !PKCS7_add_attrib_smimecap(si, smcap))
                goto err;
            sk_X509_ALGOR_pop_free(smcap, X509_ALGOR_free);
            smcap = NULL;
        }
        if (flags & PKCS7_REUSE_DIGEST) {
            if (!pkcs7_copy_existing_digest(p7, si))
                goto err;
            if (!(flags & PKCS7_PARTIAL)
                && !PKCS7_SIGNER_INFO_sign(si))
                goto err;
        }
    }
    return si;
 err:
    sk_X509_ALGOR_pop_free(smcap, X509_ALGOR_free);
    return NULL;
}

/*
 * Search for a digest matching SignerInfo digest type and if found copy
 * across.
 */

static int pkcs7_copy_existing_digest(PKCS7 *p7, PKCS7_SIGNER_INFO *si)
{
    int i;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *sitmp;
    ASN1_OCTET_STRING *osdig = NULL;
    sinfos = PKCS7_get_signer_info(p7);
    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        sitmp = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        if (si == sitmp)
            break;
        if (sk_X509_ATTRIBUTE_num(sitmp->auth_attr) <= 0)
            continue;
        if (!OBJ_cmp(si->digest_alg->algorithm, sitmp->digest_alg->algorithm)) {
            osdig = PKCS7_digest_from_attributes(sitmp->auth_attr);
            break;
        }

    }

    if (osdig != NULL)
        return PKCS7_add1_attrib_digest(si, osdig->data, osdig->length);

    ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_MATCHING_DIGEST_TYPE_FOUND);
    return 0;
}

int PKCS7_verify(PKCS7 *p7, STACK_OF(X509) *certs, X509_STORE *store,
                 BIO *indata, BIO *out, int flags)
{
    STACK_OF(X509) *signers;
    X509 *signer;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    X509_STORE_CTX *cert_ctx = NULL;
    char *buf = NULL;
    int i, j = 0, k, ret = 0;
    BIO *p7bio = NULL;
    BIO *tmpin = NULL, *tmpout = NULL;
    const PKCS7_CTX *p7_ctx;
	int hashType = 0;
	int setCerts = 0;

    if (p7 == NULL) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_signed(p7)&& !PKCS7_type_is_signedAndEnveloped(p7)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    /* Check for no data and no content: no data to verify signature */
    if (PKCS7_get_detached(p7) && !indata) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_CONTENT);
        return 0;
    }

    if (flags & PKCS7_NO_DUAL_CONTENT) {
        /*
         * This was originally "#if 0" because we thought that only old broken
         * Netscape did this.  It turns out that Authenticode uses this kind
         * of "extended" PKCS7 format, and things like UEFI secure boot and
         * tools like osslsigncode need it.  In Authenticode the verification
         * process is different, but the existing PKCs7 verification works.
         */
        if (!PKCS7_get_detached(p7) && indata) {
            ERR_raise(ERR_LIB_PKCS7, PKCS7_R_CONTENT_AND_DATA_PRESENT);
            return 0;
        }
    }

    sinfos = PKCS7_get_signer_info(p7);

    if (!sinfos || !sk_PKCS7_SIGNER_INFO_num(sinfos)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_SIGNATURES_ON_DATA);
        return 0;
    }

    signers = PKCS7_get0_signers(p7, certs, flags);
    if (signers == NULL)
        return 0;

    /* Now verify the certificates */
    p7_ctx = ossl_pkcs7_get0_ctx(p7);
    cert_ctx = X509_STORE_CTX_new_ex(ossl_pkcs7_ctx_get0_libctx(p7_ctx),
                                     ossl_pkcs7_ctx_get0_propq(p7_ctx));
    if (cert_ctx == NULL)
        goto err;
    if (!(flags & PKCS7_NOVERIFY))
        for (k = 0; k < sk_X509_num(signers); k++) {
            signer = sk_X509_value(signers, k);
            if (!(flags & PKCS7_NOCHAIN)) {
                if (!X509_STORE_CTX_init(cert_ctx, store, signer,
                                         p7->d.sign->cert)) {
                    ERR_raise(ERR_LIB_PKCS7, ERR_R_X509_LIB);
                    goto err;
                }
                X509_STORE_CTX_set_default(cert_ctx, "smime_sign");
            } else if (!X509_STORE_CTX_init(cert_ctx, store, signer, NULL)) {
                ERR_raise(ERR_LIB_PKCS7, ERR_R_X509_LIB);
                goto err;
            }
            if (!(flags & PKCS7_NOCRL))
                X509_STORE_CTX_set0_crls(cert_ctx, p7->d.sign->crl);
            i = X509_verify_cert(cert_ctx);
            if (i <= 0)
                j = X509_STORE_CTX_get_error(cert_ctx);
            if (i <= 0) {
                ERR_raise_data(ERR_LIB_PKCS7, PKCS7_R_CERTIFICATE_VERIFY_ERROR,
                               "Verify error: %s",
                               X509_verify_cert_error_string(j));
                goto err;
            }
            /* Check for revocation status here */
        }

    /*
     * Performance optimization: if the content is a memory BIO then store
     * its contents in a temporary read only memory BIO. This avoids
     * potentially large numbers of slow copies of data which will occur when
     * reading from a read write memory BIO when signatures are calculated.
     */

    if (indata && (BIO_method_type(indata) == BIO_TYPE_MEM)) {
        char *ptr;
        long len;
        len = BIO_get_mem_data(indata, &ptr);
        tmpin = (len == 0) ? indata : BIO_new_mem_buf(ptr, len);
        if (tmpin == NULL) {
            ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    } else
        tmpin = indata;

	if (flags & PKCS7_SM2_HASH)
	{
		hashType = 1; //外送hash值
	}
	else if (flags & PKCS7_SM2_ADDHASH_Z)
	{
		hashType = 0; //计算Z值到P7摘要中
	}
	else
	{
		hashType = 2;//原文裸签
	}
	//2023年6月18日22:53:25 沈雪冰 bengin add, 添加证书链用于计算SM2签名时的Z值
	if ((OBJ_obj2nid(p7->type) == NID_pkcs7_sm2_signed) || (OBJ_obj2nid(p7->type) == NID_pkcs7_sm2_signedAndEnveloped) && (!p7->d.sign->cert))
	{
		setCerts = 1;
		p7->d.sign->cert = certs; //为了SM2做Z值计算，必须要有证书链
	}
	//2023年6月18日22:53:25 沈雪冰 end add, 添加证书链用于计算SM2签名时的Z值
	if ((p7bio = PKCS7_dataInit(p7, tmpin, hashType)) == NULL)
		goto err;
	//2023年6月18日22:53:25 沈雪冰 bengin add, 添加证书链用于计算SM2签名时的Z值,需要重新设置为NULL
	if (setCerts)
	{
		p7->d.sign->cert = NULL;
	}
	//2023年6月18日22:53:25 沈雪冰 end add, 添加证书链用于计算SM2签名时的Z值,需要重新设置为NULL

    if (flags & PKCS7_TEXT) {
        if ((tmpout = BIO_new(BIO_s_mem())) == NULL) {
            ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        BIO_set_mem_eof_return(tmpout, 0);
    } else
        tmpout = out;

    /* We now have to 'read' from p7bio to calculate digests etc. */
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (;;) {
        i = BIO_read(p7bio, buf, BUFFERSIZE);
        if (i <= 0)
            break;
        if (tmpout)
            BIO_write(tmpout, buf, i);
    }

    if (flags & PKCS7_TEXT) {
        if (!SMIME_text(tmpout, out)) {
            ERR_raise(ERR_LIB_PKCS7, PKCS7_R_SMIME_TEXT_ERROR);
            BIO_free(tmpout);
            goto err;
        }
        BIO_free(tmpout);
    }

    /* Now Verify All Signatures */
    if (!(flags & PKCS7_NOSIGS))
        for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
            si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
            signer = sk_X509_value(signers, i);
            j = PKCS7_signatureVerify(p7bio, p7, si, signer,0);
            if (j <= 0) {
                ERR_raise(ERR_LIB_PKCS7, PKCS7_R_SIGNATURE_FAILURE);
                goto err;
            }
        }

    ret = 1;

 err:
    X509_STORE_CTX_free(cert_ctx);
    OPENSSL_free(buf);
    if (tmpin == indata) {
        if (indata)
            BIO_pop(p7bio);
    }
    BIO_free_all(p7bio);
    sk_X509_free(signers);
    return ret;
}

STACK_OF(X509) *PKCS7_get0_signers(PKCS7 *p7, STACK_OF(X509) *certs,
                                   int flags)
{
    STACK_OF(X509) *signers;
    STACK_OF(PKCS7_SIGNER_INFO) *sinfos;
    PKCS7_SIGNER_INFO *si;
    PKCS7_ISSUER_AND_SERIAL *ias;
    X509 *signer;
    int i;

    if (p7 == NULL) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return NULL;
    }

    if (!PKCS7_type_is_signed(p7)&& !PKCS7_type_is_signedAndEnveloped(p7)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return NULL;
    }

    /* Collect all the signers together */

    sinfos = PKCS7_get_signer_info(p7);

    if (sk_PKCS7_SIGNER_INFO_num(sinfos) <= 0) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_SIGNERS);
        return 0;
    }

    if ((signers = sk_X509_new_null()) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    for (i = 0; i < sk_PKCS7_SIGNER_INFO_num(sinfos); i++) {
        si = sk_PKCS7_SIGNER_INFO_value(sinfos, i);
        ias = si->issuer_and_serial;
        signer = NULL;
        /* If any certificates passed they take priority */
        if (certs)
            signer = X509_find_by_issuer_and_serial(certs,
                                                    ias->issuer, ias->serial);
        if (!signer && !(flags & PKCS7_NOINTERN)
            && p7->d.sign->cert)
            signer =
                X509_find_by_issuer_and_serial(p7->d.sign->cert,
                                               ias->issuer, ias->serial);
        if (!signer) {
            ERR_raise(ERR_LIB_PKCS7, PKCS7_R_SIGNER_CERTIFICATE_NOT_FOUND);
            sk_X509_free(signers);
            return 0;
        }

        if (!sk_X509_push(signers, signer)) {
            sk_X509_free(signers);
            return NULL;
        }
    }
    return signers;
}

/* Build a complete PKCS#7 enveloped data */

PKCS7 *PKCS7_encrypt_ex(STACK_OF(X509) *certs, BIO *in,
                        const EVP_CIPHER *cipher, int flags,
                        OSSL_LIB_CTX *libctx, const char *propq)
{
    PKCS7 *p7;
    BIO *p7bio = NULL;
    int i;
    X509 *x509;

    if ((p7 = PKCS7_new_ex(libctx, propq)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    //2023年7月1日13:54:57 沈雪冰 begin add,根据pkey类型设置SM2 PKCS7的类型,即GMT 0010-2012 SM2密码算法加密签名消息语法规范中的要求的oid
    if (flags & PKCS7_SM2_GMT0010)
    {
        if (flags & PKCS7_NOSIGS)
        {
            if (!PKCS7_set_type(p7, NID_pkcs7_sm2_enveloped)) //1.2.156.10197.6.1.4.2.3
                goto err;
        }
        else //2023年7月1日14:18:48 沈雪冰 add,如果是签名加密,则设置为signedAndEnveloped
        {
            PKCS7err(PKCS7_F_PKCS7_ENCRYPT, EINVAL); //2023年7月5日22:23:10 沈雪冰 add，不支持签名加密
            goto err;
            /*if (!PKCS7_set_type(p7, NID_pkcs7_sm2_signedAndEnveloped))//1.2.156.10197.6.1.4.2.4
            {
                 PKCS7err(PKCS7_F_PKCS7_ENCRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
            }*/

        }
    }
    //2023年7月1日13:54:57 沈雪冰 end add,根据pkey类型设置SM2 PKCS7的类型,即GMT 0010-2012 SM2密码算法加密签名消息语法规范中的要求的oid
    else
    {
        if (flags & PKCS7_NOSIGS)
        {
            if (!PKCS7_set_type(p7, NID_pkcs7_enveloped))
                goto err;
        }
        else //2023年7月1日14:18:48 沈雪冰 add,如果是签名加密,则设置为signedAndEnveloped
        {
            PKCS7err(PKCS7_F_PKCS7_ENCRYPT, EINVAL); //2023年7月5日22:23:10 沈雪冰 add，不支持签名加密
            goto err;
            /*if (!PKCS7_set_type(p7, NID_pkcs7_sm2_signedAndEnveloped))//1.2.156.10197.6.1.4.2.4
            {
                 PKCS7err(PKCS7_F_PKCS7_ENCRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
            }*/
        }

    }
    if (!PKCS7_set_cipher(p7, cipher)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_ERROR_SETTING_CIPHER);
        goto err;
    }

    for (i = 0; i < sk_X509_num(certs); i++) {
        x509 = sk_X509_value(certs, i);
        if (!PKCS7_add_recipient(p7, x509)) {
            ERR_raise(ERR_LIB_PKCS7, PKCS7_R_ERROR_ADDING_RECIPIENT);
            goto err;
        }
    }

    if (flags & PKCS7_STREAM)
        return p7;

    if (PKCS7_final(p7, in, flags))
        return p7;

 err:

    BIO_free_all(p7bio);
    PKCS7_free(p7);
    return NULL;

}

PKCS7 *PKCS7_encrypt(STACK_OF(X509) *certs, BIO *in, const EVP_CIPHER *cipher,
                     int flags)
{
    return PKCS7_encrypt_ex(certs, in, cipher, flags, NULL, NULL);
}
PKCS7* PKCS7_encryptEx(STACK_OF(X509)* recipientCerts, BIO* in, const EVP_CIPHER* cipher, X509_CRL* crl,
	X509* signcert, EVP_PKEY* pkey, STACK_OF(X509)* signCerts, int flags)
{
	PKCS7* p7;
	BIO* p7bio = NULL;
	int i;
	X509* x509;

	if (!(flags & PKCS7_DETACHED)) //不能有原文，必须是分离式的原文
	{
		PKCS7err(PKCS7_F_PKCS7_ENCRYPT, EINVAL);
		return NULL;
	}

	if ((p7 = PKCS7_new()) == NULL) {
		PKCS7err(PKCS7_F_PKCS7_ENCRYPT, ERR_R_MALLOC_FAILURE);
		return NULL;
	}
	//2023年7月1日13:54:57 沈雪冰 begin add,根据pkey类型设置SM2 PKCS7的类型,即GMT 0010-2012 SM2密码算法加密签名消息语法规范中的要求的oid
	if (flags & PKCS7_SM2_GMT0010)
	{
		if (flags & PKCS7_NOSIGS)
		{
			PKCS7err(PKCS7_F_PKCS7_ENCRYPT, EINVAL); //这个方法必须有签名
			goto err;
		}
		else //2023年7月1日14:18:48 沈雪冰 add,如果是签名加密,则设置为signedAndEnveloped
		{
			if (!PKCS7_set_type(p7, NID_pkcs7_sm2_signedAndEnveloped))//1.2.156.10197.6.1.4.2.4
				goto err;
		}
	}
	//2023年7月1日13:54:57 沈雪冰 end add,根据pkey类型设置SM2 PKCS7的类型,即GMT 0010-2012 SM2密码算法加密签名消息语法规范中的要求的oid
	else
	{
		if (flags & PKCS7_NOSIGS)
		{
			PKCS7err(PKCS7_F_PKCS7_ENCRYPT, EINVAL); //这个方法必须有签名
			goto err;
		}
		else //2023年7月1日14:18:48 沈雪冰 add,如果是签名加密,则设置为signedAndEnveloped
		{
			if (!PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped))
				goto err;
		}

	}

	if (!PKCS7_set_cipher(p7, cipher)) {
		PKCS7err(PKCS7_F_PKCS7_ENCRYPT, PKCS7_R_ERROR_SETTING_CIPHER);
		goto err;
	}

	for (i = 0; i < sk_X509_num(recipientCerts); i++) {
		x509 = sk_X509_value(recipientCerts, i);
		if (!PKCS7_add_recipient(p7, x509)) {
			PKCS7err(PKCS7_F_PKCS7_ENCRYPT, PKCS7_R_ERROR_ADDING_RECIPIENT);
			goto err;
		}
	}

	if ((!flags & PKCS7_NOCRL) && crl)
	{
		PKCS7_add_crl(p7, crl);
	}


	if (pkey && !PKCS7_sign_add_signer(p7, signcert, pkey, NULL, flags)) {
		PKCS7err(PKCS7_F_PKCS7_SIGN, PKCS7_R_PKCS7_ADD_SIGNER_ERROR);
		goto err;
	}

	if (!(flags & PKCS7_NOCERTS)) {
		for (i = 0; i < sk_X509_num(signCerts); i++) {
			if (!PKCS7_add_certificate(p7, sk_X509_value(signCerts, i)))
				goto err;
		}
	}

	if (flags & PKCS7_DETACHED)
		PKCS7_set_detached(p7, 1);

	if (flags & (PKCS7_STREAM | PKCS7_PARTIAL))
		return p7;

	if (PKCS7_final(p7, in, flags))
		return p7;

err:

	BIO_free_all(p7bio);
	PKCS7_free(p7);
	return NULL;

}

int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags)
{
    BIO *tmpmem;
    int ret = 0, i;
    char *buf = NULL;

    if (p7 == NULL) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_enveloped(p7)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (cert && !X509_check_private_key(cert, pkey)) {
        ERR_raise(ERR_LIB_PKCS7,
                  PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return 0;
    }

    if ((tmpmem = PKCS7_dataDecode(p7, pkey, NULL, cert)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_DECRYPT_ERROR);
        return 0;
    }

    if (flags & PKCS7_TEXT) {
        BIO *tmpbuf, *bread;
        /* Encrypt BIOs can't do BIO_gets() so add a buffer BIO */
        if ((tmpbuf = BIO_new(BIO_f_buffer())) == NULL) {
            ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpmem);
            return 0;
        }
        if ((bread = BIO_push(tmpbuf, tmpmem)) == NULL) {
            ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpbuf);
            BIO_free_all(tmpmem);
            return 0;
        }
        ret = SMIME_text(bread, data);
        if (ret > 0 && BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
            if (!BIO_get_cipher_status(tmpmem))
                ret = 0;
        }
        BIO_free_all(bread);
        return ret;
    }
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL) {
        ERR_raise(ERR_LIB_PKCS7, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (;;) {
        i = BIO_read(tmpmem, buf, BUFFERSIZE);
        if (i <= 0) {
            ret = 1;
            if (BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
                if (!BIO_get_cipher_status(tmpmem))
                    ret = 0;
            }

            break;
        }
        if (BIO_write(data, buf, i) != i) {
            break;
        }
    }
err:
    OPENSSL_free(buf);
    BIO_free_all(tmpmem);
    return ret;
}

int PKCS7_decryptEx(PKCS7* p7, EVP_PKEY* pkey, X509* cert,
    STACK_OF(X509)* certs, X509_STORE* store, BIO* data, int flags)
{
    BIO* tmpmem;
    int ret = 0, i;
    char* buf = NULL;
    BIO* indata = NULL;

    if (!p7) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, PKCS7_R_INVALID_NULL_POINTER);
        return 0;
    }

    if (!PKCS7_type_is_signedAndEnveloped(p7)) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, PKCS7_R_WRONG_CONTENT_TYPE);
        return 0;
    }

    if (cert && !X509_check_private_key(cert, pkey)) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT,
            PKCS7_R_PRIVATE_KEY_DOES_NOT_MATCH_CERTIFICATE);
        return 0;
    }

    if ((tmpmem = PKCS7_dataDecode(p7, pkey, NULL, cert)) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, PKCS7_R_DECRYPT_ERROR);
        return 0;
    }

    if (flags & PKCS7_TEXT) {
        BIO* tmpbuf, * bread;
        /* Encrypt BIOs can't do BIO_gets() so add a buffer BIO */
        if ((tmpbuf = BIO_new(BIO_f_buffer())) == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpmem);
            return 0;
        }
        if ((bread = BIO_push(tmpbuf, tmpmem)) == NULL) {
            PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
            BIO_free_all(tmpbuf);
            BIO_free_all(tmpmem);
            return 0;
        }
        ret = SMIME_text(bread, data);
        if (ret > 0 && BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
            if (!BIO_get_cipher_status(tmpmem))
                ret = 0;
        }
        BIO_free_all(bread);
        return ret;
    }
    if ((buf = OPENSSL_malloc(BUFFERSIZE)) == NULL) {
        PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    for (;;) {
        i = BIO_read(tmpmem, buf, BUFFERSIZE);
        if (i <= 0) {
            ret = 1;
            if (BIO_method_type(tmpmem) == BIO_TYPE_CIPHER) {
                if (!BIO_get_cipher_status(tmpmem))
                    ret = 0;
            }

            break;
        }
        if (!(flags & PKCS7_NOSIGS))
        {
            indata = BIO_new_mem_buf(buf, i);
            if (!indata)
            {
                PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            //验证P7签名
            ret = PKCS7_verify(p7, certs, store, indata, NULL, flags);
            if (!ret)
            {
                PKCS7err(PKCS7_F_PKCS7_DECRYPT, ERR_R_MALLOC_FAILURE);
                goto err;
            }
        }
        if (BIO_write(data, buf, i) != i) {
                        break;
        }
        
    }
err:
    OPENSSL_free(buf);
    BIO_free_all(tmpmem);
    BIO_free(indata);
    return ret;
}
