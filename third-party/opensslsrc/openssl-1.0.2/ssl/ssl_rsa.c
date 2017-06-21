/* ssl/ssl_rsa.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include "ssl_locl.h"
#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

static int ssl_set_cert(CERT *c, X509 *x509);
static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey);
int SSL_use_certificate(SSL *ssl, X509 *x)
{
    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ssl->cert)) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    return (ssl_set_cert(ssl->cert, x));
}

#ifndef OPENSSL_NO_STDIO
int SSL_use_certificate_file(SSL *ssl, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, ssl->ctx->default_passwd_callback,
                              ssl->ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = SSL_use_certificate(ssl, x);
 end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_certificate(ssl, x);
    X509_free(x);
    return (ret);
}

#ifndef OPENSSL_NO_RSA
int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa)
{
    EVP_PKEY *pkey;
    int ret;

    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ssl->cert)) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    if ((pkey = EVP_PKEY_new()) == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return (0);
    }

    RSA_up_ref(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        return 0;
    }

    ret = ssl_set_pkey(ssl->cert, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

/* start facebook */
int SSL_rsa_async_mod_exp(void *data, BIGNUM *r0, const BIGNUM *I, RSA *rsa)
{
    SSL *s = (SSL *)data;
    int ret = 0;

    if (!SSL_CTX_is_rsa_async(s->ctx))
        return 0;
    ret = s->ctx->rsa_mod_exp_cb(s, r0, I, rsa);
    if (ret == RSA_ASYNC_PENDING) {
        if (s->rsa_async) {
            SSL_RSA_ASYNC_reset(s->rsa_async);
        } else {
            if (!(s->rsa_async = SSL_RSA_ASYNC_new())) {
                SSLerr(SSL_F_SSL_RSA_ASYNC_MOD_EXP,
                       ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        RSA_up_ref(rsa);
        s->rsa_async->rsa = rsa;
    } else if (ret <= 0) {
        SSLerr(SSL_F_SSL_RSA_ASYNC_MOD_EXP, SSL_R_RSA_MOD_EXP_CB_FAILURE);
        /* Follow the RSA_eay_mod_exp() convention, OK: 1, ERROR: 0 */
        ret = 0;
    }
    return ret;
}

RSA* SSL_CTX_use_rsa_async_mod_exp(
  SSL_CTX *ctx,
  int (*mod_exp_cb)(SSL *s, BIGNUM *r0, const BIGNUM *I, RSA *rsa))
{
    RSA *rsa = NULL;
    RSA *public_rsa = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;

    /* Only >=SSLv3 is supported */
    if (
#ifndef OPENSSL_NO_SSL2
      ctx->method->ssl_accept == ssl2_accept ||
#endif
        (ctx->method->ssl_accept == ssl23_accept &&
         !(SSL_CTX_get_options(ctx) & SSL_OP_NO_SSLv2)) ||
        !ctx->cert ||
        !(x509 = ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509))
        return NULL;

    rsa = RSA_new();
    rsa->meth = RSA_PKCS1_SSLeay();
    /* EXTernal PKEY */
    rsa->flags |= RSA_FLAG_EXT_PKEY;

    /* A hack to prevent it from verifying the private
     * key with the cert.
     */
    ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509 = NULL;
    SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    ctx->cert->pkeys[SSL_PKEY_RSA_ENC].x509 = x509;

    pkey = X509_get_pubkey(x509);
    public_rsa = pkey->pkey.rsa;
    /* copy the n and e which are not secret */
    rsa->n = BN_new();
    rsa->e = BN_new();
    BN_copy(rsa->n, public_rsa->n);
    BN_copy(rsa->e, public_rsa->e);

    /* SSL_CTX_use_RSAPrivateKey() has up the ref,
     * so safe to RSA_free() now.
     */
    RSA_free(rsa);
    ctx->rsa_mod_exp_cb = mod_exp_cb;
    return(rsa);
}

int SSL_CTX_is_rsa_async(SSL_CTX *ctx)
{
    return ((ctx->rsa_mod_exp_cb) ? 1 : 0);
}

void SSL_RSA_ASYNC_reset(struct ssl_rsa_async_st *rsa_async)
{
    rsa_async->to = NULL;
    BN_clear_free(rsa_async->ret);
    rsa_async->ret = NULL;
    RSA_free(rsa_async->rsa);
    rsa_async->rsa = NULL;
}

SSL_RSA_ASYNC *SSL_RSA_ASYNC_new(void)
{
    SSL_RSA_ASYNC *ret;
    ret = (SSL_RSA_ASYNC *)OPENSSL_malloc(sizeof(*ret));
    if (!ret)
        return NULL;
    memset(ret, 0, sizeof(*ret));
    return ret;
}

void SSL_RSA_ASYNC_free(SSL_RSA_ASYNC *rsa_async)
{
    if (!rsa_async)
        return;
    SSL_RSA_ASYNC_reset(rsa_async);
    OPENSSL_free(rsa_async);
}


int SSL_set_rsa_mod_exp_result(SSL *s, const BIGNUM *ret)
{
    struct ssl_rsa_async_st *rsa_async;

    s->rwstate = 0;
    if (!(rsa_async = s->rsa_async))
      return 0;

    if (!ret) {
        BN_free(rsa_async->ret);
        rsa_async->ret = NULL;
        return 1;
    }

    if (!(rsa_async->ret = BN_new()))
        return 0;

    if (!BN_copy(rsa_async->ret, ret)) {
        BN_free(rsa_async->ret);
        rsa_async->ret = NULL;
        return 0;
    }

    return 1;
}

/* end facebook */

/* begin facebook ecdsa */
//typedef struct ec_key_st EC_KEY;
EC_KEY* SSL_CTX_use_ecdsa_async_sign(
  SSL_CTX *ctx,
  int (*async_sign_cb)(SSL *s, const unsigned char * dgst, unsigned int dlen, EC_KEY *ecdsa))
{
    EC_KEY *ec_priv_key_dummy, *ec_pub_key, *ec_key_ret = NULL;
    EVP_PKEY *evp_pubkey = NULL, *evp_privkey = NULL;
    X509 *x509 = NULL;
    struct ecdsa_async_sign_ctx *ecdsa_async_sign_ctx = NULL;

    /* Only >=SSLv3 is supported */
    if (
#ifndef OPENSSL_NO_SSL2
        ctx->method->ssl_accept == ssl2_accept ||
#endif
            (ctx->method->ssl_accept == ssl23_accept &&
             !(SSL_CTX_get_options(ctx) & SSL_OP_NO_SSLv2)) ||
            !ctx->cert ||
            !(x509 = ctx->cert->pkeys[SSL_PKEY_ECC].x509)) {
        return NULL;
    }

    evp_pubkey = X509_get_pubkey(x509);
    ec_pub_key = evp_pubkey->pkey.ec;
    if (ec_pub_key == NULL || !EC_KEY_get0_public_key(ec_pub_key)) {
        return NULL;
    }
    if (!(ec_priv_key_dummy = EC_KEY_dup(ec_pub_key))) {
        return NULL;
    }

    if (EC_KEY_get0_private_key(ec_priv_key_dummy)) {
        /* will also clear existing priv_key BIGNUM  */
        EC_KEY_set_private_key(ec_priv_key_dummy, NULL);
    }

    /* Both flags indicate that private key is external */
    EC_KEY_set_flags(ec_priv_key_dummy, EC_FLAG_NO_CHECK);
    EC_KEY_set_flags(ec_priv_key_dummy, EC_FLAG_EXT_PKEY);

    /* Create a generic EVP_PKEY obj for this privkey and
     * set it in the SSL CTX */
    if ((evp_privkey = EVP_PKEY_new()) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_EVP_LIB);
        goto end_free_eckey;
    }

    /* Ups the ref to ec_priv_key_dummy */
    EVP_PKEY_set1_EC_KEY(evp_privkey, ec_priv_key_dummy);

    if (!SSL_CTX_use_PrivateKey(ctx, evp_privkey)) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_EVP_LIB);
        goto end_free_evp;
    }
    ctx->ecdsa_async_sign_cb = async_sign_cb;
    ec_key_ret = ec_priv_key_dummy;

end_free_evp:
    /* safe to free since SSL_CTX_use_PrivateKey() ups the ref */
    EVP_PKEY_free(evp_privkey);
end_free_eckey:
    /* safe to free since ref is upped above */
    EC_KEY_free(ec_priv_key_dummy);
    return ec_key_ret;
}

int SSL_ecdsa_async_sign(void *data, int sign_type,
    const unsigned char *dgst, unsigned int dlen, /* EC_KEY*  */ void *ec)
{
    SSL *s = (SSL *)data;
    int ret = 1;

    if (!SSL_CTX_is_ecdsa_async(s->ctx))
        return 0;
    ret = s->ctx->ecdsa_async_sign_cb(s, dgst, dlen, ec);
    if (ret == ECDSA_ASYNC_PENDING) {
        if (s->ecdsa_async) {
            SSL_ECDSA_ASYNC_reset(s->ecdsa_async);
        } else {
            if (!(s->ecdsa_async = SSL_ECDSA_ASYNC_new())) {
                SSLerr(SSL_F_SSL_ECDSA_ASYNC_SIGN,
                       ERR_R_MALLOC_FAILURE);
                return 0;
            }
        }
        EC_KEY_up_ref(ec);
        s->ecdsa_async->ec = ec;
        s->ecdsa_async->sig = NULL;
        s->ecdsa_async->siglen = 0;
    } else if (ret <= 0) {
        SSLerr(SSL_F_SSL_ECDSA_ASYNC_SIGN, SSL_R_ECDSA_ASYNC_SIGN_CB_FAILURE);
        /* OK: 1, ERROR: 0 */
        ret = 0;
    }
    return ret;
}

int SSL_set_ecdsa_async_sign_result(SSL *s, const unsigned char *sig,
    unsigned int siglen)
{
    struct ssl_ecdsa_async_st *ecdsa_async;

    s->rwstate = 0;
    if (!(ecdsa_async = s->ecdsa_async)) {
      return 0;
    }

    if (!sig || !ecdsa_async->ec || siglen > ECDSA_size(ecdsa_async->ec)) {
        ecdsa_async->sig = NULL;
        ecdsa_async->siglen = 0;
        return 1;
    }

    ecdsa_async->siglen = siglen;
    ecdsa_async->sig = OPENSSL_malloc(ECDSA_size(ecdsa_async->ec));
    memcpy(ecdsa_async->sig, sig, siglen);

    return 1;
}

int SSL_CTX_is_ecdsa_async(SSL_CTX *ctx)
{
    return ((ctx->ecdsa_async_sign_cb) ? 1 : 0);
}

void SSL_ECDSA_ASYNC_reset(struct ssl_ecdsa_async_st *ecdsa_async)
{
    if (ecdsa_async->sig != NULL && ecdsa_async->siglen > 0) {
      free(ecdsa_async->sig);
    }
    EC_KEY_free(ecdsa_async->ec);
    memset(ecdsa_async, 0, sizeof(struct ssl_ecdsa_async_st));
}

SSL_ECDSA_ASYNC *SSL_ECDSA_ASYNC_new(void)
{
    SSL_ECDSA_ASYNC *ret;
    if (!(ret = (SSL_ECDSA_ASYNC *)OPENSSL_malloc(sizeof(*ret)))) {
        return NULL;
    }
    memset(ret, 0, sizeof(*ret));
    return ret;
}

void SSL_ECDSA_ASYNC_free(SSL_ECDSA_ASYNC *ecdsa_async)
{
    if (!ecdsa_async) {
        return;
    }
    SSL_ECDSA_ASYNC_reset(ecdsa_async);
    OPENSSL_free(ecdsa_async);
}

/* end facebook ecdsa */
#endif

static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey)
{
    int i;
    /*
     * Special case for DH: check two DH certificate types for a match. This
     * means for DH certificates we must set the certificate first.
     */
    if (pkey->type == EVP_PKEY_DH) {
        X509 *x;
        i = -1;
        x = c->pkeys[SSL_PKEY_DH_RSA].x509;
        if (x && X509_check_private_key(x, pkey))
            i = SSL_PKEY_DH_RSA;
        x = c->pkeys[SSL_PKEY_DH_DSA].x509;
        if (i == -1 && x && X509_check_private_key(x, pkey))
            i = SSL_PKEY_DH_DSA;
        ERR_clear_error();
    } else
        i = ssl_cert_type(NULL, pkey);
    if (i < 0) {
        SSLerr(SSL_F_SSL_SET_PKEY, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        return (0);
    }

    if (c->pkeys[i].x509 != NULL) {
        EVP_PKEY *pktmp;
        pktmp = X509_get_pubkey(c->pkeys[i].x509);
        if (pktmp == NULL) {
            SSLerr(SSL_F_SSL_SET_PKEY, ERR_R_MALLOC_FAILURE);
            EVP_PKEY_free(pktmp);
            return 0;
        }
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pktmp, pkey);
        EVP_PKEY_free(pktmp);
        ERR_clear_error();

        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if (0
#ifndef OPENSSL_NO_RSA
            ||
            ((pkey->type == EVP_PKEY_RSA) &&
            (RSA_flags(pkey->pkey.rsa) & RSA_METHOD_FLAG_NO_CHECK))
#endif
#ifndef OPENSSL_NO_EC
            ||
            /* begin facebook ecdsa */
            /* Don't check the cert+private key if key is external */
            ((pkey->type == EVP_PKEY_EC) &&
            (EC_KEY_get_flags(pkey->pkey.ec) & EC_FLAG_NO_CHECK))
            /* end facebook ecdsa */
#endif
           );
        else
        if (!X509_check_private_key(c->pkeys[i].x509, pkey)) {
            X509_free(c->pkeys[i].x509);
            c->pkeys[i].x509 = NULL;
            return 0;
        }
    }

    if (c->pkeys[i].privatekey != NULL)
        EVP_PKEY_free(c->pkeys[i].privatekey);
    CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
    c->pkeys[i].privatekey = pkey;
    c->key = &(c->pkeys[i]);

    c->valid = 0;
    return (1);
}

#ifndef OPENSSL_NO_RSA
# ifndef OPENSSL_NO_STDIO
int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         ssl->ctx->default_passwd_callback,
                                         ssl->
                                         ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_use_RSAPrivateKey(ssl, rsa);
    RSA_free(rsa);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
# endif

int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    RSA *rsa;

    p = d;
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_RSAPrivateKey(ssl, rsa);
    RSA_free(rsa);
    return (ret);
}
#endif                          /* !OPENSSL_NO_RSA */

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
{
    int ret;

    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ssl->cert)) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    ret = ssl_set_pkey(ssl->cert, pkey);
    return (ret);
}

#ifndef OPENSSL_NO_STDIO
int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       ssl->ctx->default_passwd_callback,
                                       ssl->
                                       ctx->default_passwd_callback_userdata);
    } else if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_use_PrivateKey(ssl, pkey);
    EVP_PKEY_free(pkey);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_use_PrivateKey_ASN1(int type, SSL *ssl, const unsigned char *d,
                            long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_PrivateKey(ssl, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
{
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    return (ssl_set_cert(ctx->cert, x));
}

static int ssl_set_cert(CERT *c, X509 *x)
{
    EVP_PKEY *pkey;
    int i;

    pkey = X509_get_pubkey(x);
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_SET_CERT, SSL_R_X509_LIB);
        return (0);
    }

    i = ssl_cert_type(x, pkey);
    if (i < 0) {
        SSLerr(SSL_F_SSL_SET_CERT, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
        EVP_PKEY_free(pkey);
        return (0);
    }

    if (c->pkeys[i].privatekey != NULL) {
        /*
         * The return code from EVP_PKEY_copy_parameters is deliberately
         * ignored. Some EVP_PKEY types cannot do this.
         */
        EVP_PKEY_copy_parameters(pkey, c->pkeys[i].privatekey);
        ERR_clear_error();

        /*
         * Don't check the public/private key, this is mostly for smart
         * cards.
         */
        if (0
#ifndef OPENSSL_NO_RSA
            ||
            ((c->pkeys[i].privatekey->type == EVP_PKEY_RSA) &&
            (RSA_flags(c->pkeys[i].privatekey->pkey.rsa) &
             RSA_METHOD_FLAG_NO_CHECK))
#endif
#ifndef OPENSSL_NO_EC
            ||
            /* begin facebook ecdsa */
            ((c->pkeys[i].privatekey->type == EVP_PKEY_EC) &&
            (EC_KEY_get_flags(c->pkeys[i].privatekey->pkey.ec) &
             EC_FLAG_NO_CHECK))
            /* end facebook ecdsa */
#endif
           );
        else
        if (!X509_check_private_key(x, c->pkeys[i].privatekey)) {
            /*
             * don't fail for a cert/key mismatch, just free current private
             * key (when switching to a different cert & key, first this
             * function should be used, then ssl_set_pkey
             */
            EVP_PKEY_free(c->pkeys[i].privatekey);
            c->pkeys[i].privatekey = NULL;
            /* clear error queue */
            ERR_clear_error();
        }
    }

    EVP_PKEY_free(pkey);

    if (c->pkeys[i].x509 != NULL)
        X509_free(c->pkeys[i].x509);
    CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
    c->pkeys[i].x509 = x;
    c->key = &(c->pkeys[i]);

    c->valid = 0;
    return (1);
}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type)
{
    int j;
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        x = d2i_X509_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }

    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_FILE, j);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);
 end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len,
                                 const unsigned char *d)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_certificate(ctx, x);
    X509_free(x);
    return (ret);
}

#ifndef OPENSSL_NO_RSA
int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa)
{
    int ret;
    EVP_PKEY *pkey;

    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    if ((pkey = EVP_PKEY_new()) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return (0);
    }

    RSA_up_ref(rsa);
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        RSA_free(rsa);
        return 0;
    }

    ret = ssl_set_pkey(ctx->cert, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

# ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    RSA *rsa = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        rsa = d2i_RSAPrivateKey_bio(in, NULL);
    } else if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        rsa = PEM_read_bio_RSAPrivateKey(in, NULL,
                                         ctx->default_passwd_callback,
                                         ctx->default_passwd_callback_userdata);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (rsa == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
# endif

int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d,
                                   long len)
{
    int ret;
    const unsigned char *p;
    RSA *rsa;

    p = d;
    if ((rsa = d2i_RSAPrivateKey(NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
    RSA_free(rsa);
    return (ret);
}
#endif                          /* !OPENSSL_NO_RSA */

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
{
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY, ERR_R_MALLOC_FAILURE);
        return (0);
    }
    return (ssl_set_pkey(ctx->cert, pkey));
}

#ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type)
{
    int j, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, ERR_R_SYS_LIB);
        goto end;
    }
    if (type == SSL_FILETYPE_PEM) {
        j = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata);
    } else if (type == SSL_FILETYPE_ASN1) {
        j = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }
    if (pkey == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE, j);
        goto end;
    }
    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
 end:
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
                                const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

#ifndef OPENSSL_NO_STDIO
/*
 * Read a file that contains our certificate in "PEM" format, possibly
 * followed by a sequence of CA certificates that should be sent to the peer
 * in the Certificate message.
 */
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
{
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    ERR_clear_error();          /* clear error stack for
                                 * SSL_CTX_use_certificate() */

    in = BIO_new(BIO_s_file_internal());
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    if (BIO_read_filename(in, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);

    if (ERR_peek_error() != 0)
        ret = 0;                /* Key/certificate mismatch doesn't imply
                                 * ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to the CA
         * certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        SSL_CTX_clear_chain_certs(ctx);

        while ((ca = PEM_read_bio_X509(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata))
               != NULL) {
            r = SSL_CTX_add0_chain_cert(ctx, ca);
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
            /*
             * Note that we must not free r if it was successfully added to
             * the chain (while we must free the main certificate, since its
             * reference count is increased by SSL_CTX_use_certificate).
             */
        }
        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM
            && ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0;            /* some real error */
    }

 end:
    if (x != NULL)
        X509_free(x);
    if (in != NULL)
        BIO_free(in);
    return (ret);
}
#endif

#ifndef OPENSSL_NO_TLSEXT
static int serverinfo_find_extension(const unsigned char *serverinfo,
                                     size_t serverinfo_length,
                                     unsigned int extension_type,
                                     const unsigned char **extension_data,
                                     size_t *extension_length)
{
    *extension_data = NULL;
    *extension_length = 0;
    if (serverinfo == NULL || serverinfo_length == 0)
        return -1;
    for (;;) {
        unsigned int type = 0;
        size_t len = 0;

        /* end of serverinfo */
        if (serverinfo_length == 0)
            return 0;           /* Extension not found */

        /* read 2-byte type field */
        if (serverinfo_length < 2)
            return -1;          /* Error */
        type = (serverinfo[0] << 8) + serverinfo[1];
        serverinfo += 2;
        serverinfo_length -= 2;

        /* read 2-byte len field */
        if (serverinfo_length < 2)
            return -1;          /* Error */
        len = (serverinfo[0] << 8) + serverinfo[1];
        serverinfo += 2;
        serverinfo_length -= 2;

        if (len > serverinfo_length)
            return -1;          /* Error */

        if (type == extension_type) {
            *extension_data = serverinfo;
            *extension_length = len;
            return 1;           /* Success */
        }

        serverinfo += len;
        serverinfo_length -= len;
    }
    return 0;                   /* Error */
}

static int serverinfo_srv_parse_cb(SSL *s, unsigned int ext_type,
                                   const unsigned char *in,
                                   size_t inlen, int *al, void *arg)
{

    if (inlen != 0) {
        *al = SSL_AD_DECODE_ERROR;
        return 0;
    }

    return 1;
}

static int serverinfo_srv_add_cb(SSL *s, unsigned int ext_type,
                                 const unsigned char **out, size_t *outlen,
                                 int *al, void *arg)
{
    const unsigned char *serverinfo = NULL;
    size_t serverinfo_length = 0;

    /* Is there serverinfo data for the chosen server cert? */
    if ((ssl_get_server_cert_serverinfo(s, &serverinfo,
                                        &serverinfo_length)) != 0) {
        /* Find the relevant extension from the serverinfo */
        int retval = serverinfo_find_extension(serverinfo, serverinfo_length,
                                               ext_type, out, outlen);
        if (retval == -1) {
            *al = SSL_AD_DECODE_ERROR;
            return -1;          /* Error */
        }
        if (retval == 0)
            return 0;           /* No extension found, don't send extension */
        return 1;               /* Send extension */
    }
    return 0;                   /* No serverinfo data found, don't send
                                 * extension */
}

/*
 * With a NULL context, this function just checks that the serverinfo data
 * parses correctly.  With a non-NULL context, it registers callbacks for
 * the included extensions.
 */
static int serverinfo_process_buffer(const unsigned char *serverinfo,
                                     size_t serverinfo_length, SSL_CTX *ctx)
{
    if (serverinfo == NULL || serverinfo_length == 0)
        return 0;
    for (;;) {
        unsigned int ext_type = 0;
        size_t len = 0;

        /* end of serverinfo */
        if (serverinfo_length == 0)
            return 1;

        /* read 2-byte type field */
        if (serverinfo_length < 2)
            return 0;
        /* FIXME: check for types we understand explicitly? */

        /* Register callbacks for extensions */
        ext_type = (serverinfo[0] << 8) + serverinfo[1];
        if (ctx) {
            int have_ext_cbs = 0;
            size_t i;
            custom_ext_methods *exts = &ctx->cert->srv_ext;
            custom_ext_method *meth = exts->meths;

            for (i = 0; i < exts->meths_count; i++, meth++) {
                if (ext_type == meth->ext_type) {
                    have_ext_cbs = 1;
                    break;
                }
            }

            if (!have_ext_cbs && !SSL_CTX_add_server_custom_ext(ctx, ext_type,
                                                                serverinfo_srv_add_cb,
                                                                NULL, NULL,
                                                                serverinfo_srv_parse_cb,
                                                                NULL))
                return 0;
        }

        serverinfo += 2;
        serverinfo_length -= 2;

        /* read 2-byte len field */
        if (serverinfo_length < 2)
            return 0;
        len = (serverinfo[0] << 8) + serverinfo[1];
        serverinfo += 2;
        serverinfo_length -= 2;

        if (len > serverinfo_length)
            return 0;

        serverinfo += len;
        serverinfo_length -= len;
    }
}

int SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
                           size_t serverinfo_length)
{
    unsigned char *new_serverinfo;

    if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (!serverinfo_process_buffer(serverinfo, serverinfo_length, NULL)) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, SSL_R_INVALID_SERVERINFO_DATA);
        return 0;
    }
    if (!ssl_cert_inst(&ctx->cert)) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    if (ctx->cert->key == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    new_serverinfo = OPENSSL_realloc(ctx->cert->key->serverinfo,
                                     serverinfo_length);
    if (new_serverinfo == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ctx->cert->key->serverinfo = new_serverinfo;
    memcpy(ctx->cert->key->serverinfo, serverinfo, serverinfo_length);
    ctx->cert->key->serverinfo_length = serverinfo_length;

    /*
     * Now that the serverinfo is validated and stored, go ahead and
     * register callbacks.
     */
    if (!serverinfo_process_buffer(serverinfo, serverinfo_length, ctx)) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, SSL_R_INVALID_SERVERINFO_DATA);
        return 0;
    }
    return 1;
}

# ifndef OPENSSL_NO_STDIO
int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file)
{
    unsigned char *serverinfo = NULL;
    size_t serverinfo_length = 0;
    unsigned char *extension = 0;
    long extension_length = 0;
    char *name = NULL;
    char *header = NULL;
    char namePrefix[] = "SERVERINFO FOR ";
    int ret = 0;
    BIO *bin = NULL;
    size_t num_extensions = 0;

    if (ctx == NULL || file == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
               ERR_R_PASSED_NULL_PARAMETER);
        goto end;
    }

    bin = BIO_new(BIO_s_file_internal());
    if (bin == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_BUF_LIB);
        goto end;
    }
    if (BIO_read_filename(bin, file) <= 0) {
        SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_SYS_LIB);
        goto end;
    }

    for (num_extensions = 0;; num_extensions++) {
        if (PEM_read_bio(bin, &name, &header, &extension, &extension_length)
            == 0) {
            /*
             * There must be at least one extension in this file
             */
            if (num_extensions == 0) {
                SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
                       SSL_R_NO_PEM_EXTENSIONS);
                goto end;
            } else              /* End of file, we're done */
                break;
        }
        /* Check that PEM name starts with "BEGIN SERVERINFO FOR " */
        if (strlen(name) < strlen(namePrefix)) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
                   SSL_R_PEM_NAME_TOO_SHORT);
            goto end;
        }
        if (strncmp(name, namePrefix, strlen(namePrefix)) != 0) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
                   SSL_R_PEM_NAME_BAD_PREFIX);
            goto end;
        }
        /*
         * Check that the decoded PEM data is plausible (valid length field)
         */
        if (extension_length < 4
            || (extension[2] << 8) + extension[3] != extension_length - 4) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, SSL_R_BAD_DATA);
            goto end;
        }
        /* Append the decoded extension to the serverinfo buffer */
        serverinfo =
            OPENSSL_realloc(serverinfo, serverinfo_length + extension_length);
        if (serverinfo == NULL) {
            SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        memcpy(serverinfo + serverinfo_length, extension, extension_length);
        serverinfo_length += extension_length;

        OPENSSL_free(name);
        name = NULL;
        OPENSSL_free(header);
        header = NULL;
        OPENSSL_free(extension);
        extension = NULL;
    }

    ret = SSL_CTX_use_serverinfo(ctx, serverinfo, serverinfo_length);
 end:
    /* SSL_CTX_use_serverinfo makes a local copy of the serverinfo. */
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(extension);
    OPENSSL_free(serverinfo);
    if (bin != NULL)
        BIO_free(bin);
    return ret;
}
# endif                         /* OPENSSL_NO_STDIO */
#endif                          /* OPENSSL_NO_TLSEXT */
