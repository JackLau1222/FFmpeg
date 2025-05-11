/*
 * DTLS Protocol
 * Copyright (c) 2025 Jack Lau
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "tls.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "libavutil/mem.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/random_seed.h"
#include "libavutil/time.h"
#include "libavutil/opt.h"
#include "libavutil/getenv_utf8.h"
#include "http.h"
#include "mux.h"
#include "srtp.h"
#include "url.h"

/** 
 * Returns a heap‐allocated null‐terminated string containing
 * the PEM‐encoded public key.  Caller must free().
 */
static char *pkey_to_pem_string(EVP_PKEY *pkey) {
    BIO        *mem = NULL;
    BUF_MEM    *bptr = NULL;
    char       *pem_str = NULL;

    // 1) Create a memory BIO
    if ((mem = BIO_new(BIO_s_mem())) == NULL)
        goto err;

    // 2) Write public key in PEM form
    if (!PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL))
        goto err;

    // 3) Extract pointer/length
    BIO_get_mem_ptr(mem, &bptr);
    if (bptr == NULL || bptr->length == 0)
        goto err;

    // 4) Allocate string (+1 for NUL)
    pem_str = av_malloc(bptr->length + 1);
    if (pem_str == NULL)
        goto err;

    // 5) Copy data & NUL‐terminate
    memcpy(pem_str, bptr->data, bptr->length);
    pem_str[bptr->length] = '\0';

cleanup:
    BIO_free(mem);
    return pem_str;

err:
    // error path: free and return NULL
    free(pem_str);
    pem_str = NULL;
    goto cleanup;
}

/**
 * Serialize an X509 certificate to a malloc’d PEM string.
 * Caller must free() the returned pointer.
 */
static char *cert_to_pem_string(X509 *cert)
{
    BIO     *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr = NULL;
    char    *out = NULL;

    if (!mem) goto err;

    /* Write the PEM certificate */
    if (!PEM_write_bio_X509(mem, cert))
        goto err;

    BIO_get_mem_ptr(mem, &bptr);
    if (!bptr || bptr->length == 0) goto err;

    out = av_malloc(bptr->length + 1);
    if (!out) goto err;

    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';

cleanup:
    BIO_free(mem);
    return out;

err:
    free(out);
    out = NULL;
    goto cleanup;
}


/**
 * Generate a SHA-256 fingerprint of an X.509 certificate.
 *
 * @param ctx       AVFormatContext for logging (can be NULL)
 * @param cert      X509 certificate to fingerprint
 * @return          Newly allocated fingerprint string in "AA:BB:CC:…" format,
 *                  or NULL on error (logs via av_log if ctx != NULL).
 *                  Caller must free() the returned string.
 */
static char *generate_fingerprint(X509 *cert)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    int n = 0;
    AVBPrint fingerprint;
    char *result = NULL;
    int i;
    
    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&fingerprint, 0, AV_BPRINT_SIZE_UNLIMITED);

    if (X509_digest(cert, EVP_sha256(), md, &n) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to generate fingerprint, %s\n", openssl_get_error(s));
        goto end;
    }

    for (i = 0; i < n; i++) {
        av_bprintf(&fingerprint, "%02X", md[i]);
        if (i + 1 < n)
            av_bprintf(&fingerprint, ":");
    }

    if (!fingerprint.str || !strlen(fingerprint.str)) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Fingerprint is empty\n");
        goto end;
    }

    result = av_strdup(fingerprint.str);
    if (!result) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Out of memory generating fingerprint\n");
    }

end:
    av_bprint_finalize(&fingerprint, NULL);
    return result;
}

int ssl_read_key_cert(char *key_url, char *cert_url, char *key_buf, size_t key_sz, char *cert_buf, size_t cert_sz, char **fingerprint)
{
    int ret = 0;
    BIO *key_b = NULL, *cert_b = NULL;
    AVBPrint key_bp, cert_bp;
    EVP_PKEY *pkey;
    X509 *cert;
    char *key_tem = NULL, *cert_tem = NULL;

    /* To prevent a crash during cleanup, always initialize it. */
    av_bprint_init(&key_bp, 1, MAX_CERTIFICATE_SIZE);
    av_bprint_init(&cert_bp, 1, MAX_CERTIFICATE_SIZE);

    /* Read key file. */
    ret = url_read_all(key_url, &key_bp);
    if (ret < 0) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to open key file %s\n", key_url);
        goto end;
    }

    if ((key_b = BIO_new(BIO_s_mem())) == NULL) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    BIO_write(key_b, key_bp.str, key_bp.len);
    pkey = PEM_read_bio_PrivateKey(key_b, NULL, NULL, NULL);
    if (!pkey) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to read private key from %s\n", key_url);
        ret = AVERROR(EIO);
        goto end;
    }

    /* Read certificate. */
    ret = url_read_all(cert_url, &cert_bp);
    if (ret < 0) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to open cert file %s\n", cert_url);
        goto end;
    }

    if ((cert_b = BIO_new(BIO_s_mem())) == NULL) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    BIO_write(cert_b, cert_bp.str, cert_bp.len);
    cert = PEM_read_bio_X509(cert_b, NULL, NULL, NULL);
    if (!cert) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to read certificate from %s\n", cert_url);
        ret = AVERROR(EIO);
        goto end;
    }

    key_tem = pkey_to_pem_string(pkey);
    cert_tem = cert_to_pem_string(cert);

    snprintf(key_buf,  key_sz,  "%s", key_tem);
    snprintf(cert_buf, cert_sz, "%s", cert_tem);

    /* Generate fingerprint. */
    *fingerprint = generate_fingerprint(cert);
    if (!*fingerprint) {
        av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to generate fingerprint from %s\n", cert_url);
        ret = AVERROR(EIO);
        goto end;
    }

end:
    BIO_free(key_b);
    av_bprint_finalize(&key_bp, NULL);
    BIO_free(cert_b);
    av_bprint_finalize(&cert_bp, NULL);
    if (key_tem) av_free(key_tem);
    if (cert_tem) av_free(cert_tem);
    return ret;
}

static int openssl_gen_private_key(EVP_PKEY **pkey, EC_KEY **eckey)
{
    int ret = 0;

    /**
     * Note that secp256r1 in openssl is called NID_X9_62_prime256v1 or prime256v1 in string,
     * not NID_secp256k1 or secp256k1 in string.
     *
     * TODO: Should choose the curves in ClientHello.supported_groups, for example:
     *      Supported Group: x25519 (0x001d)
     *      Supported Group: secp256r1 (0x0017)
     *      Supported Group: secp384r1 (0x0018)
     */
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_GROUP *ecgroup = NULL;
    int curve = NID_X9_62_prime256v1;
#else
    const char *curve = SN_X9_62_prime256v1;
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    *pkey = EVP_PKEY_new();
    *eckey = EC_KEY_new();
    ecgroup = EC_GROUP_new_by_curve_name(curve);
    if (!ecgroup) {
        av_log(whip, AV_LOG_ERROR, "DTLS: Create EC group by curve=%d failed, %s", curve, openssl_get_error(whip));
        goto einval_end;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
    /* For openssl 1.0, we must set the group parameters, so that cert is ok. */
    EC_GROUP_set_asn1_flag(ecgroup, OPENSSL_EC_NAMED_CURVE);
#endif

    if (EC_KEY_set_group(*eckey, ecgroup) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Generate private key, EC_KEY_set_group failed, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (EC_KEY_generate_key(*eckey) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Generate private key, EC_KEY_generate_key failed, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (EVP_PKEY_set1_EC_KEY(*pkey, *eckey) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Generate private key, EVP_PKEY_set1_EC_KEY failed, %s\n", openssl_get_error(whip));
        goto einval_end;
    }
#else
    *pkey = EVP_EC_gen(curve);
    if (!*pkey) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Generate private key, EVP_EC_gen curve=%s failed, %s\n", curve, openssl_get_error(whip));
        goto einval_end;
    }
#endif
    goto end;

einval_end:
    ret = AVERROR(EINVAL);
end:
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_GROUP_free(ecgroup);
#endif
    return ret;
}

static int openssl_gen_certificate(EVP_PKEY *pkey, X509 **cert, char **fingerprint)
{
    int ret = 0, serial, expire_day;
    const char *aor = "lavf";
    X509_NAME* subject = NULL;

    *cert= X509_new();
    if (!*cert) {
        goto enomem_end;
    }

    // TODO: Support non-self-signed certificate, for example, load from a file.
    subject = X509_NAME_new();
    if (!subject) {
        goto enomem_end;
    }

    serial = (int)av_get_random_seed();
    if (ASN1_INTEGER_set(X509_get_serialNumber(*cert), serial) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set serial, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, aor, strlen(aor), -1, 0) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set CN, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (X509_set_issuer_name(*cert, subject) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set issuer, %s\n", openssl_get_error(whip));
        goto einval_end;
    }
    if (X509_set_subject_name(*cert, subject) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set subject name, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    expire_day = 365;
    if (!X509_gmtime_adj(X509_get_notBefore(*cert), 0)) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set notBefore, %s\n", openssl_get_error(whip));
        goto einval_end;
    }
    if (!X509_gmtime_adj(X509_get_notAfter(*cert), 60*60*24*expire_day)) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set notAfter, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (X509_set_version(*cert, 2) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set version, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (X509_set_pubkey(*cert, pkey) != 1) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to set public key, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    if (!X509_sign(*cert, pkey, EVP_sha1())) {
        // av_log(NULL, AV_LOG_ERROR, "DTLS: Failed to sign certificate, %s\n", openssl_get_error(whip));
        goto einval_end;
    }

    *fingerprint = generate_fingerprint(*cert);
    if (!*fingerprint) {
        goto enomem_end;
    }

    goto end;
enomem_end:
    ret = AVERROR(ENOMEM);
    goto end;
einval_end:
    ret = AVERROR(EINVAL);
end:
    X509_NAME_free(subject);
    //av_bprint_finalize(&fingerprint, NULL);
    return ret;
}

int ssl_gen_key_cert(char *key_buf, size_t key_sz, char *cert_buf, size_t cert_sz, char **fingerprint)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = NULL;
    X509 *cert = NULL;
    char *key_tem = NULL, *cert_tem = NULL;
    
    ret = openssl_gen_private_key(&pkey, &ec_key);
    if (ret < 0) goto error;

    ret = openssl_gen_certificate(pkey, &cert, fingerprint);
    if (ret < 0) goto error;

    key_tem = pkey_to_pem_string(pkey);
    cert_tem = cert_to_pem_string(cert);

    snprintf(key_buf,  key_sz,  "%s", key_tem);
    snprintf(cert_buf, cert_sz, "%s", cert_tem);
    
    if (key_tem) av_free(key_tem);
    if (cert_tem) av_free(cert_tem);
error:
    return ret;
}

typedef struct DTLSContext {
    AVClass *av_class;
    TLSShared tls_shared;
    SSL_CTX *ctx;
    SSL *ssl;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    BIO_METHOD* url_bio_method;
#endif
    /* Helper for get error code and message. */
    int io_err;
    char error_message[256];
} DTLSContext;

/**
 * Retrieves the error message for the latest OpenSSL error.
 *
 * This function retrieves the error code from the thread's error queue, converts it
 * to a human-readable string, and stores it in the DTLSContext's error_message field.
 * The error queue is then cleared using ERR_clear_error().
 */
static const char* openssl_get_error(DTLSContext *ctx)
{
    int r2 = ERR_get_error();
    if (r2)
        ERR_error_string_n(r2, ctx->error_message, sizeof(ctx->error_message));
    else
        ctx->error_message[0] = '\0';

    ERR_clear_error();
    return ctx->error_message;
}

static int print_ssl_error(URLContext *h, int ret)
{
    DTLSContext *c = h->priv_data;
    int printed = 0, e, averr = AVERROR(EIO);
    if (h->flags & AVIO_FLAG_NONBLOCK) {
        int err = SSL_get_error(c->ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return AVERROR(EAGAIN);
    }
    while ((e = ERR_get_error()) != 0) {
        av_log(h, AV_LOG_ERROR, "%s\n", ERR_error_string(e, NULL));
        printed = 1;
    }
    if (c->io_err) {
        av_log(h, AV_LOG_ERROR, "IO error: %s\n", av_err2str(c->io_err));
        printed = 1;
        averr = c->io_err;
        c->io_err = 0;
    }
    if (!printed)
        av_log(h, AV_LOG_ERROR, "Unknown error\n");
    return averr;
}

/**
 * Deserialize a PEM‐encoded private or public key from a NUL-terminated C string.
 *
 * @param pem_str   The PEM text, e.g.
 *                  "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n"
 * @param is_priv   If non-zero, parse as a PRIVATE key; otherwise, parse as a PUBLIC key.
 * @return          EVP_PKEY* on success (must EVP_PKEY_free()), or NULL on error.
 */
static EVP_PKEY *pkey_from_pem_string(const char *pem_str, int is_priv)
{
    BIO *mem = BIO_new_mem_buf(pem_str, -1);
    if (!mem) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (is_priv) {
        pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    }

    if (!pkey) {
        fprintf(stderr, "Failed to parse %s key from string\n",
                is_priv ? "private" : "public");
    }

    BIO_free(mem);
    return pkey;
}

/**
 * Deserialize a PEM‐encoded certificate from a NUL-terminated C string.
 *
 * @param pem_str   The PEM text, e.g.
 *                  "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"
 * @return          X509* on success (must X509_free()), or NULL on error.
 */
static X509 *cert_from_pem_string(const char *pem_str)
{
    BIO *mem = BIO_new_mem_buf(pem_str, -1);
    if (!mem) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Failed to parse certificate from string\n");
    }

    BIO_free(mem);
    return cert;
}

int ff_dtls_set_udp(URLContext *h, URLContext *udp)
{
    DTLSContext *c = h->priv_data;
    c->tls_shared.udp = udp;
    return 0;
}

int ff_dtls_export_materials(URLContext *h, char *dtls_srtp_materials, size_t materials_sz)
{
    int ret = 0;
    const char* dst = "EXTRACTOR-dtls_srtp";
    DTLSContext *c = h->priv_data;

    ret = SSL_export_keying_material(c->ssl, dtls_srtp_materials, materials_sz,
        dst, strlen(dst), NULL, 0, 0);
    if (!ret) {
        av_log(c, AV_LOG_ERROR, "DTLS: Failed to export SRTP material, %s\n", openssl_get_error(c));
        return -1;
    }
    return 0;
}

int ff_dtls_state(URLContext *h)
{
    DTLSContext *c = h->priv_data;
    return c->tls_shared.state;
}

static int url_bio_create(BIO *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    BIO_set_flags(b, 0);
#else
    b->init = 1;
    b->ptr = NULL;
    b->flags = 0;
#endif
    return 1;
}

static int url_bio_destroy(BIO *b)
{
    return 1;
}

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
#define GET_BIO_DATA(x) BIO_get_data(x)
#else
#define GET_BIO_DATA(x) (x)->ptr
#endif

static int url_bio_bread(BIO *b, char *buf, int len)
{
    DTLSContext *c = GET_BIO_DATA(b);
    int ret = ffurl_read(c->tls_shared.udp, buf, len);
    if (ret >= 0)
        return ret;
    BIO_clear_retry_flags(b);
    if (ret == AVERROR_EXIT)
        return 0;
    if (ret == AVERROR(EAGAIN))
        BIO_set_retry_read(b);
    else
        c->io_err = ret;
    return -1;
}

static int url_bio_bwrite(BIO *b, const char *buf, int len)
{
    DTLSContext *c = GET_BIO_DATA(b);
    int ret = ffurl_write(c->tls_shared.udp, buf, len);
    if (ret >= 0)
        return ret;
    BIO_clear_retry_flags(b);
    if (ret == AVERROR_EXIT)
        return 0;
    if (ret == AVERROR(EAGAIN))
        BIO_set_retry_write(b);
    else
        c->io_err = ret;
    return -1;
}

static long url_bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    if (cmd == BIO_CTRL_FLUSH) {
        BIO_clear_retry_flags(b);
        return 1;
    }
    return 0;
}

static int url_bio_bputs(BIO *b, const char *str)
{
    return url_bio_bwrite(b, str, strlen(str));
}

#if OPENSSL_VERSION_NUMBER < 0x1010000fL
static BIO_METHOD url_bio_method = {
    .type = BIO_TYPE_SOURCE_SINK,
    .name = "urlprotocol bio",
    .bwrite = url_bio_bwrite,
    .bread = url_bio_bread,
    .bputs = url_bio_bputs,
    .bgets = NULL,
    .ctrl = url_bio_ctrl,
    .create = url_bio_create,
    .destroy = url_bio_destroy,
};
#endif

static void init_bio_method(URLContext *h)
{
    DTLSContext *p = h->priv_data;
    BIO *bio;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    p->url_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "urlprotocol bio");
    BIO_meth_set_write(p->url_bio_method, url_bio_bwrite);
    BIO_meth_set_read(p->url_bio_method, url_bio_bread);
    BIO_meth_set_puts(p->url_bio_method, url_bio_bputs);
    BIO_meth_set_ctrl(p->url_bio_method, url_bio_ctrl);
    BIO_meth_set_create(p->url_bio_method, url_bio_create);
    BIO_meth_set_destroy(p->url_bio_method, url_bio_destroy);
    bio = BIO_new(p->url_bio_method);
    BIO_set_data(bio, p);
#else
    bio = BIO_new(&url_bio_method);
    bio->ptr = p;
#endif
    SSL_set_bio(p->ssl, bio, bio);
}

/**
 * Callback function to print the OpenSSL SSL status.
 */
static void openssl_dtls_on_info(const SSL *dtls, int where, int r0)
{
    int w, r1, is_fatal, is_warning, is_close_notify;
    const char *method = "undefined", *alert_type, *alert_desc;
    DTLSContext *ctx = (DTLSContext*)SSL_get_ex_data(dtls, 0);

    w = where & ~SSL_ST_MASK;
    if (w & SSL_ST_CONNECT)
        method = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        method = "SSL_accept";

    r1 = SSL_get_error(ctx->ssl, r0);
    if (where & SSL_CB_LOOP) {
        av_log(ctx, AV_LOG_VERBOSE, "DTLS: Info method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
            method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1);
    } else if (where & SSL_CB_ALERT) {
        method = (where & SSL_CB_READ) ? "read":"write";

        alert_type = SSL_alert_type_string_long(r0);
        alert_desc = SSL_alert_desc_string(r0);

        if (!av_strcasecmp(alert_type, "warning") && !av_strcasecmp(alert_desc, "CN"))
            av_log(ctx, AV_LOG_WARNING, "DTLS: SSL3 alert method=%s type=%s, desc=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, alert_type, alert_desc, SSL_alert_desc_string_long(r0), where, r0, r1);
        else
            av_log(ctx, AV_LOG_ERROR, "DTLS: SSL3 alert method=%s type=%s, desc=%s(%s), where=%d, ret=%d, r1=%d %s\n",
                method, alert_type, alert_desc, SSL_alert_desc_string_long(r0), where, r0, r1, ctx->error_message);

        /**
         * Notify the DTLS to handle the ALERT message, which maybe means media connection disconnect.
         * CN(Close Notify) is sent when peer close the PeerConnection. fatal, IP(Illegal Parameter)
         * is sent when DTLS failed.
         */
        is_fatal = !av_strncasecmp(alert_type, "fatal", 5);
        is_warning = !av_strncasecmp(alert_type, "warning", 7);
        is_close_notify = !av_strncasecmp(alert_desc, "CN", 2);
        ctx->tls_shared.state = is_fatal ? DTLS_STATE_FAILED : (is_warning && is_close_notify ? DTLS_STATE_CLOSED : DTLS_STATE_NONE);
        if (ctx->tls_shared.state != DTLS_STATE_NONE) {
            av_log(ctx, AV_LOG_INFO, "DTLS: Notify ctx=%p, state=%d, fatal=%d, warning=%d, cn=%d\n",
                ctx, ctx->tls_shared.state, is_fatal, is_warning, is_close_notify);
        }
    } else if (where & SSL_CB_EXIT) {
        if (!r0)
            av_log(ctx, AV_LOG_WARNING, "DTLS: Fail method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1);
        else if (r0 < 0)
            if (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)
                av_log(ctx, AV_LOG_ERROR, "DTLS: Error method=%s state=%s(%s), where=%d, ret=%d, r1=%d %s\n",
                    method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1, ctx->error_message);
            else
                av_log(ctx, AV_LOG_VERBOSE, "DTLS: Info method=%s state=%s(%s), where=%d, ret=%d, r1=%d\n",
                    method, SSL_state_string(dtls), SSL_state_string_long(dtls), where, r0, r1);
    }
}

/**
 * Always return 1 to accept any certificate. This is because we allow the peer to
 * use a temporary self-signed certificate for DTLS.
 */
static int openssl_dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    return 1;
}

static int dtls_handshake(URLContext *h)
{
    int ret = 0, r0, r1;
    DTLSContext *p = h->priv_data;

    r0 = SSL_do_handshake(p->ssl);
    r1 = SSL_get_error(p->ssl, r0);
    if (r0 <= 0) {
        openssl_get_error(p);
        if (r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE && r1 != SSL_ERROR_ZERO_RETURN) {
            av_log(p, AV_LOG_ERROR, "DTLS: Read failed, r0=%d, r1=%d %s\n", r0, r1, p->error_message);
            ret = AVERROR(EIO);
            goto end;
        }
    } else {
        av_log(p, AV_LOG_TRACE, "DTLS: Read %d bytes, r0=%d, r1=%d\n", r0, r0, r1);
    }

    /* Check whether the DTLS is completed. */
    if (SSL_is_init_finished(p->ssl) != 1)
        goto end;

    p->tls_shared.state = DTLS_STATE_FINISHED;
end:
    return ret;
}

static int openssl_init_ca_key_cert(URLContext *h)
{
    int ret;
    DTLSContext *p = h->priv_data;
    TLSShared *c = &p->tls_shared;
    EVP_PKEY *dtls_pkey = NULL;
    X509 *dtls_cert = NULL;
    /* setup ca, private key, certificate */
    if (c->ca_file) {
        if (!SSL_CTX_load_verify_locations(p->ctx, c->ca_file, NULL))
            av_log(h, AV_LOG_ERROR, "SSL_CTX_load_verify_locations %s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    if (c->cert_file) {
        ret = SSL_CTX_use_certificate_chain_file(p->ctx, c->cert_file);
        if (ret <= 0) {
            av_log(h, AV_LOG_ERROR, "Unable to load cert file %s: %s\n",
               c->cert_file, ERR_error_string(ERR_get_error(), NULL));
            ret = AVERROR(EIO);
            goto fail;
        }
    } else if (p->tls_shared.cert_buf) {
        dtls_cert = cert_from_pem_string(p->tls_shared.cert_buf);
        if (SSL_CTX_use_certificate(p->ctx, dtls_cert) != 1) {
            av_log(p, AV_LOG_ERROR, "DTLS: Init SSL_CTX_use_certificate failed, %s\n", openssl_get_error(p));
            ret = AVERROR(EINVAL);
            return ret;
        }
    } else {
        av_log(p, AV_LOG_ERROR, "DTLS: Init cert failed, %s\n", openssl_get_error(p));
        ret = AVERROR(EINVAL);
        goto fail;
    }

    if (c->key_file) {
        ret = SSL_CTX_use_PrivateKey_file(p->ctx, c->key_file, SSL_FILETYPE_PEM);
        if (ret <= 0) {
            av_log(h, AV_LOG_ERROR, "Unable to load key file %s: %s\n",
                c->key_file, ERR_error_string(ERR_get_error(), NULL));
            ret = AVERROR(EIO);
            goto fail;
        }
    } else if (p->tls_shared.key_buf) {
        dtls_pkey = pkey_from_pem_string(p->tls_shared.key_buf, 1);
        if (SSL_CTX_use_PrivateKey(p->ctx, dtls_pkey) != 1) {
            av_log(p, AV_LOG_ERROR, "DTLS: Init SSL_CTX_use_PrivateKey failed, %s\n", openssl_get_error(p));
            ret = AVERROR(EINVAL);
            return ret;
        }
    } else {
        av_log(p, AV_LOG_ERROR, "DTLS: Init pkey failed, %s\n", openssl_get_error(p));
        ret = AVERROR(EINVAL);
        goto fail;
    }
    ret = 0;
fail:
    return ret;
}

/**
 * Initializes DTLS context using ECDHE.
 */
static av_cold int openssl_dtls_init_context(URLContext *h)
{
    int ret = 0;
    DTLSContext *p = h->priv_data;
    TLSShared *c = &p->tls_shared;
    const char* ciphers = "ALL";
    /**
     * The profile for OpenSSL's SRTP is SRTP_AES128_CM_SHA1_80, see ssl/d1_srtp.c.
     * The profile for FFmpeg's SRTP is SRTP_AES128_CM_HMAC_SHA1_80, see libavformat/srtp.c.
     */
    const char* profiles = "SRTP_AES128_CM_SHA1_80";
        
    /* Refer to the test cases regarding these curves in the WebRTC code. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L /* OpenSSL 1.1.0 */
    const char* curves = "X25519:P-256:P-384:P-521";
#elif OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL 1.0.2 */
    const char* curves = "P-256:P-384:P-521";
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L /* OpenSSL v1.0.2 */
    p->ctx = SSL_CTX_new(DTLSv1_method());
#else
    p->ctx = SSL_CTX_new(DTLS_method());
#endif
    if (!p->ctx) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL 1.0.2 */
    /* For ECDSA, we could set the curves list. */
    if (SSL_CTX_set1_curves_list(p->ctx, curves) != 1) {
        av_log(p, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set1_curves_list failed, curves=%s, %s\n",
            curves, openssl_get_error(p));
        ret = AVERROR(EINVAL);
        return ret;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
#if OPENSSL_VERSION_NUMBER < 0x10002000L // v1.0.2
    if (ctx->dtls_eckey)
        SSL_CTX_set_tmp_ecdh(p->ctx, p->dtls_eckey);
#else
    SSL_CTX_set_ecdh_auto(p->ctx, 1);
#endif
#endif

    /**
     * We activate "ALL" cipher suites to align with the peer's capabilities,
     * ensuring maximum compatibility.
     */
    if (SSL_CTX_set_cipher_list(p->ctx, ciphers) != 1) {
        av_log(p, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set_cipher_list failed, ciphers=%s, %s\n",
            ciphers, openssl_get_error(p));
        ret = AVERROR(EINVAL);
        return ret;
    }
    ret = openssl_init_ca_key_cert(h);
    if (ret < 0) goto fail;

    /* Server will send Certificate Request. */
    SSL_CTX_set_verify(p->ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, openssl_dtls_verify_callback);
    /* The depth count is "level 0:peer certificate", "level 1: CA certificate",
     * "level 2: higher level CA certificate", and so on. */
    SSL_CTX_set_verify_depth(p->ctx, 4);
    /* Whether we should read as many input bytes as possible (for non-blocking reads) or not. */
    SSL_CTX_set_read_ahead(p->ctx, 1);
    /* Setup the SRTP context */
    if (SSL_CTX_set_tlsext_use_srtp(p->ctx, profiles)) {
        av_log(p, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set_tlsext_use_srtp failed, profiles=%s, %s\n",
            profiles, openssl_get_error(p));
        ret = AVERROR(EINVAL);
        return ret;
    }

    /* The ssl should not be created unless the ctx has been initialized. */
    p->ssl = SSL_new(p->ctx);
    if (!p->ssl) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    /* Setup the callback for logging. */
    SSL_set_ex_data(p->ssl, 0, p);
    SSL_set_info_callback(p->ssl, openssl_dtls_on_info);

    /**
     * We have set the MTU to fragment the DTLS packet. It is important to note that the
     * packet is split to ensure that each handshake packet is smaller than the MTU.
     */
    SSL_set_options(p->ssl, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(p->ssl, p->tls_shared.mtu);
#if OPENSSL_VERSION_NUMBER >= 0x100010b0L /* OpenSSL 1.0.1k */
    DTLS_set_link_mtu(p->ssl, p->tls_shared.mtu);
#endif
    init_bio_method(h);
    return 0;
fail:
    // dtls_close(h);
    return ret;
}

/**
 * Once the DTLS role has been negotiated - active for the DTLS client or passive for the
 * DTLS server - we proceed to set up the DTLS state and initiate the handshake.
 */
static int dtls_start(URLContext *h, const char *url, int flags, AVDictionary **options)
{
    DTLSContext *p = h->priv_data;
    TLSShared *c = &p->tls_shared;
    int ret = 0;
    c->is_dtls = 1;
    
    if ((ret = openssl_dtls_init_context(h)) < 0) {
        av_log(p, AV_LOG_ERROR, "DTLS: Failed to initialize DTLS context\n");
        return ret;
    }

    if (p->tls_shared.use_external_udp != 1) {
        if ((ret = ff_tls_open_underlying(&p->tls_shared, h, url, options)) < 0) {
            av_log(p, AV_LOG_ERROR, "WHIP: Failed to connect %s\n", url);
            return ret;
        }
    }

    /* Setup DTLS as passive, which is server role. */
    c->listen ? SSL_set_accept_state(p->ssl) : SSL_set_connect_state(p->ssl);

    /**
     * During initialization, we only need to call SSL_do_handshake once because SSL_read consumes
     * the handshake message if the handshake is incomplete.
     * To simplify maintenance, we initiate the handshake for both the DTLS server and client after
     * sending out the ICE response in the start_active_handshake function. It's worth noting that
     * although the DTLS server may receive the ClientHello immediately after sending out the ICE
     * response, this shouldn't be an issue as the handshake function is called before any DTLS
     * packets are received.
     * 
     * The SSL_do_handshake can't be called if DTLS hasn't prepare for udp.
     */
    if (p->tls_shared.use_external_udp != 1) {
        ret = dtls_handshake(h);
        // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
        if (ret < 0) {
            av_log(p, AV_LOG_ERROR, "DTLS: Failed to drive SSL context, ret=%d\n", ret);
            return AVERROR(EIO);
        }
    }

    av_log(p, AV_LOG_VERBOSE, "DTLS: Setup ok, MTU=%d, fingerprint %s\n", 
        p->tls_shared.mtu, p->tls_shared.fingerprint);

    return ret;
}

static int dtls_read(URLContext *h, uint8_t *buf, int size)
{
    DTLSContext *c = h->priv_data;
    int ret;

    ret = SSL_read(c->ssl, buf, size);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;
    return print_ssl_error(h, ret);
}

/**
 * DTLS handshake with server, as a server in passive mode, using openssl.
 *
 * This function initializes the SSL context as the client role using OpenSSL and
 * then performs the DTLS handshake until success. Upon successful completion, it
 * exports the SRTP material key.
 *
 * @return 0 if OK, AVERROR_xxx on error
 */
static int dtls_write(URLContext *h, const uint8_t* buf, int size)
{
    DTLSContext *c = h->priv_data;
    int ret = 0;

    ret = SSL_write(c->ssl, buf, size);
    if (ret > 0)
        return ret;
    if (ret == 0)
        return AVERROR_EOF;

    return print_ssl_error(h, ret);
}

/**
 * Cleanup the DTLS context.
 */
static av_cold int dtls_close(URLContext *h)
{
    DTLSContext *ctx = h->priv_data;
    SSL_free(ctx->ssl);
    SSL_CTX_free(ctx->ctx);
    av_freep(&ctx->tls_shared.fingerprint);
    av_freep(&ctx->tls_shared.cert_buf);
    av_freep(&ctx->tls_shared.key_buf);
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_KEY_free(ctx->dtls_eckey);
#endif
    return 0;
}

static const AVOption options[] = {
    TLS_COMMON_OPTIONS(DTLSContext, tls_shared),
    { NULL }
};

static const AVClass dtls_class = {
    .class_name = "dtls",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_dtls_protocol = {
    .name           = "dtls",
    .url_open2      = dtls_start,
    .url_handshake  = dtls_handshake,
    .url_read       = dtls_read,
    .url_write      = dtls_write,
    .url_close      = dtls_close,
    .priv_data_size = sizeof(DTLSContext),
    .flags          = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class = &dtls_class,
};