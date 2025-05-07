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

#include "dtls.h"

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

static void openssl_dtls_state_trace(DTLSContext *ctx, uint8_t *data, int length, int incoming);

static int ff_dtls_open_underlying(DTLSContext *c, URLContext *parent, const char *uri, AVDictionary **options)
{
    int port;
    char host[200];
    const char *p;
    char buf[200], opts[50] = "";
    struct addrinfo hints = { 0 }, *ai = NULL;
    const char *proxy_path;
    char *env_http_proxy, *env_no_proxy;
    int use_proxy;
    int ret;

    // ret = set_options(c, uri);
    // if (ret < 0)
    //     return ret;

    // if (c->listen)
    //     snprintf(opts, sizeof(opts), "?listen=1");

    av_url_split(NULL, 0, NULL, 0, host, sizeof(host), &port, NULL, 0, uri);

    av_dict_set_int(&opts, "connect", 1, 0);
    av_dict_set_int(&opts, "fifo_size", 0, 0);
    /* Set the max packet size to the buffer size. */
    av_dict_set_int(&opts, "pkt_size", c->mtu, 0);

    p = strchr(uri, '?');

    if (!p) {
        p = opts;
    } else {
        // if (av_find_info_tag(opts, sizeof(opts), "listen", p))
        //     c->listen = 1;
    }

    ff_url_join(buf, sizeof(buf), "udp", NULL, host, ++port, "%s", p);

    hints.ai_flags = AI_NUMERICHOST;
    if (!getaddrinfo(host, NULL, &hints, &ai)) {
        // c->numerichost = 1;
        freeaddrinfo(ai);
    }

    // if (!host && !(host = av_strdup(host)))
    //     return AVERROR(ENOMEM);

    env_http_proxy = getenv_utf8("http_proxy");
    proxy_path = c->http_proxy ? c->http_proxy : env_http_proxy;

    env_no_proxy = getenv_utf8("no_proxy");
    use_proxy = !ff_http_match_no_proxy(env_no_proxy, host) &&
                proxy_path && av_strstart(proxy_path, "http://", NULL);
    freeenv_utf8(env_no_proxy);

    if (use_proxy) {
        char proxy_host[200], proxy_auth[200], dest[200];
        int proxy_port;
        av_url_split(NULL, 0, proxy_auth, sizeof(proxy_auth),
                     proxy_host, sizeof(proxy_host), &proxy_port, NULL, 0,
                     proxy_path);
        ff_url_join(dest, sizeof(dest), NULL, NULL, host, port, NULL);
        ff_url_join(buf, sizeof(buf), "httpproxy", proxy_auth, proxy_host,
                    proxy_port, "/%s", dest);
    }

    freeenv_utf8(env_http_proxy);
    ret = ffurl_open_whitelist(&c->udp_uc, buf, AVIO_FLAG_READ_WRITE,
                                &parent->interrupt_callback, options,
                                parent->protocol_whitelist, parent->protocol_blacklist, parent);

    if (ret < 0) {
        av_log(c, AV_LOG_ERROR, "WHIP: Failed to connect udp://%s:%d\n", host, port);
        return ret;
    }

    /* Make the socket non-blocking, set to READ and WRITE mode after connected */
    ff_socket_nonblock(ffurl_get_file_handle(c->udp_uc), 1);
    c->udp_uc->flags |= AVIO_FLAG_READ | AVIO_FLAG_NONBLOCK;
    return 0;
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



/**
 * Whether the packet is a DTLS packet.
 */
int is_dtls_packet(uint8_t *b, int size) {
    uint16_t version = AV_RB16(&b[1]);
    return size > DTLS_RECORD_LAYER_HEADER_LEN &&
        b[0] >= DTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC &&
        (version == DTLS_VERSION_10 || version == DTLS_VERSION_12);
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
    int ret = ffurl_read(c->udp_uc, buf, len);
    if (ret >= 0)
        return ret;
    BIO_clear_retry_flags(b);
    if (ret == AVERROR_EXIT)
        return 0;
    if (ret == AVERROR(EAGAIN))
        BIO_set_retry_read(b);
    else
        c->error_code = ret;
    openssl_dtls_state_trace(c, buf, len, 1);
    return -1;
}

static int url_bio_bwrite(BIO *b, const char *buf, int len)
{
    DTLSContext *c = GET_BIO_DATA(b);
    int ret = ffurl_write(c->udp_uc, buf, len);
    if (ret >= 0)
        return ret;
    BIO_clear_retry_flags(b);
    if (ret == AVERROR_EXIT)
        return 0;
    if (ret == AVERROR(EAGAIN))
        BIO_set_retry_write(b);
    else
        c->error_code = ret;
    openssl_dtls_state_trace(c, buf, len, 0);
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

/**
 * Get the error code for the given SSL operation result.
 *
 * This function retrieves the error code for the given SSL operation result
 * and stores the error message in the DTLS context if an error occurred.
 * It also clears the error queue.
 */
static int openssl_ssl_get_error(DTLSContext *ctx, int ret)
{
    SSL *dtls = ctx->dtls;
    int r1 = SSL_ERROR_NONE;

    if (ret <= 0)
        r1 = SSL_get_error(dtls, ret);

    openssl_get_error(ctx);
    return r1;
}

/**
 * Callback function to print the OpenSSL SSL status.
 */
static void openssl_dtls_on_info(const SSL *dtls, int where, int r0)
{
    int w, r1, is_fatal, is_warning, is_close_notify;
    const char *method = "undefined", *alert_type, *alert_desc;
    enum DTLSState state;
    DTLSContext *ctx = (DTLSContext*)SSL_get_ex_data(dtls, 0);

    w = where & ~SSL_ST_MASK;
    if (w & SSL_ST_CONNECT)
        method = "SSL_connect";
    else if (w & SSL_ST_ACCEPT)
        method = "SSL_accept";

    r1 = openssl_ssl_get_error(ctx, r0);
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
        state = is_fatal ? DTLS_STATE_FAILED : (is_warning && is_close_notify ? DTLS_STATE_CLOSED : DTLS_STATE_NONE);
        if (state != DTLS_STATE_NONE && ctx->on_state) {
            av_log(ctx, AV_LOG_INFO, "DTLS: Notify ctx=%p, state=%d, fatal=%d, warning=%d, cn=%d\n",
                ctx, state, is_fatal, is_warning, is_close_notify);
            ctx->on_state(ctx, state, alert_type, alert_desc);
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

static void openssl_dtls_state_trace(DTLSContext *ctx, uint8_t *data, int length, int incoming)
{
    uint8_t content_type = 0;
    uint16_t size = 0;
    uint8_t handshake_type = 0;

    /* Change_cipher_spec(20), alert(21), handshake(22), application_data(23) */
    if (length >= 1)
        content_type = AV_RB8(&data[0]);
    if (length >= 13)
        size = AV_RB16(&data[11]);
    if (length >= 14)
        handshake_type = AV_RB8(&data[13]);

    av_log(ctx, AV_LOG_VERBOSE, "DTLS: Trace %s, done=%u, arq=%u, len=%u, cnt=%u, size=%u, hs=%u\n",
        (incoming? "RECV":"SEND"), ctx->dtls_done_for_us, ctx->dtls_arq_packets, length,
        content_type, size, handshake_type);
}

/**
 * Always return 1 to accept any certificate. This is because we allow the peer to
 * use a temporary self-signed certificate for DTLS.
 */
static int openssl_dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    return 1;
}

/**
 * DTLS BIO read callback.
 */
#if OPENSSL_VERSION_NUMBER < 0x30000000L // v3.0.x
static long openssl_dtls_bio_out_callback(BIO* b, int oper, const char* argp, int argi, long argl, long retvalue)
#else
static long openssl_dtls_bio_out_callback_ex(BIO *b, int oper, const char *argp, size_t len, int argi, long argl, int retvalue, size_t *processed)
#endif
{
    int ret, req_size = argi, is_arq = 0;
    uint8_t content_type, handshake_type;
    uint8_t *data = (uint8_t*)argp;
    DTLSContext* ctx = b ? (DTLSContext*)BIO_get_callback_arg(b) : NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L // v3.0.x
    req_size = len;
    av_log(ctx, AV_LOG_DEBUG, "DTLS: BIO callback b=%p, oper=%d, argp=%p, len=%ld, argi=%d, argl=%ld, retvalue=%d, processed=%p, req_size=%d\n",
        b, oper, argp, len, argi, argl, retvalue, processed, req_size);
#else
    av_log(ctx, AV_LOG_DEBUG, "DTLS: BIO callback b=%p, oper=%d, argp=%p, argi=%d, argl=%ld, retvalue=%ld, req_size=%d\n",
        b, oper, argp, argi, argl, retvalue, req_size);
#endif

    if (oper != BIO_CB_WRITE || !argp || req_size <= 0)
        return retvalue;

    openssl_dtls_state_trace(ctx, data, req_size, 0);
    ret = ctx->on_write ? ctx->on_write(ctx, data, req_size) : 0;
    content_type = req_size > 0 ? AV_RB8(&data[0]) : 0;
    handshake_type = req_size > 13 ? AV_RB8(&data[13]) : 0;

    is_arq = ctx->dtls_last_content_type == content_type && ctx->dtls_last_handshake_type == handshake_type;
    ctx->dtls_arq_packets += is_arq;
    ctx->dtls_last_content_type = content_type;
    ctx->dtls_last_handshake_type = handshake_type;

    if (ret < 0) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Send request failed, oper=%d, content=%d, handshake=%d, size=%d, is_arq=%d\n",
            oper, content_type, handshake_type, req_size, is_arq);
        return ret;
    }

    return retvalue;
}

/**
 * Initializes DTLS context using ECDHE.
 */
static av_cold int openssl_dtls_init_context(DTLSContext *ctx)
{
    int ret = 0;
    EVP_PKEY *dtls_pkey = ctx->dtls_pkey;
    X509 *dtls_cert = ctx->dtls_cert;
    SSL_CTX *dtls_ctx = NULL;
    SSL *dtls = NULL;
    BIO *bio = NULL;
    const char* ciphers = "ALL";
    /**
     * The profile for OpenSSL's SRTP is SRTP_AES128_CM_SHA1_80, see ssl/d1_srtp.c.
     * The profile for FFmpeg's SRTP is SRTP_AES128_CM_HMAC_SHA1_80, see libavformat/srtp.c.
     */
    const char* profiles = "SRTP_AES128_CM_SHA1_80";
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ctx->url_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "urlprotocol bio");
    BIO_meth_set_write(ctx->url_bio_method, url_bio_bwrite);
    BIO_meth_set_read(ctx->url_bio_method, url_bio_bread);
    BIO_meth_set_puts(ctx->url_bio_method, url_bio_bputs);
    BIO_meth_set_ctrl(ctx->url_bio_method, url_bio_ctrl);
    BIO_meth_set_create(ctx->url_bio_method, url_bio_create);
    BIO_meth_set_destroy(ctx->url_bio_method, url_bio_destroy);
    bio = BIO_new(ctx->url_bio_method);
    BIO_set_data(bio, ctx);
#else
    bio = BIO_new(&url_bio_method);
    bio->ptr = p;
#endif
    /* setup private key and certificate */
    if (ctx->key_buf)
        dtls_pkey = pkey_from_pem_string(ctx->key_buf, 1);
    else {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init pkey failed, %s\n", openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        goto end;
    }
    if (ctx->cert_buf)
        dtls_cert = cert_from_pem_string(ctx->cert_buf);
    else {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init cert failed, %s\n", openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        goto end;
    }
        
    /* Refer to the test cases regarding these curves in the WebRTC code. */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L /* OpenSSL 1.1.0 */
    const char* curves = "X25519:P-256:P-384:P-521";
#elif OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL 1.0.2 */
    const char* curves = "P-256:P-384:P-521";
#endif

#if OPENSSL_VERSION_NUMBER < 0x10002000L /* OpenSSL v1.0.2 */
    dtls_ctx = ctx->dtls_ctx = SSL_CTX_new(DTLSv1_method());
#else
    dtls_ctx = ctx->dtls_ctx = SSL_CTX_new(DTLS_method());
#endif
    if (!dtls_ctx) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10002000L /* OpenSSL 1.0.2 */
    /* For ECDSA, we could set the curves list. */
    if (SSL_CTX_set1_curves_list(dtls_ctx, curves) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set1_curves_list failed, curves=%s, %s\n",
            curves, openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L // v1.1.x
#if OPENSSL_VERSION_NUMBER < 0x10002000L // v1.0.2
    if (ctx->dtls_eckey)
        SSL_CTX_set_tmp_ecdh(dtls_ctx, ctx->dtls_eckey);
#else
    SSL_CTX_set_ecdh_auto(dtls_ctx, 1);
#endif
#endif

    /**
     * We activate "ALL" cipher suites to align with the peer's capabilities,
     * ensuring maximum compatibility.
     */
    if (SSL_CTX_set_cipher_list(dtls_ctx, ciphers) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set_cipher_list failed, ciphers=%s, %s\n",
            ciphers, openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }
    /* Setup the certificate. */
    if (SSL_CTX_use_certificate(dtls_ctx, dtls_cert) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_use_certificate failed, %s\n", openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }
    if (SSL_CTX_use_PrivateKey(dtls_ctx, dtls_pkey) != 1) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_use_PrivateKey failed, %s\n", openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }

    /* Server will send Certificate Request. */
    SSL_CTX_set_verify(dtls_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, openssl_dtls_verify_callback);
    /* The depth count is "level 0:peer certificate", "level 1: CA certificate",
     * "level 2: higher level CA certificate", and so on. */
    SSL_CTX_set_verify_depth(dtls_ctx, 4);
    /* Whether we should read as many input bytes as possible (for non-blocking reads) or not. */
    SSL_CTX_set_read_ahead(dtls_ctx, 1);
    /* Setup the SRTP context */
    if (SSL_CTX_set_tlsext_use_srtp(dtls_ctx, profiles)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Init SSL_CTX_set_tlsext_use_srtp failed, profiles=%s, %s\n",
            profiles, openssl_get_error(ctx));
        ret = AVERROR(EINVAL);
        return ret;
    }

    /* The dtls should not be created unless the dtls_ctx has been initialized. */
    dtls = ctx->dtls = SSL_new(dtls_ctx);
    if (!dtls) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* Setup the callback for logging. */
    SSL_set_ex_data(dtls, 0, ctx);
    SSL_set_info_callback(dtls, openssl_dtls_on_info);

    /**
     * We have set the MTU to fragment the DTLS packet. It is important to note that the
     * packet is split to ensure that each handshake packet is smaller than the MTU.
     */
    SSL_set_options(dtls, SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(dtls, ctx->mtu);
#if OPENSSL_VERSION_NUMBER >= 0x100010b0L /* OpenSSL 1.0.1k */
    DTLS_set_link_mtu(dtls, ctx->mtu);
#endif

    // bio = BIO_new(ctx->url_bio_method);
    // if (!bio) {
    //     ret = AVERROR(ENOMEM);
    //     goto end;
    // }

    // bio_out = BIO_new(BIO_s_mem());
    // if (!bio_out) {
    //     ret = AVERROR(ENOMEM);
    //     goto end;
    // }

    /**
     * Please be aware that it is necessary to use a callback to obtain the packet to be written out. It is
     * imperative that BIO_get_mem_data is not used to retrieve the packet, as it returns all the bytes that
     * need to be sent out.
     * For example, if MTU is set to 1200, and we got two DTLS packets to sendout:
     *      ServerHello, 95bytes.
     *      Certificate, 1105+143=1248bytes.
     * If use BIO_get_mem_data, it will return 95+1248=1343bytes, which is larger than MTU 1200.
     * If use callback, it will return two UDP packets:
     *      ServerHello+Certificate(Frament) = 95+1105=1200bytes.
     *      Certificate(Fragment) = 143bytes.
     * Note that there should be more packets in real world, like ServerKeyExchange, CertificateRequest,
     * and ServerHelloDone. Here we just use two packets for example.
     */
// #if OPENSSL_VERSION_NUMBER < 0x30000000L // v3.0.x
//     BIO_set_callback(bio, openssl_dtls_bio_out_callback);
// #else
//     BIO_set_callback_ex(bio, openssl_dtls_bio_out_callback_ex);
// #endif
//     BIO_set_callback_arg(bio, (char*)ctx);

    ctx->bio = bio;
    SSL_set_bio(dtls, bio, bio);
    /* Now the bio and bio_out are owned by dtls, so we should set them to NULL. */
    bio = NULL;

end:
    BIO_free(bio);
    // BIO_free(bio_out);
    return ret;
}

/**
 * Once the DTLS role has been negotiated - active for the DTLS client or passive for the
 * DTLS server - we proceed to set up the DTLS state and initiate the handshake.
 */
static int dtls_context_start(URLContext *h, const char *url, int flags, AVDictionary **options)
{
    DTLSContext *ctx = h->priv_data;
    int ret = 0, r0, r1;
    SSL *dtls = NULL;

    ctx->dtls_init_starttime = av_gettime();
    
    if ((ret = openssl_dtls_init_context(ctx)) < 0) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to initialize DTLS context\n");
        return ret;
    }

    // if ((ret = ff_dtls_open_underlying(ctx, h, url, options)) < 0) {
    //     av_log(ctx, AV_LOG_ERROR, "WHIP: Failed to connect %s\n", url);
    //     return ret;
    // }

    dtls = ctx->dtls;

    ctx->dtls_handshake_starttime = av_gettime();

    /* Setup DTLS as passive, which is server role. */
    SSL_set_accept_state(dtls);

    /**
     * During initialization, we only need to call SSL_do_handshake once because SSL_read consumes
     * the handshake message if the handshake is incomplete.
     * To simplify maintenance, we initiate the handshake for both the DTLS server and client after
     * sending out the ICE response in the start_active_handshake function. It's worth noting that
     * although the DTLS server may receive the ClientHello immediately after sending out the ICE
     * response, this shouldn't be an issue as the handshake function is called before any DTLS
     * packets are received.
     */
    // r0 = SSL_do_handshake(dtls);
    r1 = openssl_ssl_get_error(ctx, r0);
    // Fatal SSL error, for example, no available suite when peer is DTLS 1.0 while we are DTLS 1.2.
    if (r0 < 0 && (r1 != SSL_ERROR_NONE && r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE)) {
        av_log(ctx, AV_LOG_ERROR, "DTLS: Failed to drive SSL context, r0=%d, r1=%d %s\n", r0, r1, ctx->error_message);
        return AVERROR(EIO);
    }

    ctx->dtls_init_endtime = av_gettime();
    av_log(ctx, AV_LOG_VERBOSE, "DTLS: Setup ok, MTU=%d, cost=%dms, fingerprint %s\n",
        ctx->mtu, ELAPSED(ctx->dtls_init_starttime, av_gettime()), ctx->dtls_fingerprint);

    return ret;
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
static int dtls_context_write(URLContext *h, const uint8_t* buf, int size)
{
    DTLSContext *ctx = h->priv_data;
    int ret = 0, res_ct, res_ht, r0, r1, do_callback;
    SSL *dtls = ctx->dtls;
    const char* dst = "EXTRACTOR-dtls_srtp";
    BIO *bio = ctx->bio;

    /* Got DTLS response successfully. */
    // openssl_dtls_state_trace(ctx, buf, size, 1);
    // if ((r0 = BIO_write(bio, buf, size)) <= 0) {
    //     res_ct = size > 0 ? buf[0]: 0;
    //     res_ht = size > 13 ? buf[13] : 0;
    //     av_log(ctx, AV_LOG_ERROR, "DTLS: Feed response failed, content=%d, handshake=%d, size=%d, r0=%d\n",
    //         res_ct, res_ht, size, r0);
    //     ret = AVERROR(EIO);
    //     goto error;
    // }

    /**
     * If there is data available in bio_in, use SSL_read to allow SSL to process it.
     * We limit the MTU to 1200 for DTLS handshake, which ensures that the buffer is large enough for reading.
     */
    // r0 = SSL_read(dtls, buf, sizeof(buf));
    r0 = SSL_write(dtls, buf, size);
    r1 = openssl_ssl_get_error(ctx, r0);
    if (r0 <= 0) {
        if (r1 != SSL_ERROR_WANT_READ && r1 != SSL_ERROR_WANT_WRITE && r1 != SSL_ERROR_ZERO_RETURN) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: Read failed, r0=%d, r1=%d %s\n", r0, r1, ctx->error_message);
            ret = AVERROR(EIO);
            goto error;
        }
    } else {
        av_log(ctx, AV_LOG_TRACE, "DTLS: Read %d bytes, r0=%d, r1=%d\n", r0, r0, r1);
    }

    /* Check whether the DTLS is completed. */
    if (SSL_is_init_finished(dtls) != 1)
        goto end;

    do_callback = ctx->on_state && !ctx->dtls_done_for_us;
    ctx->dtls_done_for_us = 1;
    ctx->dtls_handshake_endtime = av_gettime();

    /* Export SRTP master key after DTLS done */
    if (!ctx->dtls_srtp_key_exported) {
        ret = SSL_export_keying_material(dtls, ctx->dtls_srtp_materials, sizeof(ctx->dtls_srtp_materials),
            dst, strlen(dst), NULL, 0, 0);
        r1 = openssl_ssl_get_error(ctx, r0);
        if (!ret) {
            av_log(ctx, AV_LOG_ERROR, "DTLS: SSL export key ret=%d, r1=%d %s\n", ret, r1, ctx->error_message);
            ret = AVERROR(EIO);
            goto error;
        }

        ctx->dtls_srtp_key_exported = 1;
    }

    if (do_callback && (ret = ctx->on_state(ctx, DTLS_STATE_FINISHED, NULL, NULL)) < 0)
        goto end;

error:
    //return ret;
end:
    return size;
}

/**
 * Cleanup the DTLS context.
 */
static av_cold int dtls_context_deinit(URLContext *h)
{
    DTLSContext *ctx = h->priv_data;
    SSL_free(ctx->dtls);
    SSL_CTX_free(ctx->dtls_ctx);
    X509_free(ctx->dtls_cert);
    EVP_PKEY_free(ctx->dtls_pkey);
    av_freep(&ctx->dtls_fingerprint);
    av_freep(&ctx->cert_buf);
    av_freep(&ctx->key_buf);
#if OPENSSL_VERSION_NUMBER < 0x30000000L /* OpenSSL 3.0 */
    EC_KEY_free(ctx->dtls_eckey);
#endif
    return 0;
}

#define OFFSET(x) offsetof(DTLSContext, x)
static const AVOption options[] = {
    { "mtu", "Maximum Transmission Unit", OFFSET(mtu), AV_OPT_TYPE_INT, { .i64 = -1}, -1, INT_MAX, AV_OPT_FLAG_DECODING_PARAM },
    { "dtls_fingerprint", "The optional fingerprint for DTLS", OFFSET(dtls_fingerprint), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, AV_OPT_FLAG_DECODING_PARAM },
    { "cert_buf", "The optional certificate buffer for DTLS", OFFSET(cert_buf), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, AV_OPT_FLAG_DECODING_PARAM },
    { "key_buf", "The optional private key buffer for DTLS", OFFSET(key_buf), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, AV_OPT_FLAG_DECODING_PARAM },
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
    .url_open2      = dtls_context_start,
    // .url_read       = tls_read,
    .url_write      = dtls_context_write,
    .url_close      = dtls_context_deinit,
    // .url_get_file_handle = tls_get_file_handle,
    // .url_get_short_seek  = tls_get_short_seek,
    .priv_data_size = sizeof(DTLSContext),
    .flags          = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class = &dtls_class,
};