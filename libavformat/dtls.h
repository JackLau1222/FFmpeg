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

#ifndef AVFORMAT_DTLS_H
#define AVFORMAT_DTLS_H

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "libavutil/bprint.h"

#include "libavutil/opt.h"
#include "internal.h"
#include "network.h"


/**
 * Maximum size limit of a certificate and private key size.
 */
#define MAX_CERTIFICATE_SIZE 8192

/**
 * The size of the Secure Real-time Transport Protocol (SRTP) master key material
 * that is exported by Secure Sockets Layer (SSL) after a successful Datagram
 * Transport Layer Security (DTLS) handshake. This material consists of a key
 * of 16 bytes and a salt of 14 bytes.
 */
#define DTLS_SRTP_KEY_LEN 16
#define DTLS_SRTP_SALT_LEN 14

/**
 * The maximum size of the Secure Real-time Transport Protocol (SRTP) HMAC checksum
 * and padding that is appended to the end of the packet. To calculate the maximum
 * size of the User Datagram Protocol (UDP) packet that can be sent out, subtract
 * this size from the `pkt_size`.
 */
#define DTLS_SRTP_CHECKSUM_LEN 16

/**
 * When sending ICE or DTLS messages, responses are received via UDP. However, the peer
 * may not be ready and return EAGAIN, in which case we should wait for a short duration
 * and retry reading.
 * For instance, if we try to read from UDP and get EAGAIN, we sleep for 5ms and retry.
 * This macro is used to limit the total duration in milliseconds (e.g., 50ms), so we
 * will try at most 5 times.
 * Keep in mind that this macro should have a minimum duration of 5 ms.
 */
#define ICE_DTLS_READ_INTERVAL 50

/* The magic cookie for Session Traversal Utilities for NAT (STUN) messages. */
#define STUN_MAGIC_COOKIE 0x2112A442

/**
 * The DTLS content type.
 * See https://tools.ietf.org/html/rfc2246#section-6.2.1
 * change_cipher_spec(20), alert(21), handshake(22), application_data(23)
 */
#define DTLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC 20

/**
 * The DTLS record layer header has a total size of 13 bytes, consisting of
 * ContentType (1 byte), ProtocolVersion (2 bytes), Epoch (2 bytes),
 * SequenceNumber (6 bytes), and Length (2 bytes).
 * See https://datatracker.ietf.org/doc/html/rfc9147#section-4
 */
#define DTLS_RECORD_LAYER_HEADER_LEN 13

/**
 * The DTLS version number, which is 0xfeff for DTLS 1.0, or 0xfefd for DTLS 1.2.
 * See https://datatracker.ietf.org/doc/html/rfc9147#name-the-dtls-record-layer
 */
#define DTLS_VERSION_10 0xfeff
#define DTLS_VERSION_12 0xfefd

/* Calculate the elapsed time from starttime to endtime in milliseconds. */
#define ELAPSED(starttime, endtime) ((int)(endtime - starttime) / 1000)

/**
 * Read all data from the given URL url and store it in the given buffer bp.
 */
static int url_read_all(AVFormatContext *s, const char *url, AVBPrint *bp)
{
    int ret = 0;
    AVDictionary *opts = NULL;
    URLContext *uc = NULL;
    char buf[MAX_URL_SIZE];

    // ret = ffurl_open_whitelist(&uc, url, AVIO_FLAG_READ, &s->interrupt_callback,
    //     &opts, s->protocol_whitelist, s->protocol_blacklist, NULL);
    ret = ffurl_open_whitelist(&uc, url, AVIO_FLAG_READ, NULL,
        &opts, NULL, NULL, NULL);
    if (ret < 0) {
        av_log(s, AV_LOG_ERROR, "WHIP: Failed to open url %s\n", url);
        goto end;
    }

    while (1) {
        ret = ffurl_read(uc, buf, sizeof(buf));
        if (ret == AVERROR_EOF) {
            /* Reset the error because we read all response as answer util EOF. */
            ret = 0;
            break;
        }
        if (ret <= 0) {
            av_log(s, AV_LOG_ERROR, "WHIP: Failed to read from url=%s, key is %s\n", url, bp->str);
            goto end;
        }

        av_bprintf(bp, "%.*s", ret, buf);
        if (!av_bprint_is_complete(bp)) {
            av_log(s, AV_LOG_ERROR, "WHIP: Exceed max size %.*s, %s\n", ret, buf, bp->str);
            ret = AVERROR(EIO);
            goto end;
        }
    }

end:
    ffurl_closep(&uc);
    av_dict_free(&opts);
    return ret;
}

/* STUN Attribute, comprehension-required range (0x0000-0x7FFF) */
enum STUNAttr {
    STUN_ATTR_USERNAME                  = 0x0006, /// shared secret response/bind request
    STUN_ATTR_USE_CANDIDATE             = 0x0025, /// bind request
    STUN_ATTR_MESSAGE_INTEGRITY         = 0x0008, /// bind request/response
    STUN_ATTR_FINGERPRINT               = 0x8028, /// rfc5389
};

enum DTLSState {
    DTLS_STATE_NONE,

    /* Whether DTLS handshake is finished. */
    DTLS_STATE_FINISHED,
    /* Whether DTLS session is closed. */
    DTLS_STATE_CLOSED,
    /* Whether DTLS handshake is failed. */
    DTLS_STATE_FAILED,
};

typedef struct DTLSContext DTLSContext;
typedef int (*DTLSContext_on_state_fn)(DTLSContext *ctx, enum DTLSState state, const char* type, const char* desc);
typedef int (*DTLSContext_on_write_fn)(DTLSContext *ctx, char* data, int size);

typedef struct DTLSContext {
    AVClass *av_class;

    /* For callback. */
    DTLSContext_on_state_fn on_state;
    DTLSContext_on_write_fn on_write;

    URLContext *udp_uc;

    void* opaque;

    /* For logging. */
    AVClass *log_avcl;

    /* The DTLS context. */
    SSL_CTX *dtls_ctx;
    SSL *dtls;
    /* The DTLS BIOs. */
    BIO *bio_in;

    /* The private key for DTLS handshake. */
    EVP_PKEY *dtls_pkey;
    /* The EC key for DTLS handshake. */
    EC_KEY* dtls_eckey;
    /* The SSL certificate used for fingerprint in SDP and DTLS handshake. */
    X509 *dtls_cert;
    /* The fingerprint of certificate, used in SDP offer. */
    char *dtls_fingerprint;

    /**
     * This represents the material used to build the SRTP master key. It is
     * generated by DTLS and has the following layout:
     *          16B         16B         14B             14B
     *      client_key | server_key | client_salt | server_salt
     */
    uint8_t dtls_srtp_materials[(DTLS_SRTP_KEY_LEN + DTLS_SRTP_SALT_LEN) * 2];

    /* Whether the DTLS is done at least for us. */
    int dtls_done_for_us;
    /* Whether the SRTP key is exported. */
    int dtls_srtp_key_exported;
    /* The number of packets retransmitted for DTLS. */
    int dtls_arq_packets;
    /**
     * This is the last DTLS content type and handshake type that is used to detect
     * the ARQ packet.
     */
    uint8_t dtls_last_content_type;
    uint8_t dtls_last_handshake_type;

    /* These variables represent timestamps used for calculating and tracking the cost. */
    int64_t dtls_init_starttime;
    int64_t dtls_init_endtime;
    int64_t dtls_handshake_starttime;
    int64_t dtls_handshake_endtime;

    /* Helper for get error code and message. */
    int error_code;
    char error_message[256];

    /* The certificate and private key used for DTLS handshake. */
    char* cert_file;
    char* key_file;
    /**
     * The size of RTP packet, should generally be set to MTU.
     * Note that pion requires a smaller value, for example, 1200.
     */
    int mtu;
} DTLSContext;

int is_dtls_packet(uint8_t *b, int size);

// av_cold int dtls_context_init(AVFormatContext *s, DTLSContext *ctx);

// int dtls_context_start(URLContext *h, const char *url, int flags, AVDictionary **options);

// int dtls_context_write(URLContext *h, const uint8_t* buf, int size);

// av_cold int dtls_context_deinit(URLContext *h);

#endif /* AVFORMAT_DTLS_H */