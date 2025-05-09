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

/* Calculate the elapsed time from starttime to endtime in milliseconds. */
#define ELAPSED(starttime, endtime) ((int)(endtime - starttime) / 1000)

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

typedef struct DTLSContext {
    AVClass *av_class;

    enum DTLSState state;

    int use_external_udp;
    URLContext *udp_uc;
    char *http_proxy;
    /* temporarily don't need this to save AVFormatContext point */
    void* opaque;

    /* The DTLS context. */
    SSL_CTX *dtls_ctx;
    SSL *dtls;
    /* The DTLS BIOs. */
    BIO *bio;
#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    BIO_METHOD* url_bio_method;
#endif

    /* The private key for DTLS handshake. */
    EVP_PKEY *dtls_pkey;
    /* The EC key for DTLS handshake. */
    EC_KEY* dtls_eckey;
    /* The SSL certificate used for fingerprint in SDP and DTLS handshake. */
    X509 *dtls_cert;
    /* The fingerprint of certificate, used in SDP offer. */
    char *dtls_fingerprint;

    /* Whether the DTLS is done at least for us. */
    int dtls_done_for_us;
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

    /* The certificate and private key content used for DTLS hanshake */
    char* cert_buf;
    char* key_buf;
    /**
     * The size of RTP packet, should generally be set to MTU.
     * Note that pion requires a smaller value, for example, 1200.
     */
    int mtu;
} DTLSContext;

#endif /* AVFORMAT_DTLS_H */