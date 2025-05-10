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

#include "libavutil/bprint.h"

#include "libavutil/opt.h"
#include "internal.h"
#include "network.h"

/**
 * Maximum size limit of a certificate and private key size.
 */
#define MAX_CERTIFICATE_SIZE 8192

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

typedef struct DTLSShared {
    enum DTLSState state;

    int use_external_udp;
    URLContext *udp_uc;
    char *http_proxy;
    /* temporarily don't need this to save AVFormatContext point */
    void* opaque;

    /* The fingerprint of certificate, used in SDP offer. */
    char *dtls_fingerprint;

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
} DTLSShared;

#define DTLS_OPTFL (AV_OPT_FLAG_DECODING_PARAM | AV_OPT_FLAG_ENCODING_PARAM)
#define DTLS_COMMON_OPTIONS(pstruct, options_field) \
    { "use_external_udp", "Use external UDP from muxer or demuxer", offsetof(pstruct, options_field . use_external_udp), AV_OPT_TYPE_INT, { .i64 = 0}, 0, 1, .flags = DTLS_OPTFL }, \
    { "mtu", "Maximum Transmission Unit", offsetof(pstruct, options_field . mtu), AV_OPT_TYPE_INT,  { .i64 = 0}, INT64_MIN, INT64_MAX, .flags = DTLS_OPTFL}, \
    { "dtls_fingerprint", "The optional fingerprint for DTLS", offsetof(pstruct, options_field . dtls_fingerprint), AV_OPT_TYPE_STRING, .flags = DTLS_OPTFL}, \
    { "cert_buf", "The optional certificate buffer for DTLS", offsetof(pstruct, options_field . cert_buf), AV_OPT_TYPE_STRING, .flags = DTLS_OPTFL}, \
    { "key_buf", "The optional private key buffer for DTLS", offsetof(pstruct, options_field . key_buf), AV_OPT_TYPE_STRING, .flags = DTLS_OPTFL}

int ff_dtls_open_underlying(DTLSShared *c, URLContext *parent, const char *uri, AVDictionary **options);

int url_read_all(const char *url, AVBPrint *bp);

int ff_dtls_set_udp(URLContext *dtls, URLContext *udp);

int ff_dtls_export_materials(URLContext *dtls, char *dtls_srtp_materials);

int ff_dtls_state(URLContext *dtls);

int ssl_read_key_cert(char *key_url, char *cert_url, char *key_buf, size_t key_sz, char *cert_buf, size_t cert_sz, char **fingerprint);

int ssl_gen_key_cert(char *key_buf, size_t key_sz, char *cert_buf, size_t cert_sz, char **fingerprint);

#endif /* AVFORMAT_DTLS_H */