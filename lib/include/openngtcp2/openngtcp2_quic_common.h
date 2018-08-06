/**
 * openngtcp2
 *
 * Copyright (C) 2018, TUTU 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions: 
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software. 
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL 
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
 * DEALINGS IN THE SOFTWARE. 
 * 
 **/


#ifndef OPENNGTCP2_QUIC_COMMON_H
#define OPENNGTCP2_QUIC_COMMON_H

#define QUIC_BUF_SIZE       (384)

/* version numbers */
#define QUIC_PROTO_VER_MAX QUIC_PROTO_VER_D12
#define QUIC_PROTO_VER_D12 0xff00000cu
#define QUIC_PROTO_VER_D11 0xff00000bu

/* alpn protocol */
#define QUIC_ALPN_D12 "hq-12"
#define QUIC_ALPN_D11 "hq-11"

typedef enum {
    QUIC_CTRL_TYPE_NONE = 0,
    QUIC_CTRL_TYPE_IDLE_TIMEOUT,
    QUIC_CTRL_TYPE_MAX_STREAM_DATA,
    QUIC_CTRL_TYPE_MAX_DATA,
    QUIC_CTRL_TYPE_ACK_DELAY_EXPONENT,
    QUIC_CTRL_TYPE_MAX_PKT_SIZE,
    QUIC_CTRL_TYPE_CIPHER_LIST,
    QUIC_CTRL_TYPE_GROUP_LIST,
    QUIC_CTRL_TYPE_SNI,
    QUIC_CTRL_TYPE_NSTREAMS,
    QUIC_CTRL_TYPE_FD,
    QUIC_CTRL_TYPE_DATA,
    QUIC_CTRL_TYPE_ERR_STR,
    QUIC_CTRL_TYPE_QUIC_CTX,
    QUIC_CTRL_TYPE_SSL_CTX,
    QUIC_CTRL_TYPE_SSL,
    QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS,
    QUIC_CTRL_TYPE_NGTCP2_SETTINGS,
    QUIC_CTRL_TYPE_NGTCP2_CONN,
    QUIC_CTRL_TYPE_MAX_BIDI_STREAMS,
    QUIC_CTRL_TYPE_MAX_UNI_STREAMS,
} quic_ctrl_type;

#define QUIC_DEFAULT_IDLE_TIMEOUT       (30)
#define QUIC_DEFAULT_MAX_STREAM_DATA    (256 * 1000)
#define QUIC_DEFAULT_MAX_DATA           (1 * 1000 * 1000)
#define QUIC_DEFAULT_ACK_DELAY_EXPONENT (NGTCP2_DEFAULT_ACK_DELAY_EXPONENT)

/* callbacks */
typedef int (*quic_alpn)(
    SSL *ssl,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen,
    void *arg);
typedef SSL_CTX_keylog_cb_func              quic_keylog;

#endif /* OPENNGTCP2_QUIC_COMMON_H */