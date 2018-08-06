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


#ifndef QUIC_H
#define QUIC_H

typedef enum {
    QUIC_TYPE_CONNECT = 1,
    QUIC_TYPE_ACCEPT
} quic_type_t;

typedef enum {
    QUIC_STATE_NONE = 0,
    QUIC_STATE_WRITE_RTT0,
    QUIC_STATE_RECV,
    QUIC_STATE_DO_HANDSHAKE,
    QUIC_STATE_DO_HANDSHAKE_ONCE,
    QUIC_STATE_FINISH_HANDSHAKE,
    QUIC_STATE_MAX
} quic_state_t;

struct quic_st {
    int             fd;
    QUIC_CTX        *quic_ctx;
    SSL             *ssl;
    char            errbuf[QUIC_ERRBUF_SIZE];
    void            *data;
    bool            resumption;
    bool            in_init;

    size_t          max_pktlen;

    ngtcp2_conn     *conn;

    //addr is peer address
    quic_type_t     type;
    QUIC_ADDR       addr;
    quic_state_t    prev_state;
    quic_state_t    state;

    /* ngtcp2 */
    ngtcp2_conn_callbacks   callbacks;
    ngtcp2_settings         settings;
    ngtcp2_cid              scid, dcid, rcid;
    u_int32_t               version;
    bool                    set_transport_params;
    ngtcp2_transport_params params;

    /* ngtcp2 crypto context */
    QUIC_CRYPTO_CTX hs_crypto_ctx;
    QUIC_CRYPTO_CTX crypto_ctx;

    /* user stream that before handshake */
    quic_deque_t    *pre_streams;

    /* user stream */
    quic_stream_map_t *streams;

    /* handshake */
    //chandshake_idx is the index in chandshake, which points to the buffer to read next.
    union {
        quic_deque_t        *c;
        quic_byte_array_t   *s;
    } chandshake;
    size_t          chandshake_idx;
    size_t          shandshake_idx;

    /* handshake */
    union {
        quic_byte_array_t *c;
        quic_deque_t      *s;
    } shandshake;

    /* buffer */
    quic_buf_t      *sendbuf;
    quic_buf_t      *recvbuf;
    quic_stream_t   *recv_temp;
    size_t          nsread;
    size_t          ncread;

    u_int64_t       tx_stream0_offset;
    size_t          nstreams;

    /* for QUIC_shutdown() */
    ngtcp2_lib_error    shutdown_code;
    quic_buf_t          *closebuf;

    /* for OpenSSL */
    char        *ssl_ciphers;
    char        *ssl_groups;
    char        *ssl_sni;

    /* bio interface */
    BIO *rbio;
    BIO *wbio;

    bool initial;
};

/* quic.c */
quic_err_t quic_set_fd(QUIC *quic, int fd);
ngtcp2_lib_error quic_read_tls(QUIC *quic, size_t *idx);
quic_err_t quic_setup_early_crypto_context(QUIC *quic);
quic_err_t quic_setup_crypto_context(QUIC *quic);
quic_err_t quic_setup_handshake_crypto_context(QUIC *quic, const ngtcp2_cid *dcid);
quic_err_t quic_do_handshake_once(QUIC *quic, const uint8_t *data, size_t datalen, ssize_t *nwrite);
quic_err_t quic_do_handshake(QUIC *quic);
size_t quic_read_handshake(QUIC *quic, const u_int8_t **pdest);
void quic_write_handshake(QUIC *quic, const u_int8_t *data, size_t data_len);
quic_err_t quic_remove_tx_stream_data(QUIC *quic, u_int64_t stream_id, u_int64_t offset, size_t data_len);

/* quic_client.c */
quic_err_t quic_client_tls_handshake(QUIC *quic, bool initial);
quic_err_t quic_client_do_connect_handshake(QUIC *quic);
void quic_client_handle_early_data(QUIC *quic);
quic_err_t quic_client_write_0rtt_streams_cb(u_int64_t stream_id, quic_stream_t *stream, void *arg);

/* quic_server.c */
ngtcp2_lib_error quic_server_tls_handshake(QUIC *quic);
quic_err_t quic_server_do_accept_handshake(QUIC *quic);

#endif /* QUIC_CTX_H */