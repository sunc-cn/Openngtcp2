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


#ifndef QUIC_NGTCP2_CALLBACK_H
#define QUIC_NGTCP2_CALLBACK_H

ssize_t quic_send_client_initial_cb(
    ngtcp2_conn *conn, u_int32_t flags,
    const u_int8_t **pdest, int initial,
    void *user_data);
ssize_t quic_send_client_handshake_cb(
    ngtcp2_conn *conn, u_int32_t flags,
    const u_int8_t **pdest, void *user_data);
int quic_recv_client_initial_cb(
    ngtcp2_conn *conn, const ngtcp2_cid *dcid,
    void *user_data);
ssize_t quic_send_server_handshake_cb(
    ngtcp2_conn *conn, uint32_t flags,
    const uint8_t **pdest, int initial,
    void *user_data);
int quic_recv_stream0_data_cb(
    ngtcp2_conn *conn, u_int64_t offset, const u_int8_t *data,
    size_t data_len, void *user_data);
int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data);
ssize_t quic_do_hs_encrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data);
ssize_t quic_do_hs_decrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *ciphertext, size_t ciphertextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data);
ssize_t quic_do_encrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data);
ssize_t quic_do_decrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *ciphertext, size_t ciphertextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data);
ssize_t quic_do_hs_encrypt_pn_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    void *user_data);
ssize_t quic_do_encrypt_pn_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    void *user_data);
int quic_recv_stream_data_cb(
    ngtcp2_conn *conn,
    u_int64_t stream_id, u_int8_t fin,
    u_int64_t offset,
    const u_int8_t *data, size_t data_len,
    void *user_data, void *stream_user_data);
int quic_acked_stream_data_offset_cb(
    ngtcp2_conn *conn,
    u_int64_t stream_id, u_int64_t offset,
    size_t data_len,
    void *user_data, void *stream_user_data);
int quic_stream_close_cb(
    ngtcp2_conn *conn,
    u_int64_t stream_id, u_int16_t app_error_code,
    void *user_data, void *stream_user_data);
int quic_recv_server_stateless_retry_cb(ngtcp2_conn *conn, void *user_data);
int quic_extend_max_stream_id_cb(
    ngtcp2_conn *conn, u_int64_t max_stream_id,
    void *user_data);
int quic_rand_cb(
    ngtcp2_conn *conn,
    uint8_t *dest, size_t destlen,
    ngtcp2_rand_ctx ctx,
    void *user_data);

#endif /* QUIC_NGTCP2_CALLBACK_H */