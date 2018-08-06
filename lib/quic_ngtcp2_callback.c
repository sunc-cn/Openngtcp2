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


#include "quic_internal.h"

ssize_t quic_send_client_initial_cb(
    ngtcp2_conn *conn, u_int32_t flags,
    const u_int8_t **pdest, int initial,
    void *user_data) {
    QUIC    *quic;
    size_t  len;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {
        if(quic_client_tls_handshake(quic, initial) != QUIC_ERR_NONE) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }//end if

        quic_client_handle_early_data(quic);

        len = quic_read_handshake(quic, pdest);
        return (ssize_t)len;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {

    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_send_client_initial_cb

ssize_t quic_send_client_handshake_cb(
    ngtcp2_conn *conn, u_int32_t flags,
    const u_int8_t **pdest, void *user_data) {
    QUIC *quic;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {
        return (ssize_t)quic_read_handshake(quic, pdest);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {

    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_send_client_handshake_cb

int quic_recv_client_initial_cb(
    ngtcp2_conn *conn, const ngtcp2_cid *dcid,
    void *user_data) {
    QUIC *quic;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {
        
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        if(quic_setup_handshake_crypto_context(quic, dcid) == QUIC_ERR_NONE) {
            return 0;
        }//end if
    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_recv_client_initial_cb

ssize_t quic_send_server_handshake_cb(
    ngtcp2_conn *conn, uint32_t flags,
    const uint8_t **pdest, int initial,
    void *user_data) {
    QUIC    *quic;
    ssize_t len;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {

    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        len = (ssize_t)quic_read_handshake(quic, pdest);
        if(initial && len == 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }//end if
        return len;
    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_send_server_handshake_cb

int quic_recv_stream0_data_cb(
    ngtcp2_conn *conn, u_int64_t offset, const u_int8_t *data,
    size_t data_len, void *user_data) {
    QUIC                *quic;
    ngtcp2_lib_error    ret;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {
        quic_write_handshake(quic, data, data_len);

        if(!ngtcp2_conn_get_handshake_completed(quic->conn) && quic_client_tls_handshake(quic, false) != QUIC_ERR_NONE) {
            return NGTCP2_ERR_TLS_HANDSHAKE;
        }//end if

        return (int)quic_read_tls(quic, &(quic->chandshake_idx));
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        quic_write_handshake(quic, data, data_len);

        if(!ngtcp2_conn_get_handshake_completed(quic->conn)) {
            ret = quic_server_tls_handshake(quic);
            if(ret != 0) {
                return ret;
            }//end if

            return (int)quic_read_tls(quic, &(quic->shandshake_idx));
        }//end if
    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_recv_stream0_data_cb

int quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data) {
    QUIC *quic;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {
        if(quic_setup_crypto_context((QUIC *)user_data) == QUIC_ERR_NONE) {
            return 0;
        }//end if
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        return 0;
    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_handshake_completed_cb

ssize_t quic_do_hs_encrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data) {
    QUIC    *quic;
    ssize_t nwrite;

    quic = (QUIC *)user_data;
    nwrite = quic_crypto_encrypt(
        dest, destlen,
        plaintext, plaintextlen,
        &(quic->hs_crypto_ctx),
        key, keylen,
        nonce, noncelen,
        ad, adlen,
        quic->errbuf);
    if(nwrite < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }//end if

    return nwrite;
}//end quic_do_hs_encrypt_cb

ssize_t quic_do_hs_decrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *ciphertext, size_t ciphertextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data) {
    QUIC    *quic;
    ssize_t nwrite;

    quic = (QUIC *)user_data;
    nwrite = quic_crypto_decrypt(
        dest, destlen,
        ciphertext, ciphertextlen,
        &(quic->hs_crypto_ctx),
        key, keylen,
        nonce, noncelen,
        ad, adlen,
        quic->errbuf);
    if(nwrite < 0) {
        return NGTCP2_ERR_TLS_DECRYPT;
    }//end if

    return nwrite;
}//end quic_do_hs_decrypt_cb

ssize_t quic_do_encrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data) {
    QUIC    *quic;
    ssize_t nwrite;

    quic = (QUIC *)user_data;
    nwrite = quic_crypto_encrypt(
        dest, destlen,
        plaintext, plaintextlen,
        &(quic->crypto_ctx),
        key, keylen,
        nonce, noncelen,
        ad, adlen,
        quic->errbuf);
    if(nwrite < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }//end if

    return nwrite;
}//end quic_do_encrypt_cb

ssize_t quic_do_decrypt_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *ciphertext, size_t ciphertextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    void *user_data) {
    QUIC    *quic;
    ssize_t nwrite;

    quic = (QUIC *)user_data;
    nwrite = quic_crypto_decrypt(
        dest, destlen,
        ciphertext, ciphertextlen,
        &(quic->crypto_ctx),
        key, keylen,
        nonce, noncelen,
        ad, adlen,
        quic->errbuf);
    if(nwrite < 0) {
        return NGTCP2_ERR_TLS_DECRYPT;
    }//end if

    return nwrite;
}//end quic_do_decrypt_cb

ssize_t quic_do_hs_encrypt_pn_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    void *user_data) {
    QUIC    *quic;
    ssize_t nwrite;

    quic = (QUIC *)user_data;
    nwrite = quic_crypto_encrypt_pn(
        dest, destlen,
        plaintext, plaintextlen,
        &(quic->hs_crypto_ctx),
        key, keylen,
        nonce, noncelen,
        quic->errbuf);
    if(nwrite < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }//end if

    return nwrite;
}//end quic_do_hs_encrypt_pn_cb

ssize_t quic_do_encrypt_pn_cb(
    ngtcp2_conn *conn,
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    void *user_data) {
    QUIC    *quic;
    ssize_t nwrite;

    quic = (QUIC *)user_data;
    nwrite = quic_crypto_encrypt_pn(
        dest, destlen,
        plaintext, plaintextlen,
        &(quic->crypto_ctx),
        key, keylen,
        nonce, noncelen,
        quic->errbuf);
    if(nwrite < 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }//end if

    return nwrite;
}//end quic_do_encrypt_pn_cb

int quic_recv_stream_data_cb(
    ngtcp2_conn *conn,
    u_int64_t stream_id, u_int8_t fin,
    u_int64_t offset,
    const u_int8_t *data, size_t data_len,
    void *user_data, void *stream_user_data) {
    int     ret;
    QUIC    *quic;

    quic = (QUIC *)user_data;
    quic->recv_temp = quic_init_stream_with_data(stream_id, data, data_len);
    if(!quic->recv_temp) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }//end if

    ret = ngtcp2_conn_extend_max_stream_offset(quic->conn, stream_id, data_len);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_extend_max_stream_offset", ret);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }//end if

    ngtcp2_conn_extend_max_offset(quic->conn, data_len);
    return 0;

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_recv_stream_data_cb

int quic_acked_stream_data_offset_cb(
    ngtcp2_conn *conn,
    u_int64_t stream_id, u_int64_t offset,
    size_t data_len,
    void *user_data, void *stream_user_data) {
    QUIC *quic;

    quic = (QUIC *)user_data;
    if(quic_remove_tx_stream_data(quic, stream_id, offset, data_len) == QUIC_ERR_NONE) {
        return 0;
    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_acked_stream_data_offset_cb

int quic_stream_close_cb(
    ngtcp2_conn *conn,
    u_int64_t stream_id, u_int16_t app_error_code,
    void *user_data, void *stream_user_data) {
    QUIC            *quic;
    quic_stream_t   *st;

    quic = (QUIC *)user_data;
    st = quic_stream_map_get(quic->streams, stream_id);
    if(st) {
        quic_stream_map_remove(quic->streams, stream_id);
    }//end if

    return 0;
}//end quic_stream_close_cb

int quic_recv_server_stateless_retry_cb(ngtcp2_conn *conn, void *user_data) {
    QUIC *quic;

    quic = (QUIC *)user_data;
    if(quic->type == QUIC_TYPE_CONNECT) {
        if(quic_setup_handshake_crypto_context(quic, &(quic->dcid)) == QUIC_ERR_NONE) {
            return 0;
        }//end if
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {

    }//end if

    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_recv_server_stateless_retry_cb

int quic_extend_max_stream_id_cb(
    ngtcp2_conn *conn, u_int64_t max_stream_id,
    void *user_data) {
    return 0;
}//end quic_extend_max_stream_id_cb

int quic_rand_cb(
    ngtcp2_conn *conn,
    uint8_t *dest, size_t destlen,
    ngtcp2_rand_ctx ctx,
    void *user_data) {
    if(quic_rand(dest, destlen) == QUIC_ERR_NONE) {
        return 0;
    }//end if
    return NGTCP2_ERR_CALLBACK_FAILURE;
}//end quic_rand_cb