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

static void quic_free_deque_cb(void *data);
static size_t quic_remove_tx_stream_data_internal(QUIC *quic, quic_deque_t *d, size_t *idx, u_int64_t *tx_offset, u_int64_t offset);

quic_err_t quic_set_fd(QUIC *quic, int fd) {
    int ret;

    if(QUIC_is_init_finished(quic)) {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC connection is established");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    quic->fd = fd;
    quic->addr.len = sizeof(quic->addr.ss);
    ret = getpeername(fd, &(quic->addr.sa), &(quic->addr.len));
    if(ret != 0) {
        quic_set_sys_err(quic->errbuf, "getpeername", errno);
        return QUIC_ERR_SYSTEM;
    }//end if

    switch(quic->addr.ss.ss_family) {
        case PF_INET:
            quic->max_pktlen = NGTCP2_MAX_PKTLEN_IPV4;
            break;
        case PF_INET6:
            quic->max_pktlen = NGTCP2_MAX_PKTLEN_IPV6;
            break;
        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown socket family: %d", quic->addr.ss.ss_family);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch

    BIO_set_fd(quic->rbio, fd, BIO_NOCLOSE);
    BIO_set_fd(quic->wbio, fd, BIO_NOCLOSE);
    return QUIC_ERR_NONE;
}//end quic_set_fd

void QUIC_free(QUIC *quic) {
    if(quic) {
        if(quic->rbio) {
            BIO_free_all(quic->rbio);
        }//end if
        if(quic->wbio) {
            BIO_free_all(quic->wbio);
        }//end if
        if(quic->ssl) {
            SSL_free(quic->ssl);
        }//end if
        if(quic->conn) {
            ngtcp2_conn_del(quic->conn);
        }//end if
        if(quic->type == QUIC_TYPE_CONNECT) {
            if(quic->chandshake.c) {
                quic_free_deque_deep(quic->chandshake.c, quic_free_deque_cb);
            }//end if
            if(quic->shandshake.c) {
                quic_free_byte_array(quic->shandshake.c);
            }//end if
        }//end if
        else if(quic->type == QUIC_TYPE_ACCEPT) {
            if(quic->chandshake.s) {
                quic_free_byte_array(quic->chandshake.s);
            }//end if
            if(quic->shandshake.s) {
                quic_free_deque_deep(quic->shandshake.s, quic_free_deque_cb);
            }//end if
        }//end if
        else {
            //hmm...
        }//end else
        if(quic->pre_streams) {
            quic_free_deque_deep(quic->pre_streams, quic_free_deque_cb);
        }//end if
        if(quic->sendbuf) {
            quic_free_buf(quic->sendbuf);
        }//end if
        if(quic->recvbuf) {
            quic_free_buf(quic->recvbuf);
        }//end if
        if(quic->closebuf) {
            quic_free_buf(quic->closebuf);
        }//end if
        if(quic->streams) {
            quic_free_stream_map(quic->streams);
        }//end if
        if(quic->ssl_ciphers) {
            free(quic->ssl_ciphers);
        }//end if
        if(quic->ssl_groups) {
            free(quic->ssl_groups);
        }//end if
        if(quic->ssl_sni) {
            free(quic->ssl_sni);
        }//end if
        if(quic->quic_ctx) {
            QUIC_CTX_free(quic->quic_ctx);
        }//end if
        free(quic);
    }//end if
}//end QUIC_free

quic_err_t QUIC_reinit_ngtcp2(QUIC *quic) {
    int         i, ret;
    quic_err_t  err;
    ngtcp2_cid  scid_temp, dcid_temp;
    ngtcp2_conn *conn_temp = NULL;

    if(QUIC_is_init_finished(quic)) {
        quic_set_openngtcp2_err(quic->errbuf, "connection is established");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    if(quic->conn) {
        conn_temp = quic->conn;
        memcpy(&scid_temp, &(quic->scid), sizeof(scid_temp));
        memcpy(&dcid_temp, &(quic->dcid), sizeof(dcid_temp));
    }//end if

    if(quic->type == QUIC_TYPE_CONNECT) {
        quic->scid.datalen = 17;
        quic->dcid.datalen = 18;

        for(i = 0 ; i < quic->scid.datalen ; i++) {
            quic->scid.data[i] = random();
        }//end for
        for(i = 0 ; i < quic->dcid.datalen ; i++) {
            quic->dcid.data[i] = random();
        }//end for

        ret = ngtcp2_conn_client_new(&(quic->conn), &(quic->dcid), &(quic->scid), QUIC_PROTO_VER_MAX, &(quic->callbacks), &(quic->settings), quic);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_client_new", ret);
            quic->conn = conn_temp;
            memcpy(&(quic->scid), &scid_temp, sizeof(quic->scid));
            memcpy(&(quic->dcid), &dcid_temp, sizeof(quic->dcid));
            return QUIC_ERR_OPENNGTCP2;
        }//end if

        err = quic_setup_handshake_crypto_context(quic, &(quic->dcid));
        if(err != QUIC_ERR_NONE) {
            snprintf(quic->errbuf, QUIC_ERRBUF_SIZE, "%s", quic->errbuf);
            ngtcp2_conn_del(quic->conn);
            quic->conn = conn_temp;
            memcpy(&(quic->scid), &scid_temp, sizeof(quic->scid));
            memcpy(&(quic->dcid), &dcid_temp, sizeof(quic->dcid));
            return QUIC_ERR_OPENNGTCP2;
        }//end if

        quic->prev_state = QUIC_STATE_NONE;
        quic->state = QUIC_STATE_WRITE_RTT0;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        quic->scid.datalen = 18;

        for(i = 0 ; i < quic->scid.datalen ; i++) {
            quic->scid.data[i] = random();
        }//end for

        ret = ngtcp2_conn_server_new(&(quic->conn), &(quic->dcid), &(quic->scid), quic->version, &(quic->callbacks), &(quic->settings), quic);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_server_new", ret);
            quic->conn = conn_temp;
            memcpy(&(quic->scid), &scid_temp, sizeof(quic->scid));
            memcpy(&(quic->dcid), &dcid_temp, sizeof(quic->dcid));
            return QUIC_ERR_OPENNGTCP2;
        }//end if

        quic->prev_state = QUIC_STATE_NONE;
        quic->state = QUIC_STATE_DO_HANDSHAKE;
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else

    if(conn_temp) {
        ngtcp2_conn_del(conn_temp);
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_reinit_ngtcp2

quic_err_t QUIC_set_data_to_stream(QUIC *quic, const u_int8_t *data, size_t data_len, u_int64_t *stream_id) {
    int         ret;
    u_int64_t   s_id = -1;
    quic_err_t  err;
    quic_buf_t  *buf;

    if(QUIC_is_init_finished(quic) || quic->set_transport_params) {
        if(quic->type == QUIC_TYPE_CONNECT) {
            ret = ngtcp2_conn_open_bidi_stream(quic->conn, &s_id, NULL);
            if(ret != 0) {
                quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_open_bidi_stream", ret);
                return QUIC_ERR_NGTCP2;
            }//end if
        }//end if
        else if(quic->type == QUIC_TYPE_ACCEPT) {
            if(stream_id == NULL) {
                quic_set_openngtcp2_err(quic->errbuf, "Stream ID in ACCEPT type could not be NULL");
                return QUIC_ERR_OPENNGTCP2;
            }//end if
            s_id = *stream_id;
        }//end if
        else {
            quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
            return QUIC_ERR_OPENNGTCP2;
        }//end else

        err = quic_stream_map_insert_data(quic->streams, s_id, data, data_len);
        if(err != QUIC_ERR_NONE) {
            quic_set_openngtcp2_err(quic->errbuf, "Fail to insert new stream data at stream id: %llu", s_id);
            return QUIC_ERR_OPENNGTCP2;
        }//end if
    }//end if
    else {
        buf = quic_init_buf(data, data_len);
        if(!buf) {
            quic_set_openngtcp2_err(quic->errbuf, "Fail to allocate buffer");
            return QUIC_ERR_OPENNGTCP2;
        }//end if

        err = quic_deque_push_tail(quic->pre_streams, buf);
        if(err != QUIC_ERR_NONE) {
            quic_set_openngtcp2_err(quic->errbuf, "Fail to append data");
            quic_free_buf(buf);
            return QUIC_ERR_OPENNGTCP2;
        }//end if
    }//end else

    if(stream_id) {
        *stream_id = s_id;
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_set_data_to_stream

quic_err_t QUIC_update_data_to_stream(QUIC *quic, u_int64_t stream_id, const u_int8_t *data, size_t data_len) {
    quic_err_t err;

    err = quic_stream_map_replace_data(quic->streams, stream_id, data, data_len);
    if(err != QUIC_ERR_NONE) {
        if(err == QUIC_ERR_NOT_FOUND) {
            quic_set_openngtcp2_err(quic->errbuf, "Stream id: %llu is not found", stream_id);
        }//end if
        else {
            quic_set_openngtcp2_err(quic->errbuf, "Fail to update stream data at stream id: %llu", stream_id);
        }//end else
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_update_data_to_stream

quic_err_t QUIC_remove_data_to_stream(QUIC *quic, u_int64_t stream_id) {
    quic_err_t err;

    err = quic_stream_map_remove(quic->streams, stream_id);
    if(err != QUIC_ERR_NONE) {
        if(err == QUIC_ERR_NOT_FOUND) {
            quic_set_openngtcp2_err(quic->errbuf, "Stream id: %llu is not found", stream_id);
        }//end if
        else {
            quic_set_openngtcp2_err(quic->errbuf, "Fail to remove stream data at stream id: %llu", stream_id);
        }//end else
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_remove_data_to_stream

quic_err_t QUIC_get_data_to_stream(QUIC *quic, u_int64_t stream_id, const u_int8_t **data, size_t *data_len) {
    quic_buf_t      *buf;
    quic_stream_t   *st;

    st = quic_stream_map_get(quic->streams, stream_id);
    if(!st) {
        quic_set_openngtcp2_err(quic->errbuf, "Stream id: %llu is not found", stream_id);
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    buf = quic_deque_peak_head(st->streambuf);
    if(!buf) {
        quic_set_openngtcp2_err(quic->errbuf, "Stream id: %llu is no data", stream_id);
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    *data = quic_buf_rpos(buf);
    *data_len = quic_buf_size(buf);
    return QUIC_ERR_NONE;
}//end QUIC_get_data_to_stream

quic_err_t QUIC_read_session_from_file(QUIC *quic, const char *fname) {
    BIO         *bp;
    SSL_SESSION *sess;

    bp = BIO_new_file(fname, "r");
    if(!bp) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not open TLS session file");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    sess = PEM_read_bio_SSL_SESSION(bp, NULL, 0, NULL);
    BIO_free(bp);
    if(!sess) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not read TLS session file");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    if(SSL_set_session(quic->ssl, sess) != 1) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not read TLS session file");
        SSL_SESSION_free(sess);
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    SSL_SESSION_free(sess);
    quic->resumption = true;
    return QUIC_ERR_NONE;
}//end QUIC_read_session_from_file

quic_err_t QUIC_write_session_to_file(QUIC *quic, const char *fname) {
    BIO         *bp;
    SSL_SESSION *sess;

    bp = BIO_new_file(fname, "w");
    if(!bp) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not open TLS session file");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    sess = SSL_get_session(quic->ssl);
    if(!sess) {
        quic_set_openngtcp2_err(quic->errbuf, "Could get TLS session");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    PEM_write_bio_SSL_SESSION(bp, sess);
    BIO_free(bp);
    return QUIC_ERR_NONE;
}//end QUIC_write_session_to_file

quic_err_t QUIC_read_transport_params_from_file(QUIC *quic, const char *fname) {
    int                     ret;
    FILE                    *fp;
    char                    tmp[QUIC_BUF_SIZE];
    size_t                  len;
    ngtcp2_transport_params params;

    memset(&params, 0, sizeof(params));

    fp = fopen(fname, "r");
    if(!fp) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not read transport params file");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    while(true) {
        fgets(tmp, sizeof(tmp), fp);
        if(feof(fp)) {
            break;
        }//end if

#define GET_AND_SET(key, value) \
    do { \
        len = strlen(key); \
        if(!strncmp(tmp, key, len)) { \
            value = strtoul(tmp + len, NULL, 10); \
        } \
    } \
    while(0)
        GET_AND_SET("initial_max_bidi_streams=", params.initial_max_bidi_streams);
        GET_AND_SET("initial_max_uni_streams=", params.initial_max_uni_streams);
        GET_AND_SET("initial_max_stream_data=", params.initial_max_stream_data);
        GET_AND_SET("initial_max_data=", params.initial_max_data);
#undef GET_AND_SET
    }//end while
    fclose(fp);
    ret = ngtcp2_conn_set_early_remote_transport_params(quic->conn, &params);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_set_early_remote_transport_params", ret);
        return QUIC_ERR_NGTCP2;
    }//end if

    quic->set_transport_params = true;
    memcpy(&(quic->params), &params, sizeof(quic->params));
    return QUIC_ERR_NONE;
}//end QUIC_read_transport_params_from_file

quic_err_t QUIC_write_transport_params_to_file(QUIC *quic, const char *fname) {
    FILE *fp;
    ngtcp2_transport_params *params;

    fp = fopen(fname, "w");
    if(!fp) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not write transport params file");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    params = &(quic->params);
    fprintf(fp,
        "initial_max_bidi_streams=%d\n"
        "initial_max_uni_streams=%d\n"
        "initial_max_stream_data=%d\n"
        "initial_max_data=%d\n",
        params->initial_max_bidi_streams, params->initial_max_uni_streams,
        params->initial_max_stream_data, params->initial_max_data);
    fclose(fp);

    return QUIC_ERR_NONE;
}//end QUIC_write_transport_params_to_file

quic_err_t QUIC_do_handshake(QUIC *quic) {
    if(QUIC_is_init_finished(quic)) {
        return QUIC_ERR_NONE;
    }//end if

    if(quic->type == QUIC_TYPE_CONNECT) {
        return quic_client_do_connect_handshake(quic);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        return quic_server_do_accept_handshake(quic);
    }//end if

    quic_set_openngtcp2_err(quic->errbuf, "\"connect\" or \"accept\" state is not setted");
    return QUIC_ERR_OPENNGTCP2;
}//end QUIC_do_handshake

quic_err_t QUIC_do_retransmit(QUIC *quic) {
    quic_err_t      err;
    ngtcp2_tstamp   now;
    quic_err_t (*cb)(QUIC *, bool);

    if(quic->type == QUIC_TYPE_CONNECT) {
        cb = quic_client_write_streams;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        cb = quic_server_write_streams;
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else

    now = quic_timestamp();
    if(ngtcp2_conn_loss_detection_expiry(quic->conn) <= now) {
        err = cb(quic, true);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
    }//end if

    if(ngtcp2_conn_ack_delay_expiry(quic->conn) <= now) {
        err = cb(quic, false);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
    }//end if

    return QUIC_ERR_QUIC_WANT_READ;
}//end QUIC_do_retransmit

quic_err_t QUIC_shutdown(QUIC *quic) {
    ssize_t n;

    if(QUIC_is_in_closing(quic)) {
        quic_buf_reset(quic->sendbuf);
        memcpy(quic_buf_wpos(quic->sendbuf), quic_buf_rpos(quic->closebuf), quic_buf_size(quic->closebuf));
        quic_buf_push(quic->sendbuf, quic_buf_size(quic->closebuf));
        return quic_flush_sendbuf(quic);
    }//end if

    if(quic->shutdown_code == NGTCP2_ERR_RECV_VERSION_NEGOTIATION) {
        return QUIC_ERR_NONE;
    }//end if

    quic_buf_reset(quic->closebuf);
    n = ngtcp2_conn_write_connection_close(
        quic->conn, quic_buf_wpos(quic->closebuf), quic->max_pktlen,
        ngtcp2_err_infer_quic_transport_error_code(quic->shutdown_code),
        quic_timestamp());
    if(n < 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_write_connection_close", n);
        return QUIC_ERR_NGTCP2;
    }//end if
    quic_buf_push(quic->closebuf, n);

    quic_buf_reset(quic->sendbuf);
    memcpy(quic_buf_wpos(quic->sendbuf), quic_buf_rpos(quic->closebuf), quic_buf_size(quic->closebuf));
    quic_buf_push(quic->sendbuf, quic_buf_size(quic->closebuf));
    return quic_flush_sendbuf(quic);
}//end QUIC_shutdown

bool QUIC_is_in_closing(QUIC *quic) {
    return (quic->conn && ngtcp2_conn_in_closing_period(quic->conn)) ? true : false;
}//end QUIC_is_in_closing

bool QUIC_is_in_init(QUIC *quic) {
    return quic->in_init;
}//end QUIC_is_in_init

bool QUIC_is_init_finished(QUIC *quic) {
    return (quic->conn && ngtcp2_conn_get_handshake_completed(quic->conn)) ? true : false;
}//end QUIC_is_init_finished

struct timespec QUIC_get_retransmit_timestamp(QUIC *quic) {
    ngtcp2_tstamp   expiry, now, t, t1, t2;
    struct timespec ts;

    t1 = ngtcp2_conn_loss_detection_expiry(quic->conn);
    t2 = ngtcp2_conn_ack_delay_expiry(quic->conn);
    expiry = t1 < t2 ? t1 : t2;
    now = quic_timestamp();
    t = expiry < now ? 1 : (expiry - now);

    ts.tv_sec = t / 1000000000;
    ts.tv_nsec = t % 1000000000;
    return ts;
}//end QUIC_get_retransmit_timestamp

quic_err_t QUIC_use_PrivateKey_file(QUIC *quic, const char *file) {
    if(SSL_use_PrivateKey_file(quic->ssl, file, SSL_FILETYPE_PEM) != 1) {
        quic_set_ssl_err(quic->errbuf, "SSL_use_PrivateKey_file");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_use_PrivateKey_file

quic_err_t QUIC_use_certificate_chain_file(QUIC *quic, const char *file) {
    if(SSL_use_certificate_chain_file(quic->ssl, file) != 1) {
        quic_set_ssl_err(quic->errbuf, "SSL_use_certificate_chain_file");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_use_certificate_chain_file

quic_err_t QUIC_use_certificate_file(QUIC *quic, const char *file) {
    if(SSL_use_certificate_file(quic->ssl, file, SSL_FILETYPE_PEM) != 1) {
        quic_set_ssl_err(quic->errbuf, "SSL_use_certificate_file");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_use_certificate_file

ngtcp2_lib_error quic_read_tls(QUIC *quic, size_t *idx) {
    int         ret, err;
    size_t      nread, outidx;
    u_int8_t    buf[4096];

    ERR_clear_error();

    for(;;) {
        outidx = *idx;
        ret = SSL_read_ex(quic->ssl, buf, sizeof(buf), &nread);
        if(ret == 1) {
            //printf("Read %zu bytes from TLS stream 0\n", nread);
            continue;
        }//end if

        err = SSL_get_error(quic->ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
            case SSL_ERROR_ZERO_RETURN:
                quic_set_ssl_err(quic->errbuf, "SSL_read_ex");
                if(*idx == outidx) {
                    return NGTCP2_ERR_TLS_FATAL_ALERT_RECEIVED;
                }//end if
                return NGTCP2_ERR_TLS_FATAL_ALERT_GENERATED;
            default:
                quic_set_openngtcp2_err(quic->errbuf, "TLS read error: %d", err);
                return NGTCP2_ERR_CALLBACK_FAILURE;
        }//end switch
    }//end for
}//end quic_read_tls

quic_err_t quic_setup_early_crypto_context(QUIC *quic) {
    int         ret;
    ssize_t     keylen, ivlen, pnlen;
    u_int8_t    key[64], iv[64], pn[64], *secret;
    quic_err_t  err;

    if(quic->type == QUIC_TYPE_CONNECT) {
        secret = quic->crypto_ctx.tx_secret;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        secret = quic->crypto_ctx.rx_secret;
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else

    err = quic_crypto_negotiated_prf(quic->ssl, &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_negotiated_aead(quic->ssl, &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    quic->crypto_ctx.secretlen = EVP_MD_size(quic->crypto_ctx.prf);

    err = quic_crypto_export_early_secret(secret, quic->crypto_ctx.secretlen, quic->ssl, quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_packet_protection_key_iv_pn(
        key, sizeof(key), &keylen,
        iv, sizeof(iv), &ivlen,
        pn, sizeof(pn), &pnlen,
        secret, quic->crypto_ctx.secretlen,
        &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    ret = ngtcp2_conn_update_early_keys(quic->conn, key, keylen, iv, ivlen, pn, pnlen);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_update_early_keys", ret);
        return QUIC_ERR_NGTCP2;
    }//end if

    ngtcp2_conn_set_aead_overhead(quic->conn, quic_crypto_aead_max_overhead(&(quic->crypto_ctx)));
    return QUIC_ERR_NONE;
}//end quic_setup_early_crypto_context

quic_err_t quic_setup_crypto_context(QUIC *quic) {
    int         ret;
    uint8_t     key[64], iv[64], pn[64];
    ssize_t     keylen, ivlen, pnlen;
    quic_err_t  err;

    err = quic_crypto_negotiated_prf(quic->ssl, &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_negotiated_aead(quic->ssl, &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    quic->crypto_ctx.secretlen = EVP_MD_size(quic->crypto_ctx.prf);

    if(quic->type == QUIC_TYPE_CONNECT) {
        err = quic_crypto_export_client_secret(
            quic->crypto_ctx.tx_secret,
            quic->crypto_ctx.secretlen,
            quic->ssl, quic->errbuf);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        err = quic_crypto_export_server_secret(
            quic->crypto_ctx.tx_secret,
            quic->crypto_ctx.secretlen,
            quic->ssl, quic->errbuf);
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_packet_protection_key_iv_pn(
        key, sizeof(key), &keylen,
        iv, sizeof(iv), &ivlen,
        pn, sizeof(pn), &pnlen,
        quic->crypto_ctx.tx_secret, quic->crypto_ctx.secretlen,
        &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    ret = ngtcp2_conn_update_tx_keys(quic->conn, key, keylen, iv, ivlen, pn, pnlen);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_update_tx_keys", ret);
        return QUIC_ERR_NGTCP2;
    }//end if

    if(quic->type == QUIC_TYPE_CONNECT) {
        err = quic_crypto_export_server_secret(
            quic->crypto_ctx.rx_secret, quic->crypto_ctx.secretlen,
            quic->ssl, quic->errbuf);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        err = quic_crypto_export_client_secret(
            quic->crypto_ctx.rx_secret, quic->crypto_ctx.secretlen,
            quic->ssl, quic->errbuf);
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_packet_protection_key_iv_pn(
        key, sizeof(key), &keylen,
        iv, sizeof(iv), &ivlen,
        pn, sizeof(pn), &pnlen,
        quic->crypto_ctx.rx_secret, quic->crypto_ctx.secretlen,
        &(quic->crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    ret = ngtcp2_conn_update_rx_keys(quic->conn, key, keylen, iv, ivlen, pn, pnlen);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_update_rx_keys", ret);
        return QUIC_ERR_NGTCP2;
    }//end if

    ngtcp2_conn_set_aead_overhead(quic->conn, quic_crypto_aead_max_overhead(&(quic->crypto_ctx)));
    return QUIC_ERR_NONE;
}//end quic_setup_crypto_context

quic_err_t quic_setup_handshake_crypto_context(QUIC *quic, const ngtcp2_cid *dcid) {
    int         ret;
    ssize_t     keylen, ivlen, pnlen;
    u_int8_t    handshake_secret[32], secret[32], key[16], iv[16], pn[16];
    quic_err_t  err;

    err = quic_crypto_derive_handshake_secret(
        handshake_secret, sizeof(handshake_secret),
        dcid,
        (const uint8_t *)NGTCP2_HANDSHAKE_SALT,
        strlen((const char *)NGTCP2_HANDSHAKE_SALT),
        quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    quic->hs_crypto_ctx.prf = EVP_sha256();
    quic->hs_crypto_ctx.aead = EVP_aes_128_gcm();
    quic->hs_crypto_ctx.pn = EVP_aes_128_ctr();

    if(quic->type == QUIC_TYPE_CONNECT) {
        err = quic_crypto_derive_client_handshake_secret(
            secret, sizeof(secret),
            handshake_secret, sizeof(handshake_secret),
            quic->errbuf);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        err = quic_crypto_derive_server_handshake_secret(
            secret, sizeof(secret),
            handshake_secret, sizeof(handshake_secret),
            quic->errbuf);
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else

    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_packet_protection_key_iv_pn(
        key, sizeof(key), &keylen,
        iv, sizeof(iv), &ivlen,
        pn, sizeof(pn), &pnlen,
        secret, sizeof(secret),
        &(quic->hs_crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    ret = ngtcp2_conn_set_handshake_tx_keys(quic->conn, key, keylen, iv, ivlen, pn, pnlen);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_set_handshake_tx_keys", ret);
        return QUIC_ERR_NGTCP2;
    }//end if

    if(quic->type == QUIC_TYPE_CONNECT) {
        err = quic_crypto_derive_server_handshake_secret(
            secret, sizeof(secret),
            handshake_secret, sizeof(handshake_secret),
            quic->errbuf);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        err = quic_crypto_derive_client_handshake_secret(
            secret, sizeof(secret),
            handshake_secret, sizeof(handshake_secret),
            quic->errbuf);
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else

    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_packet_protection_key_iv_pn(
        key, sizeof(key), &keylen,
        iv, sizeof(iv), &ivlen,
        pn, sizeof(pn), &pnlen,
        secret, sizeof(secret),
        &(quic->hs_crypto_ctx), quic->errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    ret = ngtcp2_conn_set_handshake_rx_keys(quic->conn, key, keylen, iv, ivlen, pn, pnlen);
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_set_handshake_rx_keys", ret);
        return QUIC_ERR_NGTCP2;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_setup_handshake_crypto_context

quic_err_t quic_do_handshake_once(QUIC *quic, const uint8_t *data, size_t datalen, ssize_t *nwrite) {
    quic_err_t err;

    *nwrite = ngtcp2_conn_handshake(
        quic->conn, quic_buf_wpos(quic->sendbuf), quic->max_pktlen,
        data, datalen,
        quic_timestamp());
    if(*nwrite < 0) {
        switch(*nwrite) {
            case NGTCP2_ERR_TLS_DECRYPT:
                quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_handshake", *nwrite);
                return QUIC_ERR_RETURN_ZERO;
            case NGTCP2_ERR_NOBUF:
                quic_set_openngtcp2_err(quic->errbuf, "Send buffer is too small");
                return QUIC_ERR_RETURN_ZERO;
        }//end switch
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_handshake", *nwrite);
        quic->shutdown_code = *nwrite;
        return QUIC_ERR_NGTCP2;
    }//end if

    if(*nwrite == 0) {
        quic_set_openngtcp2_err(quic->errbuf, "ngtcp2_conn_handshake() return zero length");
        return QUIC_ERR_NONE;
    }//end if

    quic_buf_push(quic->sendbuf, *nwrite);
    err = quic_flush_sendbuf(quic);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_do_handshake_once

size_t quic_read_handshake(QUIC *quic, const u_int8_t **pdest) {
    quic_buf_t      *buf;
    quic_deque_t    *d;

    if(quic->type == QUIC_TYPE_CONNECT) {
        d = quic->chandshake.c;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        d = quic->shandshake.s;
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return 0;
    }//end else

    if(quic->chandshake_idx >= quic_deque_get_length(d)) {
        return 0;
    }//end if

    buf = quic_deque_peek_nth(d, quic->chandshake_idx++);
    if(!buf) {
        return 0;
    }//end if
    *pdest = quic_buf_rpos(buf);
    return quic_buf_size(buf);
}//end quic_read_handshake

void quic_write_handshake(QUIC *quic, const u_int8_t *data, size_t data_len) {
    quic_byte_array_t *b;

    if(quic->type == QUIC_TYPE_CONNECT) {
        b = quic->shandshake.c;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        b = quic->chandshake.s;
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return;
    }//end else

    quic_byte_array_append(b, data, data_len);
}//end quic_write_handshake

quic_err_t quic_do_handshake(QUIC *quic) {
    ssize_t     nwrite;
    quic_err_t  err;

    err = quic_do_handshake_once(quic, quic_buf_rpos(quic->recvbuf), quic_buf_size(quic->recvbuf), &nwrite);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if
    else if(nwrite == 0) {
        return QUIC_ERR_RETURN_ZERO;
    }//end if

    if(quic->type == QUIC_TYPE_CONNECT) {
        err = quic_stream_map_foreach(quic->streams, quic_client_write_0rtt_streams_cb, quic);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
    }//end if

    for(;;) {
        err = quic_do_handshake_once(quic, NULL, 0, &nwrite);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
        else if(nwrite == 0) {
            return QUIC_ERR_RETURN_ZERO;
        }//end if
    }//end for
}//end quic_do_handshake

quic_err_t quic_remove_tx_stream_data(QUIC *quic, u_int64_t stream_id, u_int64_t offset, size_t data_len) {
    quic_stream_t *st;

    if(stream_id == 0) {
        if(quic->type == QUIC_TYPE_CONNECT) {
            quic_remove_tx_stream_data_internal(
                quic,
                quic->chandshake.c, &(quic->chandshake_idx), &(quic->tx_stream0_offset),
                offset + data_len);
        }//end if
        else if(quic->type == QUIC_TYPE_ACCEPT) {
            quic_remove_tx_stream_data_internal(
                quic,
                quic->shandshake.s, &(quic->shandshake_idx), &(quic->tx_stream0_offset),
                offset + data_len);
        }//end if
        else {
            quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
            return QUIC_ERR_OPENNGTCP2;
        }//end else
        return QUIC_ERR_NONE;
    }//end if remove stream id 0

    st = quic_stream_map_get(quic->streams, stream_id);
    if(!st) {
        quic_set_openngtcp2_err(quic->errbuf, "Stream id %llu is not found", stream_id);
        return QUIC_ERR_NONE; //ignore error
    }//end if

    quic_remove_tx_stream_data_internal(
        quic,
        quic_stream_get_streambuf(st), quic_stream_get_streambuf_idx(st), quic_stream_get_tx_stream_offset(st),
        offset + data_len);
    return QUIC_ERR_NONE;
}//end quic_remove_tx_stream_data


/* ===== private function ===== */
static void quic_free_deque_cb(void *data) {
    quic_buf_t *buf;

    if(data) {
        buf = (quic_buf_t *)data;
        quic_free_buf(buf);
    }//end if
}//end quic_free_deque_cb

static size_t quic_remove_tx_stream_data_internal(QUIC *quic, quic_deque_t *d, size_t *idx, u_int64_t *tx_offset, u_int64_t offset) {
    size_t      len = 0;
    quic_buf_t  *buf;

    for(;;) {
        if(quic_deque_is_empty(d)) {
            break;
        }//end if
        buf = quic_deque_peak_head(d);
        if(*tx_offset + quic_buf_size(buf) > offset) {
            break;
        }//end if

        (*idx)--;
        *tx_offset += quic_buf_size(buf);
        len += quic_buf_size(buf);

        buf = quic_deque_pop_head(d);
        quic_free_buf(buf);
    }//end for

    return len;
}//end quic_remove_tx_stream_data_internal