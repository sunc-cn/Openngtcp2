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

static quic_err_t quic_client_on_write_0rtt_stream(QUIC *quic, u_int64_t stream_id, u_int8_t fin, quic_buf_t *buf);

QUIC *QUIC_new_connect(QUIC_CTX *quic_ctx, char *errbuf) {
    BIO  *bio;
    QUIC *quic;

    quic = calloc(1, sizeof(QUIC));
    if(!quic) {
        quic_set_sys_err(errbuf, "calloc", errno);
        return NULL;
    }//end if
    quic->type = QUIC_TYPE_CONNECT;

    quic->ssl = SSL_new(quic_ctx->ssl_ctx);
    if(!quic->ssl) {
        quic_set_ssl_err(errbuf, "SSL_new");
        QUIC_free(quic);
        return NULL;
    }//end if

    quic->quic_ctx = quic_ctx;
    quic_ctx->ref_count++;

    //set ssl
    SSL_set_connect_state(quic->ssl);
    // This makes OpenSSL client not send CCS after an initial
    // ClientHello.
    SSL_clear_options(quic->ssl, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    //copy from QUIC_CTX
    memcpy(&(quic->callbacks), &(quic_ctx->callbacks), sizeof(quic->callbacks));
    quic->ssl_ciphers = strdup(quic_ctx->ssl_ciphers);
    if(!quic->ssl_ciphers) {
        quic_set_sys_err(errbuf, "strdup", errno);
        QUIC_free(quic);
        return NULL;
    }//end if
    quic->ssl_groups = strdup(quic_ctx->ssl_groups);
    if(!quic->ssl_groups) {
        quic_set_sys_err(errbuf, "strdup", errno);
        QUIC_free(quic);
        return NULL;
    }//end if

    //set bio
    bio = BIO_new(quic_create_ssl_bio_method());
    BIO_set_data(bio, quic);
    SSL_set_bio(quic->ssl, bio, bio);
    SSL_set_app_data(quic->ssl, quic);

    bio = BIO_new(BIO_s_socket());
    QUIC_set_bio(quic, bio, bio);

    //init client handshake
    quic->chandshake.c = quic_init_deque();
    if(!quic->chandshake.c) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate deque");
        QUIC_free(quic);
        return NULL;
    }//end if

    //init server handshake
    quic->shandshake.c = quic_init_byte_array();
    if(!quic->shandshake.c) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate byte array");
        QUIC_free(quic);
        return NULL;
    }//end if

    quic->sendbuf = quic_init_buf_sized(NGTCP2_MAX_PKTLEN_IPV4);
    if(!quic->sendbuf) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate send buffer");
        QUIC_free(quic);
        return NULL;
    }//end if

    quic->recvbuf = quic_init_buf_sized(65536);
    if(!quic->recvbuf) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate receive buffer");
        QUIC_free(quic);
        return NULL;
    }//end if

    quic->closebuf = quic_init_buf_sized(NGTCP2_MAX_PKTLEN_IPV4);
    if(!quic->closebuf) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate close send buffer");
        QUIC_free(quic);
        return NULL;
    }//end if

    quic->streams = quic_init_stream_map();
    if(!quic->streams) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate streams");
        QUIC_free(quic);
        return NULL;
    }//end if

    quic->pre_streams = quic_init_deque();
    if(!quic->pre_streams) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate deque");
        QUIC_free(quic);
        return NULL;
    }//end if

    //ngtcp2 setttings
    quic->settings.initial_ts = quic_timestamp();
    QUIC_set_max_pkt_size(quic, NGTCP2_MAX_PKT_SIZE);
    QUIC_set_idle_timeout(quic, QUIC_DEFAULT_IDLE_TIMEOUT);
    QUIC_set_max_stream_data(quic, QUIC_DEFAULT_MAX_STREAM_DATA);
    QUIC_set_max_data(quic, QUIC_DEFAULT_MAX_DATA);
    QUIC_set_ack_delay_exponent(quic, QUIC_DEFAULT_ACK_DELAY_EXPONENT);
    QUIC_set_max_bidi_streams(quic, 1);
    QUIC_set_max_uni_streams(quic, 1);
    QUIC_set_nstreams(quic, 1);

    //other
    quic->fd = -1;

    //init ngtcp2
    if(QUIC_reinit_ngtcp2(quic) != QUIC_ERR_NONE) {
        snprintf(errbuf, QUIC_ERRBUF_SIZE, "%s", quic->errbuf);
        QUIC_free(quic);
        return NULL;
    }//end if
    
    return quic;
}//end QUIC_new_connect

quic_err_t quic_client_tls_handshake(QUIC *quic, bool initial) {
    int     ret, err;
    size_t  nwrite;

    ERR_clear_error();

    /* Note that SSL_SESSION_get_max_early_data() and
     * SSL_get_max_early_data() return completely different value. */
    if(initial && quic->resumption && SSL_SESSION_get_max_early_data(SSL_get_session(quic->ssl))) {
        ret = SSL_write_early_data(quic->ssl, "", 0, &nwrite);
        if(ret == 0) {
            err = SSL_get_error(quic->ssl, ret);
            switch(err) {
                case SSL_ERROR_SSL:
                    quic_set_ssl_err(quic->errbuf, "SSL_write_early_data");
                    return QUIC_ERR_SSL;
                default:
                    quic_set_openngtcp2_err(quic->errbuf, "TLS write early data handshake error: %d", err);
                    return QUIC_ERR_SSL;
            }//end switch
        }//end if
    }//end if

    ret = SSL_do_handshake(quic->ssl);
    if(!initial && quic->resumption) {
        if(SSL_get_early_data_status(quic->ssl) != SSL_EARLY_DATA_ACCEPTED) {
            quic_set_openngtcp2_err(quic->errbuf, "Early data was rejected by server");
            ngtcp2_conn_early_data_rejected(quic->conn);
        }//end if
    }//end if

    if(ret <= 0) {
        err = SSL_get_error(quic->ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return QUIC_ERR_NONE;
            case SSL_ERROR_SSL:
                quic_set_ssl_err(quic->errbuf, "SSL_do_handshake");
                return QUIC_ERR_SSL;
            default:
                quic_set_openngtcp2_err(quic->errbuf, "TLS handshake error: %d", err);
                return QUIC_ERR_SSL;
        }//end switch
    }//end if

    ngtcp2_conn_handshake_completed(quic->conn);
    return QUIC_ERR_NONE;
}//end quic_client_tls_handshake

void quic_client_handle_early_data(QUIC *quic) {
    if(!quic->resumption || quic_setup_early_crypto_context(quic) != QUIC_ERR_NONE) {
        return;
    }//end if
}//end quic_client_handle_early_data

quic_err_t quic_client_do_connect_handshake(QUIC *quic) {
    int             ret;
    ssize_t         nwrite;
    u_int64_t       stream_id;
    quic_err_t      err;
    quic_buf_t      *buf;
    quic_state_t    old_state;
    quic_stream_t   *st;

    quic->in_init = true;
    err = quic_flush_sendbuf(quic);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    while(!QUIC_is_init_finished(quic)) {
        old_state = quic->state;
        switch(old_state) {
            case QUIC_STATE_WRITE_RTT0:
                err = quic_stream_map_foreach(quic->streams, quic_client_write_0rtt_streams_cb, quic);
                if(err == QUIC_ERR_NONE) {
                    if(quic->prev_state == QUIC_STATE_NONE) {
                        quic->state = QUIC_STATE_DO_HANDSHAKE_ONCE;
                    }//end if
                    if(old_state != QUIC_STATE_RECV) {
                        quic->prev_state = old_state;
                    }//end if
                    break;
                }//end if
                return err;

            case QUIC_STATE_DO_HANDSHAKE_ONCE:
                err = quic_do_handshake_once(quic, NULL, 0, &nwrite);
                if(err == QUIC_ERR_NONE) {
                    if(quic->prev_state == QUIC_STATE_WRITE_RTT0) {
                        quic->state = QUIC_STATE_RECV;
                    }//end if

                    if(old_state != QUIC_STATE_RECV) {
                        quic->prev_state = old_state;
                    }//end if
                    break;
                }//end if
                return err;

            case QUIC_STATE_RECV:
                err = quic_recv(quic);
                if(err == QUIC_ERR_NONE) {
                    if(quic->prev_state == QUIC_STATE_DO_HANDSHAKE_ONCE) {
                        quic->state = QUIC_STATE_DO_HANDSHAKE;
                    }//end if
                    else if(quic->prev_state == QUIC_STATE_DO_HANDSHAKE) {
                        quic->state = QUIC_STATE_DO_HANDSHAKE;
                    }//end if

                    if(old_state != QUIC_STATE_RECV) {
                        quic->prev_state = old_state;
                    }//end if
                    break;
                }//end if
                return err;

            case QUIC_STATE_DO_HANDSHAKE:
                if(ngtcp2_conn_get_handshake_completed(quic->conn)) {
                    quic->state = QUIC_STATE_FINISH_HANDSHAKE;
                    if(old_state != QUIC_STATE_RECV) {
                        quic->prev_state = old_state;
                    }//end if
                    break;
                }//end if
                err = quic_do_handshake(quic);
                if(err == QUIC_ERR_RETURN_ZERO) {
                    quic->state = QUIC_STATE_RECV;

                    if(old_state != QUIC_STATE_RECV) {
                        quic->prev_state = old_state;
                    }//end if
                    break;
                }//end if
                return err;

            default:
                quic_set_openngtcp2_err(quic->errbuf, "Unknown state: %d", quic->state);
                return QUIC_ERR_OPENNGTCP2;
        }//end switch
    }//end while

    //flush all pre set streams data
    if(QUIC_is_init_finished(quic)) {
        quic->state = QUIC_STATE_FINISH_HANDSHAKE;
        quic->in_init = false;
        while(!quic_deque_is_empty(quic->pre_streams)) {
            buf = quic_deque_pop_head(quic->pre_streams);
            ret = ngtcp2_conn_open_bidi_stream(quic->conn, &stream_id, NULL);
            if(ret != 0) {
                quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_open_bidi_stream", ret);
                return QUIC_ERR_OPENNGTCP2;
            }//end if

            st = quic_init_stream_with_buf(stream_id, buf);
            if(!st) {
                quic_set_openngtcp2_err(quic->errbuf, "Fail to init stream buffer");
                quic_free_buf(buf);
                return QUIC_ERR_OPENNGTCP2;
            }//end if

            err = quic_stream_map_insert_stream(quic->streams, stream_id, st);
            if(err != QUIC_ERR_NONE) {
                quic_set_openngtcp2_err(quic->errbuf, "Fail to insert stream data");
                quic_free_buf(buf);
                return QUIC_ERR_OPENNGTCP2;
            }//end if
        }//end while
    }//end if

    return QUIC_ERR_NONE;
}//end quic_client_do_connect_handshake

quic_err_t quic_client_write_0rtt_streams_cb(u_int64_t stream_id, quic_stream_t *stream, void *arg) {
    bool            fin;
    size_t          i, *streambuf_idx;
    QUIC            *quic;
    quic_buf_t      *buf;
    quic_err_t      err;
    quic_deque_t    *streambuf;

    quic = (QUIC *)arg;
    streambuf = quic_stream_get_streambuf(stream);
    streambuf_idx = quic_stream_get_streambuf_idx(stream);
    for(i = *streambuf_idx; ; i++) {
        buf = quic_deque_peek_nth(streambuf, (int)i);
        if(!buf) {
            break;
        }//end if
        fin = stream->should_send_fin && (quic_deque_peek_nth(streambuf, (int)i + 1) == NULL);
        err = quic_client_on_write_0rtt_stream(quic, quic_stream_get_stream_id(stream), fin, buf);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
        if(quic_buf_size(buf) > 0) {
            break;
        }//end if
        (*streambuf_idx)++;
    }//end for

    return QUIC_ERR_NONE;
}//end quic_client_write_0rtt_streams_cb


/* ===== private function ===== */
static quic_err_t quic_client_on_write_0rtt_stream(QUIC *quic, u_int64_t stream_id, u_int8_t fin, quic_buf_t *buf) {
    ssize_t     ndatalen, n;
    quic_err_t  err;

    for(;;) {
        n = ngtcp2_conn_client_handshake(
        quic->conn, quic_buf_wpos(quic->sendbuf), quic->max_pktlen,
        &ndatalen, NULL, 0, stream_id,
        fin, quic_buf_rpos(buf), quic_buf_size(buf), quic_timestamp());
        if(n < 0) {
            switch(n) {
                case NGTCP2_ERR_EARLY_DATA_REJECTED:
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                case NGTCP2_ERR_STREAM_SHUT_WR:
                case NGTCP2_ERR_STREAM_NOT_FOUND:
                case NGTCP2_ERR_NOBUF:
                    quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_client_handshake", n);
                    return QUIC_ERR_RETURN_ZERO;
            }//end switch
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_client_handshake", n);
            quic->shutdown_code = n;
            return QUIC_ERR_NGTCP2;
        }//end if
        else if(n == 0) {
            return QUIC_ERR_NONE;
        }//end if

        if(ndatalen > 0) {
            quic_buf_seek(buf, ndatalen);
        }//end if

        quic_buf_push(quic->sendbuf, n);
        err = quic_flush_sendbuf(quic);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
        if(quic_buf_size(buf) == 0) {
            break;
        }//end if
    }//end for

    return QUIC_ERR_NONE;
}//end quic_client_on_write_0rtt_stream