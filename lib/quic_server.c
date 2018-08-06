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

quic_err_t QUIC_preaccept(int server_fd, QUIC_PREACCEPT *pre_data, char *errbuf) {
    int             nread, ret;
    QUIC_ADDR       *addr;
    ngtcp2_pkt_hd   *hd;

    memset(pre_data, 0, sizeof(QUIC_PREACCEPT));
    addr = &(pre_data->addr);
    hd = &(pre_data->hd);
    addr->len = sizeof(addr->ss);
    pre_data->data_len = nread = recvfrom(server_fd, pre_data->data, sizeof(pre_data->data), MSG_DONTWAIT, &(addr->sa), &(addr->len));
    if(nread == -1) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
            case 0:
                return QUIC_ERR_QUIC_WANT_READ;
            default:
                quic_set_sys_err(errbuf, "recvfrom", errno);
                return QUIC_ERR_SYSTEM;
        }//end switch
    }//end if
    else if(nread == 0) {
        quic_set_openngtcp2_err(errbuf, "Receive zero length");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    if(nread < 1200) {
        quic_set_openngtcp2_err(errbuf, "Initial packet is too short: %d < 1200", nread);
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    ret = ngtcp2_accept(hd, pre_data->data, nread);
    if(ret == -1) {
        quic_set_openngtcp2_err(errbuf, "Unexpected packet received");
        return QUIC_ERR_OPENNGTCP2;
    }//end if
    else if(ret == 1) {
        //need to call QUIC_send_version_negotiation() when return
        return QUIC_ERR_QUIC_WANT_WRITE;
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_preaccept

QUIC *QUIC_new_accept(QUIC_CTX *quic_ctx, QUIC_PREACCEPT *pre_data, char *errbuf) {
    BIO     *bio;
    long    ssl_opts;
    QUIC    *quic;

    //start to allocate
    quic = calloc(1, sizeof(QUIC));
    if(!quic) {
        quic_set_sys_err(errbuf, "calloc", errno);
        return NULL;
    }//end if
    quic->type = QUIC_TYPE_ACCEPT;

    quic->ssl = SSL_new(quic_ctx->ssl_ctx);
    if(!quic->ssl) {
        quic_set_ssl_err(errbuf, "SSL_new");
        QUIC_free(quic);
        return NULL;
    }//end if
    
    quic->quic_ctx = quic_ctx;
    quic_ctx->ref_count++;

    //set ssl
    SSL_set_accept_state(quic->ssl);

    ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) | SSL_OP_SINGLE_ECDH_USE | SSL_OP_CIPHER_SERVER_PREFERENCE;
    SSL_set_options(quic->ssl, ssl_opts);
    SSL_set_max_early_data(quic->ssl, UINT32_MAX);

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
    quic->chandshake.s = quic_init_byte_array();
    if(!quic->chandshake.s) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate byte array");
        QUIC_free(quic);
        return NULL;
    }//end if

    //init server handshake
    quic->shandshake.s = quic_init_deque();
    if(!quic->shandshake.s) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate deque");
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

    //copy to receive buf
    memcpy(quic_buf_rpos(quic->recvbuf), pre_data->data, pre_data->data_len);
    quic_buf_push(quic->recvbuf, pre_data->data_len);

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
    quic->settings.stateless_reset_token_present = 1;
    QUIC_set_max_pkt_size(quic, NGTCP2_MAX_PKT_SIZE);
    QUIC_set_idle_timeout(quic, QUIC_DEFAULT_IDLE_TIMEOUT);
    QUIC_set_max_stream_data(quic, QUIC_DEFAULT_MAX_STREAM_DATA);
    QUIC_set_max_data(quic, QUIC_DEFAULT_MAX_DATA);
    QUIC_set_ack_delay_exponent(quic, QUIC_DEFAULT_ACK_DELAY_EXPONENT);
    QUIC_set_max_bidi_streams(quic, 100);
    QUIC_set_max_uni_streams(quic, 0);

    //other
    quic->fd = -1;
    quic->initial = true;
    //quic->prev_state = QUIC_STATE_NONE;
    //quic->state = QUIC_STATE_WRITE_RTT0;

    memcpy(&(quic->addr), &(pre_data->addr), sizeof(quic->addr));
    memcpy(&(quic->rcid), &(pre_data->hd.dcid), sizeof(quic->rcid));
    memcpy(&(quic->dcid), &(pre_data->hd.scid), sizeof(quic->dcid));
    quic->version = pre_data->hd.version;

    //init ngtcp2
    if(QUIC_reinit_ngtcp2(quic) != QUIC_ERR_NONE) {
        snprintf(errbuf, QUIC_ERRBUF_SIZE, "%s", quic->errbuf);
        QUIC_free(quic);
        return NULL;
    }//end if

    return quic;
}//end QUIC_new_accept

ngtcp2_lib_error quic_server_tls_handshake(QUIC *quic) {
    int         err, ret;
    size_t      nread;
    u_int8_t    buf[8];

    ERR_clear_error();

    if(quic->initial) {
        ret = SSL_read_early_data(quic->ssl, buf, sizeof(buf), &nread);
        quic->initial = false;

        switch(ret) {
            case SSL_READ_EARLY_DATA_ERROR:
                err = SSL_get_error(quic->ssl, ret);
                switch(err) {
                    case SSL_ERROR_WANT_READ:
                    case SSL_ERROR_WANT_WRITE:
                        if(SSL_get_early_data_status(quic->ssl) == SSL_EARLY_DATA_ACCEPTED && quic_setup_early_crypto_context(quic) != QUIC_ERR_NONE) {
                          return NGTCP2_ERR_INTERNAL;
                        }//end if
                        if(quic_setup_crypto_context(quic) != QUIC_ERR_NONE) {
                            return NGTCP2_ERR_INTERNAL;
                        }//end if
                        return 0;

                    case SSL_ERROR_SSL:
                        quic_set_ssl_err(quic->errbuf, "SSL_read_early_data");
                        return NGTCP2_ERR_TLS_HANDSHAKE;

                    default:
                        quic_set_openngtcp2_err(quic->errbuf, "TLS read early data handshake error: %d", err);
                        return NGTCP2_ERR_TLS_HANDSHAKE;
                }//end switch
                break;

            case SSL_READ_EARLY_DATA_SUCCESS:
                if(nread > 0) {
                    return NGTCP2_ERR_PROTO;
                }//end if
                break;

            case SSL_READ_EARLY_DATA_FINISH:
                break;
        }//end switch

        if(quic_setup_crypto_context(quic) != 0) {
            return NGTCP2_ERR_INTERNAL;
        }//end if
    }//end if

    ret = SSL_do_handshake(quic->ssl);
    if(ret <= 0) {
        err = SSL_get_error(quic->ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return 0;
            case SSL_ERROR_SSL:
                quic_set_ssl_err(quic->errbuf, "SSL_do_handshake");
                return NGTCP2_ERR_TLS_HANDSHAKE;
            default:
                quic_set_openngtcp2_err(quic->errbuf, "TLS handshake error: %d", err);
                return NGTCP2_ERR_TLS_HANDSHAKE;
        }//end switch
    }//end if

    ngtcp2_conn_handshake_completed(quic->conn);

    return 0;
}//end quic_server_tls_handshake

quic_err_t quic_server_do_accept_handshake(QUIC *quic) {
    int             ret;
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
            case QUIC_STATE_RECV:
                err = quic_recv(quic);
                if(err == QUIC_ERR_NONE) {
                    if(quic->prev_state == QUIC_STATE_NONE) {
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
    if(ngtcp2_conn_get_handshake_completed(quic->conn)) {
        quic->state = QUIC_STATE_FINISH_HANDSHAKE;
        quic->in_init = false;
        while(!quic_deque_is_empty(quic->pre_streams)) {
            buf = quic_deque_pop_head(quic->pre_streams);
            ret = ngtcp2_conn_open_uni_stream(quic->conn, &stream_id, NULL);
            if(ret != 0) {
                quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_open_uni_stream", ret);
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
}//end quic_server_do_accept_handshake