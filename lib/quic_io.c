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

static u_int32_t quic_generate_reserved_version(QUIC_PREACCEPT *pre_data);
static quic_err_t quic_stream_map_foreach_write_cb(u_int64_t stream_id, quic_stream_t *stream, void *arg);
static quic_err_t quic_on_write_stream(QUIC *quic, u_int64_t stream_id, u_int8_t fin, quic_buf_t *buf);

quic_err_t quic_send(QUIC *quic) {
    int nwrite, eintr_retries = 5;

    do {
        nwrite = BIO_write(quic->wbio, quic_buf_rpos(quic->sendbuf), quic_buf_size(quic->sendbuf));
    }//end do
    while ((nwrite == -1) && (errno == EINTR) && (eintr_retries-- > 0));
    if(nwrite == 0) {
        quic_set_openngtcp2_err(quic->errbuf, "Peer is closed");
        return QUIC_ERR_RETURN_ZERO;
    }//end if
    else if(nwrite < 0) {
        if(BIO_should_retry(quic->wbio)) {
            return QUIC_ERR_QUIC_WANT_WRITE;
        }//end if
        //quic_set_ssl_err(quic->errbuf, "BIO_write");
        quic_set_openngtcp2_err(quic->errbuf, "Peer is closed");
        return QUIC_ERR_SSL;
    }//end if

    quic_buf_reset(quic->sendbuf);
    return QUIC_ERR_NONE;
}//end quic_send

quic_err_t quic_recv(QUIC *quic) {
    int nread;

    quic_buf_reset(quic->recvbuf);
    nread = BIO_read(quic->rbio, quic_buf_wpos(quic->recvbuf), quic_buf_left_size(quic->recvbuf));
    if(nread == 0) {
        quic_set_openngtcp2_err(quic->errbuf, "Peer is closed");
        return QUIC_ERR_RETURN_ZERO;
    }//end if
    else if(nread < 0) {
        if(BIO_should_retry(quic->rbio)) {
            return QUIC_ERR_QUIC_WANT_READ;
        }//end if
        //quic_set_ssl_err(quic->errbuf, "BIO_read");
        quic_set_openngtcp2_err(quic->errbuf, "Peer is closed");
        return QUIC_ERR_SSL;
    }//end if

    quic_buf_push(quic->recvbuf, nread);
    return QUIC_ERR_NONE;
}//end quic_recv

quic_err_t QUIC_send_version_negotiation(int server_fd, QUIC_PREACCEPT *pre_data, char *errbuf) {
    int             eintr_retries = 5;
    ssize_t         nwrite;
    socklen_t       sa_len;
    u_int32_t       sv[2];
    quic_buf_t      *buf;
    ngtcp2_pkt_hd   *hd;
    struct sockaddr *sa;

    sv[0] = quic_generate_reserved_version(pre_data);
    sv[1] = NGTCP2_PROTO_VER_D12;

    buf = quic_init_buf_sized(NGTCP2_MAX_PKTLEN_IPV4);
    if(!buf) {
        quic_set_openngtcp2_err(errbuf, "Could not allocate send buffer");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    hd = &(pre_data->hd);
    sa = &(pre_data->addr.sa);
    sa_len = pre_data->addr.len;
    nwrite = ngtcp2_pkt_write_version_negotiation(
      quic_buf_wpos(buf), quic_buf_left_size(buf), random() % UINT8_MAX + 1,
      &(hd->scid), &(hd->dcid), sv, sizeof(sv)/sizeof(sv[0]));
    if(nwrite < 0) {
        quic_set_ngtcp2_err(errbuf, "ngtcp2_pkt_write_version_negotiation", nwrite);
        quic_free_buf(buf);
        return QUIC_ERR_NGTCP2;
    }//end if

    quic_buf_push(buf, nwrite);
    do {
        nwrite = sendto(server_fd, quic_buf_rpos(buf), quic_buf_size(buf), 0, sa, sa_len);
    }//end do
    while((nwrite == -1) && (errno == EINTR) && (eintr_retries-- > 0));
    if(nwrite < 0) {
        switch(errno) {
            case EAGAIN:
            case EINTR:
            case 0:
                return QUIC_ERR_QUIC_WANT_WRITE;
            default:
                quic_set_sys_err(errbuf, "sendto", errno);
                return QUIC_ERR_SYSTEM;
        }//end switch
    }//end if

    quic_free_buf(buf);
    return QUIC_ERR_NONE;
}//end QUIC_send_version_negotiation

quic_err_t quic_flush_sendbuf(QUIC *quic) {
    quic_err_t err;

    if(quic_buf_size(quic->sendbuf) > 0) {
        err = quic_send(quic);
        if(err != QUIC_ERR_NONE) {
            quic->shutdown_code = NGTCP2_ERR_INTERNAL;
            return err;
        }//end if
    }//end if
    quic_buf_reset(quic->sendbuf);
    return QUIC_ERR_NONE;
}//end quic_flush_sendbuf

quic_err_t QUIC_read_stream(QUIC *quic, u_int8_t *buf, size_t buf_size, size_t *buf_len, u_int64_t *stream_id) {
    int             ret;
    quic_err_t      err;
    quic_buf_t      *q_buf;
    quic_deque_t    *d;

    *buf_len = 0;
    *stream_id = -1;
    if(!QUIC_is_init_finished(quic)) {
        err = quic_do_handshake(quic);
        if(err == QUIC_ERR_RETURN_ZERO) {
            return QUIC_ERR_QUIC_WANT_READ;
        }//end if
        return err;
    }//end if

    if(buf_size < quic->max_pktlen) {
        quic_set_openngtcp2_err(quic->errbuf, "Buffer size is less than %zd", quic->max_pktlen);
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    err = quic_recv(quic);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    if(quic->recv_temp) {
        quic_free_stream(quic->recv_temp);
        quic->recv_temp = NULL;
    }//end if

    ret = ngtcp2_conn_recv(quic->conn,
        quic_buf_rpos(quic->recvbuf), quic_buf_size(quic->recvbuf),
        quic_timestamp());
    if(ret != 0) {
        quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_recv", ret);
        quic->shutdown_code = ret;
        if(ret == NGTCP2_ERR_DRAINING) {
            return QUIC_ERR_QUIC_WANT_DRAIN;
        }//end if
        else if(ret == NGTCP2_ERR_CLOSING) {
            return QUIC_ERR_QUIC_WANT_CLOSE;
        }//end if
        return QUIC_ERR_NGTCP2;
    }//end if

    if(!quic->recv_temp) {
        return QUIC_ERR_QUIC_WANT_READ;
    }//end if

    d = quic_stream_get_streambuf(quic->recv_temp);
    if(!d) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not get stream buffer deque");
        return QUIC_ERR_NGTCP2;
    }//end if

    q_buf = quic_deque_peak_head(d);
    if(!q_buf) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not get stream buffer");
        return QUIC_ERR_NGTCP2;
    }//end if

    *buf_len = quic_buf_size(q_buf);
    *stream_id = quic_stream_get_stream_id(quic->recv_temp);
    memcpy(buf, quic_buf_rpos(q_buf), *buf_len);

    return QUIC_ERR_NONE;
}//end QUIC_read_stream

quic_err_t QUIC_write_streams(QUIC *quic) {
    if(quic->type == QUIC_TYPE_CONNECT) {
        return quic_client_write_streams(quic, false);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        return quic_server_write_streams(quic, false);
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else
}//end QUIC_write_streams

quic_err_t quic_client_write_streams(QUIC *quic, bool retransmit) {
    int         ret;
    ssize_t     nwrite;
    quic_err_t  err;

    err = quic_flush_sendbuf(quic);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    if(retransmit) {
        ret = ngtcp2_conn_on_loss_detection_alarm(quic->conn, quic_timestamp());
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_on_loss_detection_alarm", ret);
            quic->shutdown_code = NGTCP2_ERR_INTERNAL;
            return QUIC_ERR_OPENNGTCP2;
        }//end if
    }//end if

    if(!QUIC_is_init_finished(quic)) {
        err = quic_do_handshake(quic);
        if(err == QUIC_ERR_RETURN_ZERO) {
            return QUIC_ERR_QUIC_WANT_READ;
        }//end if
        return err;
    }//end if

    for(;;) {
        nwrite = ngtcp2_conn_write_pkt(quic->conn,
            quic_buf_wpos(quic->sendbuf), quic->max_pktlen,
            quic_timestamp());
        if(nwrite < 0) {
            if(nwrite == NGTCP2_ERR_NOBUF) {
                break;
            }//end if
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_write_pkt", nwrite);
            quic->shutdown_code = nwrite;
            return QUIC_ERR_NGTCP2;
        }//end if

        if(nwrite == 0) {
            break;
        }//end if
        quic_buf_push(quic->sendbuf, nwrite);
        err = quic_flush_sendbuf(quic);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
    }//end for

    return !retransmit ? quic_stream_map_foreach(quic->streams, quic_stream_map_foreach_write_cb, quic) : QUIC_ERR_NONE;
}//end quic_client_write_streams

quic_err_t quic_server_write_streams(QUIC *quic, bool retransmit) {
    int         ret;
    ssize_t     nwrite;
    quic_err_t  err;

    if(ngtcp2_conn_in_closing_period(quic->conn)) {
        return QUIC_ERR_NONE;
    }//end if

    err = quic_flush_sendbuf(quic);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    if(retransmit) {
        ret = ngtcp2_conn_on_loss_detection_alarm(quic->conn, quic_timestamp());
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_on_loss_detection_alarm", ret);
            quic->shutdown_code = NGTCP2_ERR_INTERNAL;
            return QUIC_ERR_OPENNGTCP2;
        }//end if
    }//end if

    if(!QUIC_is_init_finished(quic)) {
        err = quic_do_handshake(quic);
        if(err == QUIC_ERR_RETURN_ZERO) {
            return QUIC_ERR_QUIC_WANT_READ;
        }//end if
        else if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
    }//end if

    err = quic_stream_map_foreach(quic->streams, quic_stream_map_foreach_write_cb, quic);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    if(!QUIC_is_init_finished(quic)) {
        return QUIC_ERR_QUIC_WANT_READ;
    }//end if

    for(;;) {
        nwrite = ngtcp2_conn_write_pkt(quic->conn,
            quic_buf_wpos(quic->sendbuf), quic->max_pktlen,
            quic_timestamp());
        if(nwrite < 0) {
            if(nwrite == NGTCP2_ERR_NOBUF) {
                break;
            }//end if
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_write_pkt", nwrite);
            quic->shutdown_code = nwrite;
            return QUIC_ERR_NGTCP2;
        }//end if

        if(nwrite == 0) {
            break;
        }//end if
        quic_buf_push(quic->sendbuf, nwrite);
        err = quic_flush_sendbuf(quic);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
    }//end for

    return QUIC_ERR_NONE;
}//end quic_server_write_streams


/* ===== private function ===== */
static quic_err_t quic_stream_map_foreach_write_cb(u_int64_t stream_id, quic_stream_t *stream, void *arg) {
    int             i;
    bool            fin;
    QUIC            *quic;
    size_t          *streambuf_idx;
    quic_err_t      err;
    quic_buf_t      *buf;
    quic_deque_t    *streambuf;

    quic = (void *)arg;
    streambuf_idx = quic_stream_get_streambuf_idx(stream);
    streambuf = quic_stream_get_streambuf(stream);
    for(i = *streambuf_idx; ; i++) {
        buf = quic_deque_peek_nth(streambuf, (int)i);
        if(!buf) {
            break;
        }//end if
        fin = stream->should_send_fin && (quic_deque_peek_nth(streambuf, (int)i + 1) == NULL);
        err = quic_on_write_stream(quic, quic_stream_get_stream_id(stream), fin, buf);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
        if(quic_buf_size(buf) > 0) {
            break;
        }//end if
        (*streambuf_idx)++;
    }//end for

    return QUIC_ERR_NONE;
}//end quic_stream_map_foreach_write_cb

static quic_err_t quic_on_write_stream(QUIC *quic, u_int64_t stream_id, u_int8_t fin, quic_buf_t *buf) {
    ssize_t     ndatalen, n;
    quic_err_t  err;

    for(;;) {
        n = ngtcp2_conn_write_stream(
        quic->conn, quic_buf_wpos(quic->sendbuf), quic->max_pktlen,
        &ndatalen, stream_id,
        fin, quic_buf_rpos(buf), quic_buf_size(buf), quic_timestamp());
        if(n < 0) {
            switch(n) {
                case NGTCP2_ERR_EARLY_DATA_REJECTED:
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                case NGTCP2_ERR_STREAM_SHUT_WR:
                case NGTCP2_ERR_STREAM_NOT_FOUND:
                case NGTCP2_ERR_NOBUF:
                    quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_write_stream", n);
                    return QUIC_ERR_RETURN_ZERO;
            }//end switch
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_write_stream", n);
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
}//end quic_on_write_stream

static u_int32_t quic_generate_reserved_version(QUIC_PREACCEPT *pre_data) {
    socklen_t       sa_len;
    u_int32_t       version, h;
    const u_int8_t  *p, *ep;
    struct sockaddr *sa;

    sa = &(pre_data->addr.sa);
    sa_len = pre_data->addr.len;
    version = pre_data->hd.version;
    h = 0x811C9DC5u;
    p = (const u_int8_t *)sa;
    ep = p + sa_len;

    for(; p != ep; ++p) {
        h ^= *p;
        h *= 0x01000193u;
    }//end for

    version = htonl(version);
    p = (const uint8_t *)&version;
    ep = p + sizeof(version);
    for(; p != ep; ++p) {
        h ^= *p;
        h *= 0x01000193u;
    }//end for
    h &= 0xf0f0f0f0u;
    h |= 0x0a0a0a0au;

    return h;
}//end quic_generate_reserved_version