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

static void quic_free_stream_deque(void *data);

quic_stream_t *quic_init_stream_with_fd(u_int64_t stream_id, int fd) {
    size_t          data_len;
    u_int8_t        *data;
    struct stat     st;
    quic_stream_t   *stream;

    if(fstat(fd, &st) != 0) {
        return NULL;
    }//end if

    data_len = st.st_size;
    data = (u_int8_t *)mmap(NULL, data_len, PROT_READ, MAP_SHARED, fd, 0);
    if(!data) {
        return NULL;
    }//end if

    stream = quic_init_stream_with_data(stream_id, data, data_len);
    munmap((void *)data, data_len);
    return stream;
}//end quic_init_stream_with_fd

quic_stream_t *quic_init_stream_with_data(u_int64_t stream_id, const u_int8_t *data, size_t data_len) {
    quic_buf_t      *buf;
    quic_stream_t   *st;

    buf = quic_init_buf(data, data_len);
    if(!buf) {
        return NULL;
    }//end if

    st = quic_init_stream_with_buf(stream_id, buf);
    if(!st) {
        quic_free_buf(buf);
        return NULL;
    }//end if

    return st;
}//end quic_init_stream_with_data

quic_stream_t *quic_init_stream_with_buf(u_int64_t stream_id, quic_buf_t *buf) {
    quic_stream_t *st;

    st = calloc(1, sizeof(quic_stream_t));
    if(!st) {
        return NULL;
    }//end if

    st->should_send_fin = true;
    st->stream_id = stream_id;
    st->streambuf = quic_init_deque();
    if(!st->streambuf) {
        quic_free_stream(st);
        return NULL;
    }//end if

    if(quic_deque_push_tail(st->streambuf, buf) != QUIC_ERR_NONE) {
        quic_free_stream(st);
        return NULL;
    }//end if

    return st;
}//end quic_init_stream_with_buf

void quic_free_stream(quic_stream_t *st) {
    if(st) {
        if(st->streambuf) {
            quic_free_deque_deep(st->streambuf, quic_free_stream_deque);
        }//end if
        free(st);
    }//end if
}//end quic_free_stream

quic_deque_t *quic_stream_get_streambuf(quic_stream_t *st) {
    return st->streambuf;
}//end quic_stream_get_streambuf

size_t *quic_stream_get_streambuf_idx(quic_stream_t *st) {
    return &(st->streambuf_idx);
}//end quic_stream_get_streambuf_idx

u_int64_t quic_stream_get_stream_id(quic_stream_t *st) {
    return st->stream_id;
}//end quic_stream_get_stream_id

u_int64_t *quic_stream_get_tx_stream_offset(quic_stream_t *st) {
    return &(st->tx_stream_offset);
}//end quic_stream_get_tx_stream_offset


/* ===== private function ===== */
static void quic_free_stream_deque(void *data) {
    quic_buf_t *buf;
    if(data) {
        buf = (quic_buf_t *)data;
        quic_free_buf(buf);
    }//end if
}//end quic_free_stream_deque