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

quic_buf_t *quic_init_buf_sized(size_t len) {
    quic_buf_t *buf;

    buf = calloc(1, sizeof(quic_buf_t));
    if(!buf) {
        return NULL;
    }//end if

    buf->buf = calloc(len, sizeof(u_int8_t));
    if(!buf->buf) {
        quic_free_buf(buf);
        return NULL;
    }//end if
    buf->buf_len = len;
    buf->head = buf->tail = buf->buf;

    return buf;
}//end quic_init_buf_sized

quic_buf_t *quic_init_buf(const u_int8_t *data, size_t len) {
    quic_buf_t *buf;

    buf = calloc(1, sizeof(quic_buf_t));
    if(!buf) {
        return NULL;
    }//end if

    buf->buf = calloc(len, sizeof(u_int8_t));
    if(!buf->buf) {
        quic_free_buf(buf);
        return NULL;
    }//end if
    buf->buf_len = len;
    memcpy(buf->buf, data, len);
    buf->head = buf->buf;
    buf->tail = buf->buf + len;

    return buf;
}//end quic_init_buf

void quic_free_buf(quic_buf_t *buf) {
    if(buf) {
        if(buf->buf) {
            free(buf->buf);
        }//end if
        free(buf);
    }//end if
}//end quic_free_buf

size_t quic_buf_size(quic_buf_t *buf) {
    return buf->tail - buf->head;
}//end quic_buf_size

size_t quic_buf_left_size(quic_buf_t *buf) {
    return buf->buf_len - quic_buf_size(buf);
}//end quic_buf_left_size

u_int8_t *quic_buf_data(quic_buf_t *buf) {
    return buf->buf;
}//end quic_buf_data

u_int8_t *quic_buf_wpos(quic_buf_t *buf) {
    return buf->tail;
}//end quic_buf_wpos

u_int8_t *quic_buf_rpos(quic_buf_t *buf) {
    return buf->head;
}//end quic_buf_rpos

void quic_buf_seek(quic_buf_t *buf, size_t len) {
    buf->head += len;
}//end quic_buf_seek

void quic_buf_push(quic_buf_t *buf, size_t len) {
    buf->tail += len;
}//end quic_buf_push

void quic_buf_reset(quic_buf_t *buf) {
    buf->head = buf->tail = buf->buf;
}//end quic_buf_reset