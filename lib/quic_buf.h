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


#ifndef QUIC_BUF_H
#define QUIC_BUF_H

struct quic_buf_st {
    u_int8_t *buf;
    size_t buf_len;

    u_int8_t *head;
    u_int8_t *tail;
};
typedef struct quic_buf_st quic_buf_t;

quic_buf_t *quic_init_buf_sized(size_t len);
quic_buf_t *quic_init_buf(const u_int8_t *data, size_t len);
void quic_free_buf(quic_buf_t *buf);
size_t quic_buf_size(quic_buf_t *buf);
size_t quic_buf_left_size(quic_buf_t *buf);
u_int8_t *quic_buf_data(quic_buf_t *buf);
u_int8_t *quic_buf_wpos(quic_buf_t *buf);
u_int8_t *quic_buf_rpos(quic_buf_t *buf);
void quic_buf_seek(quic_buf_t *buf, size_t len);
void quic_buf_push(quic_buf_t *buf, size_t len);
void quic_buf_reset(quic_buf_t *buf);

#endif /* QUIC_BUF_H */