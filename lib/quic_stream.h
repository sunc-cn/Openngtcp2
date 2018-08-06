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


#ifndef QUIC_STREAM_H
#define QUIC_STREAM_H

struct quic_stream_st {
    u_int64_t       stream_id;
    quic_deque_t    *streambuf;
    size_t          streambuf_idx;
    u_int64_t       tx_stream_offset;
    bool            should_send_fin;
};
typedef struct quic_stream_st quic_stream_t;

quic_stream_t *quic_init_stream_with_fd(u_int64_t stream_id, int fd);
quic_stream_t *quic_init_stream_with_data(u_int64_t stream_id, const u_int8_t *data, size_t data_len);
quic_stream_t *quic_init_stream_with_buf(u_int64_t stream_id, quic_buf_t *buf);
void quic_free_stream(quic_stream_t *st);
quic_deque_t *quic_stream_get_streambuf(quic_stream_t *st);
size_t *quic_stream_get_streambuf_idx(quic_stream_t *st);
u_int64_t quic_stream_get_stream_id(quic_stream_t *st);
u_int64_t *quic_stream_get_tx_stream_offset(quic_stream_t *st);

#endif /* QUIC_STREAM_H */