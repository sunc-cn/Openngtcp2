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


#ifndef QUIC_STREAM_MAP_H
#define QUIC_STREAM_MAP_H

struct quic_stream_map_st {
    quic_stream_t   **streams;
    size_t          streams_len; /* streams buffer length */
    size_t          length;     /* count of streams in used */
};
typedef struct quic_stream_map_st quic_stream_map_t;

quic_stream_map_t *quic_init_stream_map(void);
void quic_free_stream_map(quic_stream_map_t *stm);
quic_stream_t *quic_stream_map_get(quic_stream_map_t *stm, u_int64_t stream_id);
quic_err_t quic_stream_map_insert_data(quic_stream_map_t *stm, u_int64_t stream_id, const u_int8_t *data, size_t data_len);
quic_err_t quic_stream_map_insert_stream(quic_stream_map_t *stm, u_int64_t stream_id, quic_stream_t *st);
quic_err_t quic_stream_map_replace_data(quic_stream_map_t *stm, u_int64_t stream_id, const u_int8_t *data, size_t data_len);
quic_err_t quic_stream_map_replace_stream(quic_stream_map_t *stm, u_int64_t stream_id, quic_stream_t *st);
quic_err_t quic_stream_map_remove(quic_stream_map_t *stm, u_int64_t stream_id);
bool quic_stream_map_is_empty(quic_stream_map_t *stm);
quic_err_t quic_stream_map_foreach(quic_stream_map_t *stm, quic_err_t (*foreach_cb)(u_int64_t, quic_stream_t *, void *), void *arg);

#endif /* QUIC_STREAM_MAP_H */