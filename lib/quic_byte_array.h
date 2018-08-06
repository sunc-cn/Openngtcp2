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


#ifndef QUIC_BYTE_ARRAY_H
#define QUIC_BYTE_ARRAY_H

struct quic_byte_array_st {
    u_int8_t *data;
    size_t data_len;
    size_t alloc_size;
};
typedef struct quic_byte_array_st quic_byte_array_t;

quic_byte_array_t *quic_init_byte_array(void);
quic_byte_array_t *quic_init_byte_array_sized(size_t size);
void quic_free_byte_array(quic_byte_array_t *arr);
size_t quic_byte_array_get_length(quic_byte_array_t *arr);
u_int8_t *quic_byte_array_get_data(quic_byte_array_t *arr);
quic_err_t quic_byte_array_append(quic_byte_array_t *arr, const u_int8_t *data, size_t data_len);
quic_err_t quic_byte_array_append_offset(quic_byte_array_t *arr, const u_int8_t *data, size_t data_len, off_t offset);

#endif /* QUIC_BYTE_ARRAY_H */