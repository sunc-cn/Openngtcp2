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

static quic_err_t quic_byte_array_may_extend(quic_byte_array_t *arr, size_t data_len);

quic_byte_array_t *quic_init_byte_array(void) {
    return quic_init_byte_array_sized(128);
}//end quic_init_byte_array

quic_byte_array_t *quic_init_byte_array_sized(size_t size) {
    quic_byte_array_t *arr;

    arr = calloc(1, sizeof(quic_byte_array_t));
    if(!arr) {
        return NULL;
    }//end if

    arr->alloc_size = size;
    arr->data = calloc(size, sizeof(u_int8_t));
    if(!arr->data) {
        quic_free_byte_array(arr);
        return NULL;
    }//end if

    return arr;
}//end quic_init_byte_array_sized

void quic_free_byte_array(quic_byte_array_t *arr) {
    if(arr) {
        if(arr->data) {
            free(arr->data);
        }//end if
        free(arr);
    }//end if
}//end quic_free_byte_array

size_t quic_byte_array_get_length(quic_byte_array_t *arr) {
    return arr->data_len;
}//end quic_byte_array_get_length

u_int8_t *quic_byte_array_get_data(quic_byte_array_t *arr) {
    return arr->data;
}//end quic_byte_array_get_data

quic_err_t quic_byte_array_append(quic_byte_array_t *arr, const u_int8_t *data, size_t data_len) {
    return quic_byte_array_append_offset(arr, data, data_len, 0);
}//end quic_byte_array_append

quic_err_t quic_byte_array_append_offset(quic_byte_array_t *arr, const u_int8_t *data, size_t data_len, off_t offset) {
    quic_err_t err;

    err = quic_byte_array_may_extend(arr, data_len + offset);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    memcpy(arr->data + arr->data_len + offset, data, data_len);
    arr->data_len += (data_len + offset);

    return QUIC_ERR_NONE;
}//end quic_byte_array_append_offset


/* ===== private function ===== */
static quic_err_t quic_byte_array_may_extend(quic_byte_array_t *arr, size_t data_len) {
    void    *new_ptr;
    size_t  old_size, new_size;

    if(arr->alloc_size >= arr->data_len + data_len) {
        return QUIC_ERR_NONE;
    }//end if no need to realloc

    old_size = arr->alloc_size;
    new_size = (arr->alloc_size + data_len) * 2;

    new_ptr = realloc(arr->data, new_size);
    if(!new_ptr) {
        return QUIC_ERR_SYSTEM;
    }//end if

    //clear out
    memset((u_int8_t *)new_ptr + old_size, 0, new_size - old_size);
    arr->data = new_ptr;
    arr->alloc_size = new_size;

    return QUIC_ERR_NONE;
}//end quic_byte_array_may_extend