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

static quic_err_t quic_stream_map_may_extend(quic_stream_map_t *stm, u_int64_t stream_id);

quic_stream_map_t *quic_init_stream_map(void) {
    quic_stream_map_t *stm = NULL;

    stm = calloc(1, sizeof(quic_stream_map_t));
    if(!stm) {
        return NULL;
    }//end if

    stm->streams_len = 8;
    stm->streams = calloc(stm->streams_len, sizeof(quic_stream_t *));
    if(!stm->streams) {
        quic_free_stream_map(stm);
        return NULL;
    }//end if

    return stm;
}//end quic_init_stream_map

void quic_free_stream_map(quic_stream_map_t *stm) {
    int i;
    if(stm) {
        if(stm->streams) {
            for(i = 0 ; i < stm->streams_len ; i++) {
                if(stm->streams[i]) {
                    quic_free_stream(stm->streams[i]);
                }//end if
            }//end for
            free(stm->streams);
        }//end if
        free(stm);
    }//end if
}//end quic_free_stream_map

quic_stream_t *quic_stream_map_get(quic_stream_map_t *stm, u_int64_t stream_id) {
    if(stream_id >= stm->streams_len) {
        return NULL;
    }//end if

    return stm->streams[stream_id];
}//end quic_stream_map_get

quic_err_t quic_stream_map_insert_data(quic_stream_map_t *stm, u_int64_t stream_id, const u_int8_t *data, size_t data_len) {
    quic_err_t      err;
    quic_stream_t   *st;

    if(quic_stream_map_get(stm, stream_id)) {
        return QUIC_ERR_EXSIT;
    }//end if

    st = quic_init_stream_with_data(stream_id, data, data_len);
    if(!st) {
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    //may extend
    err = quic_stream_map_may_extend(stm, stream_id);
    if(err != QUIC_ERR_NONE) {
        quic_free_stream(st);
        return err;
    }//end if

    err = quic_stream_map_insert_stream(stm, stream_id, st);
    if(err != QUIC_ERR_NONE) {
        quic_free_stream(st);
        return err;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_stream_map_insert_data

quic_err_t quic_stream_map_insert_stream(quic_stream_map_t *stm, u_int64_t stream_id, quic_stream_t *st) {
    if(quic_stream_map_get(stm, stream_id)) {
        return QUIC_ERR_EXSIT;
    }//end if

    stm->streams[stream_id] = st;
    stm->length++;
    return QUIC_ERR_NONE;
}//end quic_stream_map_insert_stream

quic_err_t quic_stream_map_replace_data(quic_stream_map_t *stm, u_int64_t stream_id, const u_int8_t *data, size_t data_len) {
    quic_stream_t *st;

    st = quic_stream_map_get(stm, stream_id);
    if(st) {
        quic_free_stream(st);
        stm->streams[stream_id] = NULL;
    }//end if
    else {
        return QUIC_ERR_NOT_FOUND;
    }//end else

    return quic_stream_map_insert_data(stm, stream_id, data, data_len);
}//end quic_stream_map_replace_data

quic_err_t quic_stream_map_replace_stream(quic_stream_map_t *stm, u_int64_t stream_id, quic_stream_t *st) {
    st = quic_stream_map_get(stm, stream_id);
    if(st) {
        quic_free_stream(st);
        stm->streams[stream_id] = NULL;
    }//end if
    else {
        return QUIC_ERR_NOT_FOUND;
    }//end else

    return quic_stream_map_insert_stream(stm, stream_id, st);
}//end quic_stream_map_replace_stream

quic_err_t quic_stream_map_remove(quic_stream_map_t *stm, u_int64_t stream_id) {
    quic_stream_t *st;

    st = quic_stream_map_get(stm, stream_id);
    if(st) {
        quic_free_stream(st);
        stm->streams[stream_id] = NULL;
        stm->length--;
        return QUIC_ERR_NONE;
    }//end if
    else {
        return QUIC_ERR_NOT_FOUND;
    }//end else
}//end quic_stream_map_remove

bool quic_stream_map_is_empty(quic_stream_map_t *stm) {
    return stm->length == 0 ? true : false;
}//end quic_stream_map_is_empty

quic_err_t quic_stream_map_foreach(quic_stream_map_t *stm, quic_err_t (*foreach_cb)(u_int64_t, quic_stream_t *, void *), void *arg) {
    size_t          i;
    quic_err_t      err;
    quic_stream_t   *st;

    for(i = 0 ; i < stm->streams_len ; i++) {
        st = stm->streams[i];
        if(st) {
            err = foreach_cb(i, st, arg);
            if(err != QUIC_ERR_NONE) {
                return err;
            }//end if
        }//end if
    }//end for

    return QUIC_ERR_NONE;
}//end quic_stream_map_foreach


/* ===== private function ===== */
static quic_err_t quic_stream_map_may_extend(quic_stream_map_t *stm, u_int64_t stream_id) {
    void    *new_ptr;
    size_t  new_size, old_size;

    if(stream_id < stm->streams_len) {
        return QUIC_ERR_NONE;
    }//end if

    old_size = stm->streams_len * sizeof(quic_stream_t *);
    new_size = stream_id * sizeof(quic_stream_t *) * 2;

    new_ptr = realloc(stm->streams, new_size);
    if(!new_ptr) {
        return QUIC_ERR_SYSTEM;
    }//end if

    //clear out
    memset((u_int8_t *)new_ptr + old_size, 0, new_size - old_size);
    stm->streams = new_ptr;
    stm->streams_len = new_size / sizeof(quic_stream_t *);

    return QUIC_ERR_NONE;
}//end quic_stream_map_may_extend