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

quic_list_t *quic_init_list(void *data) {
    quic_list_t *list;

    list = calloc(1, sizeof(quic_list_t));
    if(!list) {
        return NULL;
    }//end if
    list->data = data;

    return list;
}//end quic_init_list

void quic_free_list_deep(quic_list_t *list, void (*free_cb)(void *)) {
    quic_list_t *next;

    //foreach free
    while(list) {
        next = list->next;
        free_cb(list->data);
        free(list);
        list = next;
    }//end while
}//end quic_list_deep_free

void quic_free_list(quic_list_t *list) {
    quic_list_t *next;
    while(list) {
        next = list->next;
        free(list);
        list = next;
    }//end while
}//end quic_free_list

void quic_free_list_node(quic_list_t *list) {
    if(list) {
        free(list);
    }//end if
}//end quic_free_list_node

quic_list_t *quic_list_reverse(quic_list_t *list) {
    quic_list_t *last;

    last = NULL;
    while(list) {
        last = list;
        list = last->next;
        last->next = last->prev;
        last->prev = list;
    }//end while

    return last;
}//end quic_list_reverse

quic_list_t *quic_list_prepend(quic_list_t *list, void *data) {
    quic_list_t *new_list;

    new_list = quic_init_list(data);
    if(!new_list) {
        return NULL;
    }//end if
    new_list->next = list;

    if(list) {
        new_list->prev = list->prev;
        if(list->prev) {
            list->prev->next = new_list;
        }//end if
        list->prev = new_list;
    }//end if
    else {
        new_list->prev = NULL;
    }//end else
  
    return new_list;
}//end quic_list_prepend

quic_list_t *quic_list_append(quic_list_t *list, void *data) {
    quic_list_t *new_list, *last;

    new_list = quic_init_list(data);
    if(!new_list) {
        return NULL;
    }//end if

    if(list) {
        last = quic_list_last(list);
        last->next = new_list;
        new_list->prev = last;
        return list;
    }//end if
    else {
        new_list->prev = NULL;
        return new_list;
    }//end else
}//end quic_list_append

quic_list_t *quic_list_last(quic_list_t *list) {
    if(list) {
        while(list->next) {
            list = list->next;
        }//end while
    }//end if
    return list;
}//end quic_list_last