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

quic_deque_t *quic_init_deque(void) {
    quic_deque_t *deque;

    deque = calloc(1, sizeof(quic_deque_t));
    if(!deque) {
        return NULL;
    }//end if

    return deque;
}//end quic_init_deque

void quic_free_deque(quic_deque_t *deque) {
    if(deque) {
        quic_free_list(deque->head);
        free(deque);
    }//end if
}//end quic_free_deque

void quic_free_deque_deep(quic_deque_t *deque, void (*free_cb)(void *)) {
    if(deque) {
        quic_free_list_deep(deque->head, free_cb);
        free(deque);
    }//end if
}//end quic_free_deque_deep

bool quic_deque_is_empty(quic_deque_t *deque) {
    return (deque->head == NULL) ? true : false;
}//end quic_deque_is_empty

size_t quic_deque_get_length(quic_deque_t *deque) {
    return deque->length;
}//end quic_deque_get_length

void quic_deque_reverse(quic_deque_t *deque) {
    deque->tail = deque->head;
    deque->head = quic_list_reverse(deque->head);
}//end quic_deque_reverse

quic_err_t quic_deque_foreach(quic_deque_t *deque, quic_err_t (*foreach_cb)(void *, void *), void *arg) {
    quic_err_t  err;
    quic_list_t *list, *next;

    list = deque->head;
    while(list) {
        next = list->next;
        err = foreach_cb(list->data, arg);
        if(err != QUIC_ERR_NONE) {
            return err;
        }//end if
        list = next;
    }//end while

    return QUIC_ERR_NONE;
}//end quic_deque_foreach

quic_err_t quic_deque_push_head(quic_deque_t *deque, void *data) {
    quic_list_t *new_head;

    new_head = quic_list_prepend(deque->head, data);
    if(!new_head) {
        return QUIC_ERR_SYSTEM;
    }//end if
    deque->head = new_head;

    if(!deque->tail) {
        deque->tail = deque->head;
    }//end if
    deque->length++;
    return QUIC_ERR_NONE;
}//end quic_deque_push_head

quic_err_t quic_deque_push_tail(quic_deque_t *deque, void *data) {
    quic_list_t *new_tail;

    new_tail = quic_list_append(deque->tail, data);
    if(!new_tail) {
        return QUIC_ERR_SYSTEM;
    }//end if
    deque->tail = new_tail;

    if(deque->tail->next) {
        deque->tail = deque->tail->next;
    }//end if
    else {
        deque->head = deque->tail;
    }//end else
    deque->length++;
    return QUIC_ERR_NONE;
}//end quic_deque_push_tail

void *quic_deque_pop_head(quic_deque_t *deque) {
    void        *data;
    quic_list_t *node;

    if(deque->head) {
        node = deque->head;
        data = node->data;

        deque->head = node->next;
        if(deque->head) {
            deque->head->prev = NULL;
        }//end if
        else {
            deque->tail = NULL;
        }//end else
        quic_free_list_node(node);
        deque->length--;

        return data;
    }//end if

    return NULL;
}//end quic_deque_pop_head

void *quic_deque_pop_tail(quic_deque_t *deque) {
    void        *data;
    quic_list_t *node;

    if(deque->tail) {
        node = deque->tail;
        data = node->data;

        deque->tail = node->prev;
        if(deque->tail) {
            deque->tail->next = NULL;
        }//end if
        else {
            deque->head = NULL;
        }//end else
        quic_free_list_node(node);
        deque->length--;

        return data;
    }//end if
  
    return NULL;
}//end quic_deque_pop_tail

void *quic_deque_peak_head(quic_deque_t *deque) {
    return deque->head ? deque->head->data : NULL;
}//end quic_deque_peak_head

void *quic_deque_peak_tail(quic_deque_t *deque) {
    return deque->tail ? deque->tail->data : NULL;
}//end quic_deque_peak_tail

void *quic_deque_peek_nth(quic_deque_t *deque, int n) {
    int         i;
    quic_list_t *link = NULL;

    if(n >= deque->length) {
        return NULL;
    }//end if

    if(n > deque->length / 2) {
        n = deque->length - n - 1;

        link = deque->tail;
        for(i = 0; i < n; i++) {
            link = link->prev;
        }//end for
    }//end if
    else {
        link = deque->head;
        for(i = 0; i < n; i++) {
            link = link->next;
        }//end for
    }//end else

    return link ? link->data : NULL;
}//end quic_deque_peek_nth