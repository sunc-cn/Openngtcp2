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


#ifndef QUIC_DEQUE_H
#define QUIC_DEQUE_H

typedef struct quic_deque_st quic_deque_t;
struct quic_deque_st {
    size_t      length;
    quic_list_t *head;
    quic_list_t *tail;
};

quic_deque_t *quic_init_deque(void);
void quic_free_deque(quic_deque_t *deque);
void quic_free_deque_deep(quic_deque_t *deque, void (*free_cb)(void *));
bool quic_deque_is_empty(quic_deque_t *deque);
size_t quic_deque_get_length(quic_deque_t *deque);
void quic_deque_reverse(quic_deque_t *deque);
quic_err_t quic_deque_foreach(quic_deque_t *deque, quic_err_t (*foreach_cb)(void *, void *), void *arg);
quic_err_t quic_deque_push_head(quic_deque_t *deque, void *data);
quic_err_t quic_deque_push_tail(quic_deque_t *deque, void *data);
void *quic_deque_pop_head(quic_deque_t *deque);
void *quic_deque_pop_tail(quic_deque_t *deque);
void *quic_deque_peak_head(quic_deque_t *deque);
void *quic_deque_peak_tail(quic_deque_t *deque);
void *quic_deque_peek_nth(quic_deque_t *deque, int n);

#endif /* QUIC_DEQUE_H */