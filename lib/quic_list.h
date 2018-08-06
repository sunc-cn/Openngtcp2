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


#ifndef QUIC_LIST_H
#define QUIC_LIST_H

typedef struct quic_list_st quic_list_t;
struct quic_list_st {
    quic_list_t *prev;
    quic_list_t *next;
    void *data;
};

quic_list_t *quic_init_list(void *data);
void quic_free_list_deep(quic_list_t *list, void (*free_cb)(void *));
void quic_free_list(quic_list_t *list);
void quic_free_list_node(quic_list_t *list);
quic_list_t *quic_list_reverse(quic_list_t *list);
quic_list_t *quic_list_prepend(quic_list_t *list, void *data);
quic_list_t *quic_list_append(quic_list_t *list, void *data);
quic_list_t *quic_list_last(quic_list_t *list);

#endif /* QUIC_LIST_H */