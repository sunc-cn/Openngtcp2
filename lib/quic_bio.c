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

void QUIC_set_rbio(QUIC *quic, BIO *b) {
    if(quic->rbio == b) {
        return;
    }//end if

    if(quic->rbio) {
        BIO_free_all(quic->rbio);
    }//end if
    quic->rbio = b;
}//end QUIC_set_rbio

void QUIC_set_wbio(QUIC *quic, BIO *b) {
    if(quic->wbio == b) {
        return;
    }//end if

    if(quic->wbio) {
        BIO_free_all(quic->wbio);
    }//end if
    quic->wbio = b;
}//end QUIC_set_wbio

void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio) {
    if(rbio != NULL && rbio == wbio) {
        BIO_up_ref(rbio);
    }//end if

    QUIC_set_rbio(quic, rbio);
    QUIC_set_wbio(quic, wbio);
}//end QUIC_set_bio

BIO *QUIC_get_rbio(QUIC *quic) {
    return quic->rbio;
}//end QUIC_get_rbio

BIO *QUIC_get_wbio(QUIC *quic) {
    return quic->wbio;
}//end QUIC_get_wbio