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

static int quic_ssl_bio_write(BIO *b, const char *buf, int len);
static int quic_ssl_bio_read(BIO *b, char *buf, int len);
static int quic_ssl_bio_puts(BIO *b, const char *str);
static int quic_ssl_bio_gets(BIO *b, char *buf, int len);
static long quic_ssl_bio_ctrl(BIO *b, int cmd, long num, void *ptr);
static int quic_ssl_bio_create(BIO *b);
static int quic_ssl_bio_destroy(BIO *b);
static quic_err_t quic_ssl_bio_read_handshake(QUIC *quic, u_int8_t *buf, size_t buf_len, size_t *out_len);
static quic_err_t quic_ssl_bio_write_handshake(QUIC *quic, const u_int8_t *data, size_t data_len);

BIO_METHOD *quic_create_ssl_bio_method(void) {
    BIO_METHOD *meth;

    meth = BIO_meth_new(BIO_TYPE_FD, "bio");
    BIO_meth_set_write(meth, quic_ssl_bio_write);
    BIO_meth_set_read(meth, quic_ssl_bio_read);
    BIO_meth_set_puts(meth, quic_ssl_bio_puts);
    BIO_meth_set_gets(meth, quic_ssl_bio_gets);
    BIO_meth_set_ctrl(meth, quic_ssl_bio_ctrl);
    BIO_meth_set_create(meth, quic_ssl_bio_create);
    BIO_meth_set_destroy(meth, quic_ssl_bio_destroy);

    return meth;
}//end quic_create_ssl_bio_method


/* ===== private function ===== */
static int quic_ssl_bio_write(BIO *b, const char *buf, int len) {
    QUIC        *quic;
    quic_err_t  err;

    BIO_clear_retry_flags(b);
    quic = (QUIC *)BIO_get_data(b);

    err = quic_ssl_bio_write_handshake(quic, (const u_int8_t *)buf, len);
    if(err != QUIC_ERR_NONE) {
        return -1;
    }//end if

    return len;
}//end quic_ssl_bio_write

static int quic_ssl_bio_read(BIO *b, char *buf, int len) {
    QUIC    *quic;
    size_t  outlen;

    BIO_clear_retry_flags(b);
    quic = (QUIC *)BIO_get_data(b);

    if((quic_ssl_bio_read_handshake(quic, (u_int8_t *)buf, (size_t)len, &outlen) != QUIC_ERR_NONE) ||
        (outlen == 0)) {
        BIO_set_retry_read(b);
        return -1;
    }//end if

    return (int)outlen;
}//end quic_ssl_bio_read

static int quic_ssl_bio_puts(BIO *b, const char *str) {
    return quic_ssl_bio_write(b, str, strlen(str));
}//end quic_ssl_bio_puts

static int quic_ssl_bio_gets(BIO *b, char *buf, int len) {
    return -1;
}//end quic_ssl_bio_gets

static long quic_ssl_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
    switch(cmd) {
        case BIO_CTRL_FLUSH:
            return 1;
    }//end switch
    return 0;
}//end quic_ssl_bio_ctrl

static int quic_ssl_bio_create(BIO *b) {
    BIO_set_init(b, 1);
    return 1;
}//end quic_ssl_bio_create

static int quic_ssl_bio_destroy(BIO *b) {
    if(b == NULL) {
        return 0;
    }//end if
    return 1;
}//end quic_ssl_bio_destroy

static quic_err_t quic_ssl_bio_read_handshake(QUIC *quic, u_int8_t *buf, size_t buf_len, size_t *out_len) {
    size_t              n, *nread;
    quic_byte_array_t   *b;

    if(quic->type == QUIC_TYPE_CONNECT) {
        b = quic->shandshake.c;
        nread = &(quic->nsread);
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        b = quic->chandshake.s;
        nread = &(quic->ncread);
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return 0;
    }//end else

    n = buf_len < (quic_byte_array_get_length(b) - *nread) ? buf_len : (quic_byte_array_get_length(b) - *nread);
    memcpy(buf, quic_byte_array_get_data(b) + *nread, n);
    *nread += n;
    *out_len = n;

    return QUIC_ERR_NONE;
}//end quic_ssl_bio_read_handshake

static quic_err_t quic_ssl_bio_write_handshake(QUIC *quic, const u_int8_t *data, size_t data_len) {
    quic_buf_t      *buf;
    quic_deque_t    *d;

    if(quic->type == QUIC_TYPE_CONNECT) {
        d = quic->chandshake.c;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        d = quic->shandshake.s;
    }//end if
    else {
        quic_set_openngtcp2_err(quic->errbuf, "QUIC type is not determined");
        return QUIC_ERR_OPENNGTCP2;
    }//end else

    buf = quic_init_buf(data, data_len);
    if(!buf) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not allocate a buffer");
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    if(quic_deque_push_tail(d, buf) != QUIC_ERR_NONE) {
        quic_set_openngtcp2_err(quic->errbuf, "Could not append buffer data");
        quic_free_buf(buf);
        return QUIC_ERR_OPENNGTCP2;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_ssl_bio_write_handshake