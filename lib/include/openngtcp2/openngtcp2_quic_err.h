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


#ifndef OPENNGTCP2_QUIC_ERR_H
#define OPENNGTCP2_QUIC_ERR_H

#define QUIC_ERRBUF_SIZE (384)
typedef enum {
    QUIC_ERR_NONE = 0,
    QUIC_ERR_SYSTEM = -1,
    QUIC_ERR_SSL = -2,
    QUIC_ERR_CRYPTO = -3,
    QUIC_ERR_NGTCP2 = -4,
    QUIC_ERR_OPENNGTCP2 = -5,
    QUIC_ERR_RETURN_ZERO = -6,
    QUIC_ERR_QUIC_WANT_READ = -7,
    QUIC_ERR_QUIC_WANT_WRITE = -8,
    QUIC_ERR_QUIC_WANT_DRAIN = -9,
    QUIC_ERR_QUIC_WANT_CLOSE = -10,
    QUIC_ERR_NOT_FOUND = -11,
    QUIC_ERR_EXSIT = -12
} quic_err_t;

#endif /* OPENNGTCP2_QUIC_ERR_H */