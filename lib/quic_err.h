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


#ifndef QUIC_ERR_H
#define QUIC_ERR_H

#define quic_set_ssl_err(errbuf, call_func) \
    snprintf(errbuf, QUIC_ERRBUF_SIZE, "%d:%s:%s(): %s", __LINE__, __FUNCTION__, call_func, ERR_error_string(ERR_get_error(), NULL))
#define quic_set_ngtcp2_err(errbuf, call_func, err_num) \
    snprintf(errbuf, QUIC_ERRBUF_SIZE, "%d:%s:%s(): %s", __LINE__, __FUNCTION__, call_func, ngtcp2_strerror(err_num))
#define quic_set_sys_err(errbuf, call_func, err_num) \
    snprintf(errbuf, QUIC_ERRBUF_SIZE, "%d:%s:%s(): %s", __LINE__, __FUNCTION__, call_func, strerror(err_num))
#define quic_set_gai_err(errbuf, call_func, err_num) \
    snprintf(errbuf, QUIC_ERRBUF_SIZE, "%d:%s:%s(): %s", __LINE__, __FUNCTION__, call_func, gai_strerror(err_num))
#define quic_set_openngtcp2_err(errbuf, fmt, ...) \
    snprintf(errbuf, QUIC_ERRBUF_SIZE, "%d:%s(): "fmt, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#endif /* QUIC_ERR_H */