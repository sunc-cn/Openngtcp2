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


#ifndef QUIC_SSL_CALLBACK_H
#define QUIC_SSL_CALLBACK_H

int quic_transport_params_add_cb(
    SSL *ssl, unsigned int ext_type,
    unsigned int content, const unsigned char **out,
    size_t *outlen, X509 *x, size_t chainidx, int *al,
    void *add_arg);
void quic_transport_params_free_cb(
    SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char *out,
    void *add_arg);
int quic_transport_params_parse_cb(
    SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char *in,
    size_t inlen, X509 *x, size_t chainidx, int *al,
    void *parse_arg);
int quic_alpn_select_proto_cb(
    SSL *ssl,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen,
    void *arg);

#endif /* QUIC_SSL_CALLBACK_H */