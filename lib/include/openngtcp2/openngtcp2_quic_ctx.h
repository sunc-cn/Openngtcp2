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


#ifndef OPENNGTCP2_QUIC_CTX_H
#define OPENNGTCP2_QUIC_CTX_H

struct quic_ctx_st;
typedef struct quic_ctx_st QUIC_CTX;

QUIC_CTX *QUIC_CTX_new(char *errbuf);
void QUIC_CTX_free(QUIC_CTX *quic_ctx);

/* OpenSSL callback */
void QUIC_CTX_set_alpn_cb(QUIC_CTX *quic_ctx, quic_alpn cb, void *arg);
void QUIC_CTX_set_keylog_cb(QUIC_CTX *quic_ctx, quic_keylog cb);

/* certificate */
quic_err_t QUIC_CTX_use_PrivateKey_file(QUIC_CTX *quic_ctx, const char *file);
quic_err_t QUIC_CTX_use_certificate_chain_file(QUIC_CTX *quic_ctx, const char *file);
quic_err_t QUIC_CTX_use_certificate_file(QUIC_CTX *quic_ctx, const char *file);
bool QUIC_CTX_check_private_key(QUIC_CTX *quic_ctx);
quic_err_t QUIC_CTX_use_certificate(QUIC_CTX *quic_ctx, X509 *x);
quic_err_t QUIC_CTX_use_PrivateKey(QUIC_CTX *quic_ctx, EVP_PKEY *pkey);

#endif /* OPENNGTCP2_QUIC_CTX_H */