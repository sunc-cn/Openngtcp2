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


#ifndef OPENNGTCP2_QUIC_CTX_CTRL_H
#define OPENNGTCP2_QUIC_CTX_CTRL_H

/* ctrl integer */
quic_err_t QUIC_CTX_ctrl_set_integer(QUIC_CTX *quic_ctx, quic_ctrl_type type, int64_t value);

int64_t QUIC_CTX_ctrl_get_integer(QUIC_CTX *quic_ctx, quic_ctrl_type type);

/* ctrl string */
quic_err_t QUIC_CTX_ctrl_set_string(QUIC_CTX *quic_ctx, quic_ctrl_type type, const char *value);
#define QUIC_CTX_set_cipher_list(quic_ctx, value)           QUIC_CTX_ctrl_set_string(quic_ctx, QUIC_CTRL_TYPE_CIPHER_LIST, value)
#define QUIC_CTX_set_group_list(quic_ctx, value)            QUIC_CTX_ctrl_set_string(quic_ctx, QUIC_CTRL_TYPE_GROUP_LIST, value)

const char *QUIC_CTX_ctrl_get_string(QUIC_CTX *quic_ctx, quic_ctrl_type type);
#define QUIC_CTX_get_cipher_list(quic_ctx)                  QUIC_CTX_ctrl_get_string(quic_ctx, QUIC_CTRL_TYPE_CIPHER_LIST)
#define QUIC_CTX_get_group_list(quic_ctx)                   QUIC_CTX_ctrl_get_string(quic_ctx, QUIC_CTRL_TYPE_GROUP_LIST)
#define QUIC_CTX_get_err(quic_ctx)                          QUIC_CTX_ctrl_get_string(quic_ctx, QUIC_CTRL_TYPE_ERR_STR)

/* ctrl void */
quic_err_t QUIC_CTX_ctrl_set_void(QUIC_CTX *quic_ctx, quic_ctrl_type type, void *value);
#define QUIC_CTX_set_ngtcp2_conn_callbacks(quic_ctx, value) QUIC_CTX_ctrl_set_void(quic_ctx, QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS, value)

const void *QUIC_CTX_ctrl_get_void(QUIC_CTX *quic_ctx, quic_ctrl_type type);
#define QUIC_CTX_get_ngtcp2_conn_callbacks(quic_ctx)        ((ngtcp2_conn_callbacks *)QUIC_CTX_ctrl_get_void(quic_ctx, QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS))
#define QUIC_CTX_get_SSL_CTX(quic_ctx)                      ((SSL_CTX *)QUIC_CTX_ctrl_get_void(quic_ctx, QUIC_CTRL_TYPE_SSL_CTX))

/* ctrl variable argument */
quic_err_t QUIC_CTX_set_alpn_protos(QUIC_CTX *quic_ctx, size_t len, ...);

/* callback */
void QUIC_CTX_set_tlsext_servername_callback(QUIC_CTX *quic_ctx, int (*cb)(SSL *, int *, void *), void *arg);

#endif /* OPENNGTCP2_QUIC_CTX_CTRL_H */