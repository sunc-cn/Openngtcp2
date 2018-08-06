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

quic_err_t QUIC_CTX_ctrl_set_integer(QUIC_CTX *quic_ctx, quic_ctrl_type type, int64_t value) {
    switch(type) {
        default:
            quic_set_openngtcp2_err(quic_ctx->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_CTX_ctrl_set_integer

int64_t QUIC_CTX_ctrl_get_integer(QUIC_CTX *quic_ctx, quic_ctrl_type type) {
    switch(type) {
        default:
            quic_set_openngtcp2_err(quic_ctx->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_CTX_ctrl_get_integer

quic_err_t QUIC_CTX_ctrl_set_string(QUIC_CTX *quic_ctx, quic_ctrl_type type, const char *value) {
    switch(type) {
        case QUIC_CTRL_TYPE_CIPHER_LIST:
            if(quic_ctx->ssl_ciphers) {
                free(quic_ctx->ssl_ciphers);
                quic_ctx->ssl_ciphers = NULL;
            }//end if
            if(SSL_CTX_set_cipher_list(quic_ctx->ssl_ctx, value) != 1) {
                quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_set_cipher_list");
                return QUIC_ERR_SSL;
            }//end if
            quic_ctx->ssl_ciphers = strdup(value);
            if(!quic_ctx->ssl_ciphers) {
                quic_set_sys_err(quic_ctx->errbuf, "strdup", errno);
                return QUIC_ERR_SYSTEM;
            }//end if
            break;

        case QUIC_CTRL_TYPE_GROUP_LIST:
            if(quic_ctx->ssl_groups) {
                free(quic_ctx->ssl_groups);
                quic_ctx->ssl_groups = NULL;
            }//end if
            if(SSL_CTX_set1_groups_list(quic_ctx->ssl_ctx, value) != 1) {
                quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_set1_groups_list");
                return QUIC_ERR_SSL;
            }//end if
            quic_ctx->ssl_groups = strdup(value);
            if(!quic_ctx->ssl_groups) {
                quic_set_sys_err(quic_ctx->errbuf, "strdup", errno);
                return QUIC_ERR_SYSTEM;
            }//end if
            break;

        default:
            quic_set_openngtcp2_err(quic_ctx->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_CTX_ctrl_set_string

const char *QUIC_CTX_ctrl_get_string(QUIC_CTX *quic_ctx, quic_ctrl_type type) {
    switch(type) {
        case QUIC_CTRL_TYPE_CIPHER_LIST:
            return quic_ctx->ssl_ciphers;

        case QUIC_CTRL_TYPE_GROUP_LIST:
            return quic_ctx->ssl_groups;

        case QUIC_CTRL_TYPE_ERR_STR:
            return quic_ctx->errbuf;

        default:
            quic_set_openngtcp2_err(quic_ctx->errbuf, "Unknown ctrl type: %d", type);
            return NULL;
    }//end switch
    return "";
}//end QUIC_CTX_ctrl_get_string

quic_err_t QUIC_CTX_ctrl_set_void(QUIC_CTX *quic_ctx, quic_ctrl_type type, void *value) {
    switch(type) {
        case QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS:
            memcpy(&(quic_ctx->callbacks), value, sizeof(quic_ctx->callbacks));
            break;

        default:
            quic_set_openngtcp2_err(quic_ctx->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_CTX_ctrl_set_void

const void *QUIC_CTX_ctrl_get_void(QUIC_CTX *quic_ctx, quic_ctrl_type type) {
    switch(type) {
        case QUIC_CTRL_TYPE_SSL_CTX:
            return quic_ctx->ssl_ctx;

        case QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS:
            return &(quic_ctx->callbacks);

        default:
            quic_set_openngtcp2_err(quic_ctx->errbuf, "Unknown ctrl type: %d", type);
            return NULL;
    }//end switch
    return NULL;
}//end QUIC_CTX_ctrl_get_void

quic_err_t QUIC_CTX_set_alpn_protos(QUIC_CTX *quic_ctx, size_t len, ...) {
    size_t          i, j = 0, total_len = 0, tmp_len;
    va_list         vap;
    const char      *tmp;
    unsigned char   *buf;

    va_start(vap, len);
    for(i = 0 ; i < len ; i++) {
        tmp = va_arg(vap, const char *);
        total_len += 1 + strlen(tmp);
    }//end for
    va_end(vap);

    buf = calloc(total_len, sizeof(unsigned char));
    if(!buf) {
        quic_set_sys_err(quic_ctx->errbuf, "calloc", errno);
        return QUIC_ERR_SYSTEM;
    }//end if

    va_start(vap, len);
    for(i = 0 ; i < len ; i++) {
        tmp = va_arg(vap, const char *);
        tmp_len = strlen(tmp);
        buf[j++] = tmp_len;
        memcpy(buf + j, tmp, tmp_len);
        j += tmp_len;
    }//end for
    va_end(vap);

    if(SSL_CTX_set_alpn_protos(quic_ctx->ssl_ctx, buf, total_len) != 0) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_set_alpn_protos");
        return QUIC_ERR_SSL;
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_CTX_set_alpn_protos

void QUIC_CTX_set_tlsext_servername_callback(QUIC_CTX *quic_ctx, int (*cb)(SSL *, int *, void *), void *arg) {
    SSL_CTX_set_tlsext_servername_callback(quic_ctx->ssl_ctx, cb);
    SSL_CTX_set_tlsext_servername_arg(quic_ctx->ssl_ctx, arg);
}//end QUIC_CTX_set_tlsext_servername_callback