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

quic_err_t QUIC_ctrl_set_integer(QUIC *quic, quic_ctrl_type type, int64_t value) {
    switch(type) {
        case QUIC_CTRL_TYPE_IDLE_TIMEOUT:
            quic->settings.idle_timeout = value;
            break;

        case QUIC_CTRL_TYPE_MAX_STREAM_DATA:
            quic->settings.max_stream_data = value;
            break;

        case QUIC_CTRL_TYPE_MAX_DATA:
            quic->settings.max_data = value;
            break;

        case QUIC_CTRL_TYPE_ACK_DELAY_EXPONENT:
            quic->settings.ack_delay_exponent = value;
            break;

        case QUIC_CTRL_TYPE_MAX_PKT_SIZE:
            quic->settings.max_packet_size = value;
            break;

        case QUIC_CTRL_TYPE_NSTREAMS:
            quic->nstreams = value;
            break;

        case QUIC_CTRL_TYPE_FD:
            return quic_set_fd(quic, value);

        case QUIC_CTRL_TYPE_MAX_BIDI_STREAMS:
            quic->settings.max_bidi_streams = value;
            break;

        case QUIC_CTRL_TYPE_MAX_UNI_STREAMS:
            quic->settings.max_uni_streams = value;
            break;

        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_ctrl_set_integer

int64_t QUIC_ctrl_get_integer(QUIC *quic, quic_ctrl_type type) {
    switch(type) {
        case QUIC_CTRL_TYPE_IDLE_TIMEOUT:
            return quic->settings.idle_timeout;

        case QUIC_CTRL_TYPE_MAX_STREAM_DATA:
            return quic->settings.max_stream_data;

        case QUIC_CTRL_TYPE_MAX_DATA:
            return quic->settings.max_data;

        case QUIC_CTRL_TYPE_ACK_DELAY_EXPONENT:
            return quic->settings.ack_delay_exponent;

        case QUIC_CTRL_TYPE_MAX_PKT_SIZE:
            return quic->settings.max_packet_size;

        case QUIC_CTRL_TYPE_NSTREAMS:
            return quic->nstreams;

        case QUIC_CTRL_TYPE_FD:
            return quic->fd;

        case QUIC_CTRL_TYPE_MAX_BIDI_STREAMS:
            return quic->settings.max_bidi_streams;

        case QUIC_CTRL_TYPE_MAX_UNI_STREAMS:
            return quic->settings.max_uni_streams;

        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_ctrl_get_integer

quic_err_t QUIC_ctrl_set_string(QUIC *quic, quic_ctrl_type type, const char *value) {
    switch(type) {
        case QUIC_CTRL_TYPE_CIPHER_LIST:
            if(quic->ssl_ciphers) {
                free(quic->ssl_ciphers);
                quic->ssl_ciphers = NULL;
            }//end if
            if(SSL_set_cipher_list(quic->ssl, value) != 1) {
                quic_set_ssl_err(quic->errbuf, "SSL_set_cipher_list");
                return QUIC_ERR_SSL;
            }//end if
            quic->ssl_ciphers = strdup(value);
            if(!quic->ssl_ciphers) {
                quic_set_sys_err(quic->errbuf, "strdup", errno);
                return QUIC_ERR_SYSTEM;
            }//end if
            break;

        case QUIC_CTRL_TYPE_GROUP_LIST:
            if(quic->ssl_groups) {
                free(quic->ssl_groups);
                quic->ssl_groups = NULL;
            }//end if
            if(SSL_set1_groups_list(quic->ssl, value) != 1) {
                quic_set_ssl_err(quic->errbuf, "SSL_set1_groups_list");
                return QUIC_ERR_SSL;
            }//end if
            quic->ssl_groups = strdup(value);
            if(!quic->ssl_groups) {
                quic_set_sys_err(quic->errbuf, "strdup", errno);
                return QUIC_ERR_SYSTEM;
            }//end if
            break;

        case QUIC_CTRL_TYPE_SNI:
            if(quic->ssl_sni) {
                free(quic->ssl_sni);
                quic->ssl_sni = NULL;
            }//end if
            if(SSL_set_tlsext_host_name(quic->ssl, value) != 1) {
                quic_set_ssl_err(quic->errbuf, "SSL_set_tlsext_host_name");
                return QUIC_ERR_SSL;
            }//end if
            quic->ssl_sni = strdup(value);
            if(!quic->ssl_sni) {
                quic_set_sys_err(quic->errbuf, "strdup", errno);
                return QUIC_ERR_SYSTEM;
            }//end if
            break;

        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_ctrl_set_string

const char *QUIC_ctrl_get_string(QUIC *quic, quic_ctrl_type type) {
    switch(type) {
        case QUIC_CTRL_TYPE_CIPHER_LIST:
            return quic->ssl_ciphers;

        case QUIC_CTRL_TYPE_GROUP_LIST:
            return quic->ssl_groups;

        case QUIC_CTRL_TYPE_SNI:
            return quic->ssl_sni;

        case QUIC_CTRL_TYPE_ERR_STR:
            return quic->errbuf;

        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown ctrl type: %d", type);
            return NULL;
    }//end switch
    return "";
}//end QUIC_ctrl_get_string

quic_err_t QUIC_ctrl_set_void(QUIC *quic, quic_ctrl_type type, void *value) {
    switch(type) {
        case QUIC_CTRL_TYPE_DATA:
            quic->data = value;
            break;

        case QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS:
            memcpy(&(quic->callbacks), value, sizeof(quic->callbacks));
            break;

        case QUIC_CTRL_TYPE_NGTCP2_SETTINGS:
            memcpy(&(quic->settings), value, sizeof(quic->settings));
            break;

        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown ctrl type: %d", type);
            return QUIC_ERR_OPENNGTCP2;
    }//end switch
    return QUIC_ERR_NONE;
}//end QUIC_ctrl_set_void

const void *QUIC_ctrl_get_void(QUIC *quic, quic_ctrl_type type) {
    switch(type) {
        case QUIC_CTRL_TYPE_DATA:
            return quic->data;

        case QUIC_CTRL_TYPE_QUIC_CTX:
            return quic->quic_ctx;

        case QUIC_CTRL_TYPE_SSL_CTX:
            return quic->quic_ctx->ssl_ctx;

        case QUIC_CTRL_TYPE_SSL:
            return quic->ssl;

        case QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS:
            return &(quic->callbacks);

        case QUIC_CTRL_TYPE_NGTCP2_SETTINGS:
            return &(quic->settings);

        case QUIC_CTRL_TYPE_NGTCP2_CONN:
            return quic->conn;

        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unknown ctrl type: %d", type);
            return NULL;
    }//end switch
    return NULL;
}//end QUIC_ctrl_get_void

quic_err_t QUIC_set_alpn_protos(QUIC *quic, size_t len, ...) {
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
        quic_set_sys_err(quic->errbuf, "calloc", errno);
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

    if(SSL_set_alpn_protos(quic->ssl, buf, total_len) != 0) {
        quic_set_ssl_err(quic->errbuf, "SSL_set_alpn_protos");
        return QUIC_ERR_SSL;
    }//end if

    return QUIC_ERR_NONE;
}//end QUIC_set_alpn_protos