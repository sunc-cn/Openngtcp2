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


#ifndef OPENNGTCP2_QUIC_CTRL_H
#define OPENNGTCP2_QUIC_CTRL_H

/* ctrl integer */
quic_err_t QUIC_ctrl_set_integer(QUIC *quic, quic_ctrl_type type, int64_t value);
#define QUIC_set_idle_timeout(quic, value)          QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_IDLE_TIMEOUT, value)
#define QUIC_set_max_stream_data(quic, value)       QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_MAX_STREAM_DATA, value)
#define QUIC_set_max_data(quic, value)              QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_MAX_DATA, value)
#define QUIC_set_ack_delay_exponent(quic, value)    QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_ACK_DELAY_EXPONENT, value)
#define QUIC_set_max_pkt_size(quic_ctx, value)      QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_MAX_PKT_SIZE, value)
#define QUIC_set_nstreams(quic, value)              QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_NSTREAMS, value)
#define QUIC_set_fd(quic, value)                    QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_FD, value)
#define QUIC_set_max_bidi_streams(quic, value)      QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_MAX_BIDI_STREAMS, value)
#define QUIC_set_max_uni_streams(quic, value)       QUIC_ctrl_set_integer(quic, QUIC_CTRL_TYPE_MAX_UNI_STREAMS, value)

int64_t QUIC_ctrl_get_integer(QUIC *quic, quic_ctrl_type type);
#define QUIC_get_idle_timeout(quic)                 QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_IDLE_TIMEOUT)
#define QUIC_get_max_stream_data(quic)              QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_MAX_STREAM_DATA)
#define QUIC_get_max_data(quic)                     QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_MAX_DATA)
#define QUIC_get_ack_delay_exponent(quic)           QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_ACK_DELAY_EXPONENT)
#define QUIC_get_max_pkt_size(quic)                 QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_MAX_PKT_SIZE)
#define QUIC_get_nstreams(quic)                     QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_NSTREAMS)
#define QUIC_get_fd(quic)                           QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_FD)
#define QUIC_get_max_bidi_streams(quic)             QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_MAX_BIDI_STREAMS)
#define QUIC_get_max_uni_streams(quic)              QUIC_ctrl_get_integer(quic, QUIC_CTRL_TYPE_MAX_UNI_STREAMS)

/* ctrl string */
quic_err_t QUIC_ctrl_set_string(QUIC *quic, quic_ctrl_type type, const char *value);
#define QUIC_set_cipher_list(quic, value)           QUIC_ctrl_set_string(quic, QUIC_CTRL_TYPE_CIPHER_LIST, value)
#define QUIC_set_group_list(quic, value)            QUIC_ctrl_set_string(quic, QUIC_CTRL_TYPE_GROUP_LIST, value)
#define QUIC_set_tlsext_host_name(quic, value)      QUIC_ctrl_set_string(quic, QUIC_CTRL_TYPE_SNI, value)

const char *QUIC_ctrl_get_string(QUIC *quic, quic_ctrl_type type);
#define QUIC_get_cipher_list(quic)                  QUIC_ctrl_get_string(quic, QUIC_CTRL_TYPE_CIPHER_LIST)
#define QUIC_get_group_list(quic)                   QUIC_ctrl_get_string(quic, QUIC_CTRL_TYPE_GROUP_LIST)
#define QUIC_get_tlsext_host_name(quic)             QUIC_ctrl_get_string(quic, QUIC_CTRL_TYPE_SNI)
#define QUIC_get_err(quic)                          QUIC_ctrl_get_string(quic, QUIC_CTRL_TYPE_ERR_STR)

/* ctrl void */
quic_err_t QUIC_ctrl_set_void(QUIC *quic, quic_ctrl_type type, void *value);
#define QUIC_set_data(quic, value)                  QUIC_ctrl_set_void(quic, QUIC_CTRL_TYPE_DATA, value)
#define QUIC_set_ngtcp2_conn_callbacks(quic, value) QUIC_ctrl_set_void(quic, QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS, value)
#define QUIC_set_ngtcp2_settings(quic, value)       QUIC_ctrl_set_void(quic, QUIC_CTRL_TYPE_NGTCP2_SETTINGS, value)

const void *QUIC_ctrl_get_void(QUIC *quic, quic_ctrl_type type);
#define QUIC_get_data(quic)                         QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_DATA)
#define QUIC_get_QUIC_CTX(quic)                     ((QUIC_CTX *)(QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_QUIC_CTX)))
#define QUIC_get_SSL_CTX(quic)                      ((SSL_CTX *)QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_SSL_CTX))
#define QUIC_get_SSL(quic)                          ((SSL *)QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_SSL))
#define QUIC_get_ngtcp2_conn_callbacks(quic)        ((ngtcp2_conn_callbacks *)QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_NGTCP2_CONN_CALLBACKS))
#define QUIC_get_ngtcp2_settings(quic)              ((ngtcp2_settings *)QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_NGTCP2_SETTINGS))
#define QUIC_get_ngtcp2_conn(quic)                  ((ngtcp2_conn *)QUIC_ctrl_get_void(quic, QUIC_CTRL_TYPE_NGTCP2_CONN))

/* ctrl variable argument */
quic_err_t QUIC_set_alpn_protos(QUIC *quic, size_t len, ...);

#endif /* OPENNGTCP2_QUIC_CTRL_H */