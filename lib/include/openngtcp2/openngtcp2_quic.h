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


#ifndef OPENNGTCP2_QUIC_H
#define OPENNGTCP2_QUIC_H

struct quic_st;
typedef struct quic_st QUIC;

typedef struct {
    socklen_t len;
    union {
        struct sockaddr         sa;
        struct sockaddr_in      in;
        struct sockaddr_in6     in6;
        struct sockaddr_storage ss;
    };
} QUIC_ADDR;

typedef struct {
    QUIC_ADDR       addr;
    ngtcp2_pkt_hd   hd;
    u_int8_t        data[65536];
    size_t          data_len;
} QUIC_PREACCEPT;

/* for client connect */
QUIC *QUIC_new_connect(QUIC_CTX *quic_ctx, char *errbuf);

/* for server accept */
quic_err_t QUIC_preaccept(int server_fd, QUIC_PREACCEPT *pre_data, char *errbuf);
quic_err_t QUIC_send_version_negotiation(int server_fd, QUIC_PREACCEPT *pre_data, char *errbuf);
QUIC *QUIC_new_accept(QUIC_CTX *quic_ctx, QUIC_PREACCEPT *pre_data, char *errbuf);

/* io */
quic_err_t QUIC_set_data_to_stream(QUIC *quic, const u_int8_t *data, size_t data_len, u_int64_t *stream_id);
quic_err_t QUIC_update_data_to_stream(QUIC *quic, u_int64_t stream_id, const u_int8_t *data, size_t data_len);
quic_err_t QUIC_remove_data_to_stream(QUIC *quic, u_int64_t stream_id);
quic_err_t QUIC_write_streams(QUIC *quic);

quic_err_t QUIC_read_stream(QUIC *quic, u_int8_t *buf, size_t buf_size, size_t *buf_len, u_int64_t *stream_id);

/* for RTT0 */
quic_err_t QUIC_read_session_from_file(QUIC *quic, const char *fname);
quic_err_t QUIC_write_session_to_file(QUIC *quic, const char *fname);
quic_err_t QUIC_read_transport_params_from_file(QUIC *quic, const char *fname);
quic_err_t QUIC_write_transport_params_to_file(QUIC *quic, const char *fname);

/* common */
void QUIC_free(QUIC *quic);
quic_err_t QUIC_reinit_ngtcp2(QUIC *quic);
quic_err_t QUIC_do_handshake(QUIC *quic);
quic_err_t QUIC_shutdown(QUIC *quic);
bool QUIC_is_in_init(QUIC *quic);
bool QUIC_is_init_finished(QUIC *quic);
quic_err_t QUIC_do_retransmit(QUIC *quic);
bool QUIC_is_in_closing(QUIC *quic);

struct timespec QUIC_get_retransmit_timestamp(QUIC *quic);

/* bio */
void QUIC_set_rbio(QUIC *quic, BIO *b);
void QUIC_set_wbio(QUIC *quic, BIO *b);
void QUIC_set_bio(QUIC *quic, BIO *rbio, BIO *wbio);
BIO *QUIC_get_rbio(QUIC *quic);
BIO *QUIC_get_wbio(QUIC *quic);

/* certificate */
quic_err_t QUIC_use_PrivateKey_file(QUIC *quic, const char *file);
quic_err_t QUIC_use_certificate_chain_file(QUIC *quic, const char *file);
quic_err_t QUIC_use_certificate_file(QUIC *quic, const char *file);
bool QUIC_check_private_key(QUIC *quic);
quic_err_t QUIC_use_certificate(QUIC *quic, X509 *x);
quic_err_t QUIC_use_PrivateKey(QUIC *quic, EVP_PKEY *pkey);

#endif /* OPENNGTCP2_QUIC_H */