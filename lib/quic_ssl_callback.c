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

int quic_transport_params_add_cb(
    SSL *ssl, unsigned int ext_type,
    unsigned int content, const unsigned char **out,
    size_t *outlen, X509 *x, size_t chainidx, int *al,
    void *add_arg) {
    int                     ret;
    QUIC                    *quic;
    ngtcp2_conn             *conn;
    ssize_t                 nwrite;
    u_int8_t                buf[512];
    ngtcp2_transport_params params;

    quic = (QUIC *)SSL_get_app_data(ssl);
    conn = quic->conn;

    if(quic->type == QUIC_TYPE_CONNECT) {
        ret = ngtcp2_conn_get_local_transport_params(conn, &params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_get_local_transport_params", ret);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }//end if

        nwrite = ngtcp2_encode_transport_params(buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
        if(nwrite < 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_encode_transport_params", ret);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }//end if

        *out = calloc(nwrite, sizeof(unsigned char));
        if(!(*out)) {
            quic_set_sys_err(quic->errbuf, "calloc", errno);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }//end if

        memcpy((void *)*out, buf, nwrite);
        *outlen = nwrite;
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        ret = ngtcp2_conn_get_local_transport_params(conn, &params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_get_local_transport_params", ret);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }//end if

        //assign supported versions
        params.v.ee.len = 1;
        params.v.ee.supported_versions[0] = NGTCP2_PROTO_VER_D12;

        nwrite = ngtcp2_encode_transport_params(buf, sizeof(buf), NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
        if(nwrite < 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_encode_transport_params", ret);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }//end if

        *out = calloc(nwrite, sizeof(unsigned char));
        if(!(*out)) {
            quic_set_sys_err(quic->errbuf, "calloc", errno);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }//end if

        memcpy((void *)*out, buf, nwrite);
        *outlen = nwrite;
    }//end if
    else {
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
    }//end else

    return 1;
}//end quic_transport_params_add_cb

void quic_transport_params_free_cb(
    SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char *out,
    void *add_arg) {
    free((void *)out);
}//end quic_transport_params_free_cb

int quic_transport_params_parse_cb(
    SSL *ssl, unsigned int ext_type,
    unsigned int context, const unsigned char *in,
    size_t inlen, X509 *x, size_t chainidx, int *al,
    void *parse_arg) {
    int                     ret;
    QUIC                    *quic;
    ngtcp2_conn             *conn;
    ngtcp2_transport_params params;

    quic = (QUIC *)SSL_get_app_data(ssl);
    conn = quic->conn;

    if(quic->type == QUIC_TYPE_CONNECT) {
        ret = ngtcp2_decode_transport_params(&params, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, in, inlen);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_decode_transport_params", ret);
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return -1;
        }//end if

        ret = ngtcp2_conn_set_remote_transport_params(conn, NGTCP2_TRANSPORT_PARAMS_TYPE_ENCRYPTED_EXTENSIONS, &params);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_set_remote_transport_params", ret);
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return -1;
        }//end if

        memcpy(&(quic->params), &params, sizeof(quic->params));
    }//end if
    else if(quic->type == QUIC_TYPE_ACCEPT) {
        if(context != SSL_EXT_CLIENT_HELLO) {
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return -1;
        }//end if

        ret = ngtcp2_decode_transport_params(&params, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, in, inlen);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_decode_transport_params", ret);
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return -1;
        }//end if

        ret = ngtcp2_conn_set_remote_transport_params(conn, NGTCP2_TRANSPORT_PARAMS_TYPE_CLIENT_HELLO, &params);
        if(ret != 0) {
            quic_set_ngtcp2_err(quic->errbuf, "ngtcp2_conn_set_remote_transport_params", ret);
            *al = SSL_AD_ILLEGAL_PARAMETER;
            return -1;
        }//end if
    }//end if
    else {
        *al = SSL_AD_ILLEGAL_PARAMETER;
        return -1;
    }//end else

    return 1;
}//end quic_transport_params_parse_cb

int quic_alpn_select_proto_cb(
    SSL *ssl,
    const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen,
    void *arg) {
    QUIC                *quic;
    size_t              alpnlen;
    u_int32_t           version;
    const uint8_t       *alpn;
    const unsigned char *p, *end;

    quic = SSL_get_app_data(ssl);
    version = ngtcp2_conn_negotiated_version(quic->conn);

    switch(version) {
        case NGTCP2_PROTO_VER_D12:
            alpn = (const u_int8_t *)"\x5"QUIC_ALPN_D12;
            alpnlen = strlen((const char *)alpn);
            break;
        default:
            quic_set_openngtcp2_err(quic->errbuf, "Unexpected quic protocol version: %010x", version);
            return SSL_TLSEXT_ERR_NOACK;
    }//end switch

    for(p = in, end = in + inlen; p + alpnlen <= end; p += *p + 1) {
        if(!memcmp(alpn, p, alpnlen)) {
            *out = p + 1;
            *outlen = *p;
            return SSL_TLSEXT_ERR_OK;
        }//end if
    }//end for

    *out = alpn + 1;
    *outlen = alpn[0];

    return SSL_TLSEXT_ERR_OK;
}//end quic_alpn_select_proto_cb