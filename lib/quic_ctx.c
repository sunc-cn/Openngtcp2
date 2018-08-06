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

static bool init_openssl = false;

QUIC_CTX *QUIC_CTX_new(char *errbuf) {
    QUIC_CTX    *quic_ctx;
    quic_err_t  err;
    const char  *ciphers = "TLS13-AES-128-GCM-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256";
    const char  *groups = "P-256:X25519:P-384:P-521";

    if(!init_openssl) {
        quic_srand();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();
        OpenSSL_add_ssl_algorithms();
        SSL_load_error_strings();
        ERR_load_ERR_strings();
        ERR_load_crypto_strings();
        ENGINE_load_builtin_engines();
    }//end if

    quic_ctx = calloc(1, sizeof(QUIC_CTX));
    if(!quic_ctx) {
        quic_set_sys_err(errbuf, "calloc", errno);
        return NULL;
    }//end if

    quic_ctx->ref_count = 1;

    //init SSL_CTX
    quic_ctx->ssl_ctx = SSL_CTX_new(TLS_method());
    if(!quic_ctx->ssl_ctx) {
        quic_set_ssl_err(errbuf, "SSL_CTX_new");
        QUIC_CTX_free(quic_ctx);
        return NULL;
    }//end if

    //set tls version to 1.3
    SSL_CTX_set_min_proto_version(quic_ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(quic_ctx->ssl_ctx, TLS1_3_VERSION);

    //set default ciphers and groups
    if(QUIC_CTX_set_cipher_list(quic_ctx, ciphers) != QUIC_ERR_NONE) {
        snprintf(errbuf, QUIC_ERRBUF_SIZE, "%s", quic_ctx->errbuf);
        QUIC_CTX_free(quic_ctx);
        return NULL;
    }//end if

    if(QUIC_CTX_set_group_list(quic_ctx, groups) != QUIC_ERR_NONE) {
        snprintf(errbuf, QUIC_ERRBUF_SIZE, "%s", quic_ctx->errbuf);
        QUIC_CTX_free(quic_ctx);
        return NULL;
    }//end if

    SSL_CTX_set_default_verify_paths(quic_ctx->ssl_ctx);

    //ngtcp2 callbacks
    quic_ctx->callbacks = (ngtcp2_conn_callbacks){
        quic_send_client_initial_cb,
        quic_send_client_handshake_cb,
        quic_recv_client_initial_cb,
        quic_send_server_handshake_cb,
        quic_recv_stream0_data_cb,
        quic_handshake_completed_cb,
        NULL,
        quic_do_hs_encrypt_cb,
        quic_do_hs_decrypt_cb,
        quic_do_encrypt_cb,
        quic_do_decrypt_cb,
        quic_do_hs_encrypt_pn_cb,
        quic_do_encrypt_pn_cb,
        quic_recv_stream_data_cb,
        quic_acked_stream_data_offset_cb,
        quic_stream_close_cb,
        NULL,
        quic_recv_server_stateless_retry_cb,
        quic_extend_max_stream_id_cb,
        quic_rand_cb
    };

    //quic ssl extension
    if(SSL_CTX_add_custom_ext(
          quic_ctx->ssl_ctx, NGTCP2_TLSEXT_QUIC_TRANSPORT_PARAMETERS,
          SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
          quic_transport_params_add_cb,
          quic_transport_params_free_cb,
          NULL,
          quic_transport_params_parse_cb,
          NULL) != 1) {
        quic_set_ssl_err(errbuf, "SSL_CTX_add_custom_ext");
        QUIC_CTX_free(quic_ctx);
        return NULL;
    }//end if

    //alpn list for client to send
    err = QUIC_CTX_set_alpn_protos(quic_ctx, 1, QUIC_ALPN_D12);
    if(err != QUIC_ERR_NONE) {
        snprintf(errbuf, QUIC_ERRBUF_SIZE, "%s", quic_ctx->errbuf);
        QUIC_CTX_free(quic_ctx);
        return NULL;
    }//end if

    //alpn list for server to select
    QUIC_CTX_set_alpn_cb(quic_ctx, quic_alpn_select_proto_cb, quic_ctx);

    //other
    SSL_CTX_set_session_cache_mode(quic_ctx->ssl_ctx, SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL_STORE);
    SSL_CTX_set_mode(quic_ctx->ssl_ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_QUIC_HACK);

    return quic_ctx;
}//end QUIC_CTX_new

void QUIC_CTX_free(QUIC_CTX *quic_ctx) {
    if(quic_ctx) {
        if(--(quic_ctx->ref_count) > 0) {
            return;
        }//end if
        if(quic_ctx->ssl_ctx) {
            SSL_CTX_free(quic_ctx->ssl_ctx);
        }//end if
        if(quic_ctx->ssl_ciphers) {
            free(quic_ctx->ssl_ciphers);
        }//end if
        if(quic_ctx->ssl_groups) {
            free(quic_ctx->ssl_groups);
        }//end if
        free(quic_ctx);
    }//end if
}//end QUIC_CTX_free

void QUIC_CTX_set_alpn_cb(QUIC_CTX *quic_ctx, quic_alpn cb, void *arg) {
    SSL_CTX_set_alpn_select_cb(quic_ctx->ssl_ctx, cb, arg);
}//end QUIC_CTX_set_alpn_cb

void QUIC_CTX_set_keylog_cb(QUIC_CTX *quic_ctx, quic_keylog cb) {
    SSL_CTX_set_keylog_callback(quic_ctx->ssl_ctx, cb);
}//end QUIC_CTX_set_keylog_cb

quic_err_t QUIC_CTX_use_PrivateKey_file(QUIC_CTX *quic_ctx, const char *file) {
    if(SSL_CTX_use_PrivateKey_file(quic_ctx->ssl_ctx, file, SSL_FILETYPE_PEM) != 1) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_use_PrivateKey_file");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_CTX_use_PrivateKey_file

quic_err_t QUIC_CTX_use_certificate_chain_file(QUIC_CTX *quic_ctx, const char *file) {
    if(SSL_CTX_use_certificate_chain_file(quic_ctx->ssl_ctx, file) != 1) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_use_certificate_chain_file");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_CTX_use_certificate_chain_file

quic_err_t QUIC_CTX_use_certificate_file(QUIC_CTX *quic_ctx, const char *file) {
    if(SSL_CTX_use_certificate_file(quic_ctx->ssl_ctx, file, SSL_FILETYPE_PEM) != 1) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_use_certificate_file");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_CTX_use_certificate_file

bool QUIC_CTX_check_private_key(QUIC_CTX *quic_ctx) {
    if(SSL_CTX_check_private_key(quic_ctx->ssl_ctx) != 1) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_check_private_key");
        return false;
    }//end if
    return true;
}//end QUIC_CTX_check_private_key

quic_err_t QUIC_CTX_use_certificate(QUIC_CTX *quic_ctx, X509 *x) {
    if(SSL_CTX_use_certificate(quic_ctx->ssl_ctx, x) != 1) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_use_certificate");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_CTX_use_certificate

quic_err_t QUIC_CTX_use_PrivateKey(QUIC_CTX *quic_ctx, EVP_PKEY *pkey) {
    if(SSL_CTX_use_PrivateKey(quic_ctx->ssl_ctx, pkey) != 1) {
        quic_set_ssl_err(quic_ctx->errbuf, "SSL_CTX_use_PrivateKey");
        return QUIC_ERR_SSL;
    }//end if
    return QUIC_ERR_NONE;
}//end QUIC_CTX_use_PrivateKey