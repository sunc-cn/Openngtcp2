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

quic_err_t quic_crypto_negotiated_prf(SSL *ssl, QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    u_int32_t   cipher_id;
    SSL_CIPHER  *cipher;

    cipher = SSL_get_current_cipher(ssl);
    if(!cipher) {
        quic_set_openngtcp2_err(errbuf, "No session has been established");
        return QUIC_ERR_CRYPTO;
    }//end if

    cipher_id = SSL_CIPHER_get_id(cipher);
    switch(cipher_id) {
        case 0x03001301u: // TLS_AES_128_GCM_SHA256
        case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
            crypto_ctx->prf = EVP_sha256();
            break;
        case 0x03001302u: // TLS_AES_256_GCM_SHA384
            crypto_ctx->prf = EVP_sha384();
            break;
        default:
            quic_set_openngtcp2_err(errbuf, "Unknown cipher id: %u\n", cipher_id);
            return QUIC_ERR_CRYPTO;
    }//end switch

    return QUIC_ERR_NONE;
}//end quic_crypto_negotiated_prf

quic_err_t quic_crypto_negotiated_aead(SSL *ssl, QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    u_int32_t   cipher_id;
    SSL_CIPHER  *cipher;

    cipher = SSL_get_current_cipher(ssl);
    if(!cipher) {
        quic_set_openngtcp2_err(errbuf, "No session has been established");
        return QUIC_ERR_CRYPTO;
    }//end if

    cipher_id = SSL_CIPHER_get_id(cipher);
    switch(cipher_id) {
        case 0x03001301u: // TLS_AES_128_GCM_SHA256
            crypto_ctx->aead = EVP_aes_128_gcm();
            crypto_ctx->pn = EVP_aes_128_ctr();
            break;
        case 0x03001302u: // TLS_AES_256_GCM_SHA384
            crypto_ctx->aead = EVP_aes_256_gcm();
            crypto_ctx->pn = EVP_aes_256_ctr();
            break;
        case 0x03001303u: // TLS_CHACHA20_POLY1305_SHA256
            crypto_ctx->aead = EVP_chacha20_poly1305();
            crypto_ctx->pn = EVP_chacha20();
            break;
        default:
            quic_set_openngtcp2_err(errbuf, "Unknown cipher id: %u\n", cipher_id);
            return QUIC_ERR_CRYPTO;
    }//end switch
    
    return QUIC_ERR_NONE;
}//end quic_crypto_negotiated_aead

quic_err_t quic_crypto_hkdf_expand(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    const u_int8_t *info, size_t infolen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    EVP_PKEY_CTX *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if(pctx == NULL) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_new_id");
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_derive_init(pctx) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_derive_init");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_hkdf_mode");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_set_hkdf_md(pctx, crypto_ctx->prf) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_set_hkdf_md");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, "", 0) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_set1_hkdf_salt");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_set1_hkdf_key");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_add1_hkdf_info");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_derive");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    EVP_PKEY_CTX_free(pctx);
    return QUIC_ERR_NONE;
}//end quic_crypto_hkdf_expand

quic_err_t quic_crypto_hkdf_extract(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    const u_int8_t *salt, size_t saltlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    EVP_PKEY_CTX *pctx;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if(pctx == NULL) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_new_id");
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_derive_init(pctx) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_derive_init");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_hkdf_mode");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_set_hkdf_md(pctx, crypto_ctx->prf) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_set_hkdf_md");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_set1_hkdf_salt");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secretlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_CTX_set1_hkdf_key");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    if(EVP_PKEY_derive(pctx, dest, &destlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_PKEY_derive");
        EVP_PKEY_CTX_free(pctx);
        return QUIC_ERR_CRYPTO;
    }//end if

    EVP_PKEY_CTX_free(pctx);
    return QUIC_ERR_NONE;
}//end quic_crypto_hkdf_extract

ssize_t quic_crypto_encrypt_pn(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    QUIC_CRYPTO_CTX *crypto_ctx,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    char *errbuf) {
    int             len;
    size_t          outlen = 0;
    EVP_CIPHER_CTX  *actx;

    actx = EVP_CIPHER_CTX_new();
    if(actx == NULL) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_new");
        return -1;
    }//end if

    if(EVP_EncryptInit_ex(actx, crypto_ctx->pn, NULL, key, nonce) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptInit_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptUpdate");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    outlen = len;
    if(EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    EVP_CIPHER_CTX_free(actx);
    return outlen;
}//end quic_crypto_encrypt_pn

ssize_t quic_crypto_encrypt(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    QUIC_CRYPTO_CTX *crypto_ctx,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    char *errbuf) {
    int             len;
    size_t          taglen, outlen = 0;
    EVP_CIPHER_CTX  *actx;

    taglen = quic_crypto_aead_tag_length(crypto_ctx);
    if(destlen < plaintextlen + taglen) {
        return -1;
    }//end if

    actx = EVP_CIPHER_CTX_new();
    if(actx == NULL) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_new");
        return -1;
    }//end if

    if(EVP_EncryptInit_ex(actx, crypto_ctx->aead, NULL, NULL, NULL) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptInit_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != 1) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_ctrl");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_EncryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptInit_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_EncryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptUpdate");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_EncryptUpdate(actx, dest, &len, plaintext, plaintextlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptUpdate");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    outlen = len;

    if(EVP_EncryptFinal_ex(actx, dest + outlen, &len) != 1) {
        quic_set_ssl_err(errbuf, "EVP_EncryptFinal_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    outlen += len;

    if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_GET_TAG, taglen, dest + outlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_ctrl");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    outlen += taglen;
    EVP_CIPHER_CTX_free(actx);
    return outlen;
}//end quic_crypto_encrypt

ssize_t quic_crypto_decrypt(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *ciphertext, size_t ciphertextlen,
    QUIC_CRYPTO_CTX *crypto_ctx,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    char *errbuf) {
    int             len;
    size_t          taglen, outlen;
    const u_int8_t  *tag;
    EVP_CIPHER_CTX  *actx;

    taglen = quic_crypto_aead_tag_length(crypto_ctx);
    if(taglen > ciphertextlen || destlen + taglen < ciphertextlen) {
        return -1;
    }//end if

    ciphertextlen -= taglen;
    tag = ciphertext + ciphertextlen;
    actx = EVP_CIPHER_CTX_new();
    if(actx == NULL) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_new");
        return -1;
    }//end if

    if(EVP_DecryptInit_ex(actx, crypto_ctx->aead, NULL, NULL, NULL) != 1) {
        quic_set_ssl_err(errbuf, "EVP_DecryptInit_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_IVLEN, noncelen, NULL) != 1) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_ctrl");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_DecryptInit_ex(actx, NULL, NULL, key, nonce) != 1) {
        quic_set_ssl_err(errbuf, "EVP_DecryptInit_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_DecryptUpdate(actx, NULL, &len, ad, adlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_DecryptUpdate");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_DecryptUpdate(actx, dest, &len, ciphertext, ciphertextlen) != 1) {
        quic_set_ssl_err(errbuf, "EVP_DecryptUpdate");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    outlen = len;

    if(EVP_CIPHER_CTX_ctrl(actx, EVP_CTRL_AEAD_SET_TAG, taglen, (u_int8_t *)tag) != 1) {
        quic_set_ssl_err(errbuf, "EVP_CIPHER_CTX_ctrl");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    if(EVP_DecryptFinal_ex(actx, dest + outlen, &len) != 1) {
        quic_set_ssl_err(errbuf, "EVP_DecryptFinal_ex");
        EVP_CIPHER_CTX_free(actx);
        return -1;
    }//end if

    EVP_CIPHER_CTX_free(actx);
    outlen += len;
    return outlen;
}//end quic_crypto_decrypt

size_t quic_crypto_aead_max_overhead(QUIC_CRYPTO_CTX *crypto_ctx) {
    return quic_crypto_aead_tag_length(crypto_ctx);
}//end quic_crypto_aead_max_overhead

size_t quic_crypto_aead_key_length(QUIC_CRYPTO_CTX *crypto_ctx) {
    return EVP_CIPHER_key_length(crypto_ctx->aead);
}//end quic_crypto_aead_key_length

size_t quic_crypto_aead_nonce_length(QUIC_CRYPTO_CTX *crypto_ctx) {
    return EVP_CIPHER_iv_length(crypto_ctx->aead);
}//end quic_crypto_aead_nonce_length

size_t quic_crypto_aead_tag_length(QUIC_CRYPTO_CTX *crypto_ctx) {
    if(crypto_ctx->aead == EVP_aes_128_gcm() || crypto_ctx->aead == EVP_aes_256_gcm()) {
        return EVP_GCM_TLS_TAG_LEN;
    }//end if
    if(crypto_ctx->aead == EVP_chacha20_poly1305()) {
        return EVP_CHACHAPOLY_TLS_TAG_LEN;
    }//end if
    return 0;
}//end quic_crypto_aead_tag_length

quic_err_t quic_crypto_export_early_secret(u_int8_t *dest, size_t destlen, SSL *ssl, char *errbuf) {
    int                 ret;
    static const char   label[] = "EXPORTER-QUIC 0rtt";

    ret = SSL_export_keying_material_early(
        ssl, dest, destlen,
        label, strlen(label),
        (const u_int8_t *)"", 0);
    if(ret != 1) {
        quic_set_ssl_err(errbuf, "SSL_export_keying_material_early");
        return QUIC_ERR_SSL;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_crypto_export_early_secret

quic_err_t quic_crypto_export_secret(u_int8_t *dest, size_t destlen, SSL *ssl, const u_int8_t *label, size_t labellen, char *errbuf) {
    int ret;

    ret = SSL_export_keying_material(ssl,
        dest, destlen, (const char *)label, labellen,
        (const u_int8_t *)"", 0, 1);
    if(ret != 1) {
        quic_set_ssl_err(errbuf, "SSL_export_keying_material");
        return QUIC_ERR_SSL;
    }//end if

    return QUIC_ERR_NONE;
}//end quic_crypto_export_secret

quic_err_t quic_crypto_derive_packet_protection_key_iv_pn(
    u_int8_t *key, size_t keylen, ssize_t *key_outlen,
    u_int8_t *iv, size_t ivlen, ssize_t *iv_outlen,
    u_int8_t *pn, size_t pnlen, ssize_t *pn_outlen,
    const u_int8_t *secret, size_t secretlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    quic_err_t err;

    err = quic_crypto_derive_packet_protection_key(
        key, keylen,
        secret, secretlen,
        key_outlen,
        crypto_ctx, errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_packet_protection_iv(
        iv, ivlen,
        secret, secretlen,
        iv_outlen,
        crypto_ctx, errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    err = quic_crypto_derive_pkt_num_protection_key(
        pn, pnlen,
        secret, secretlen,
        pn_outlen,
        crypto_ctx, errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    return QUIC_ERR_NONE;
}//end derive_packet_protection_key_iv_pn

quic_err_t quic_crypto_derive_packet_protection_key(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    ssize_t *outlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    quic_err_t              err;
    size_t                  keylen;
    static const u_int8_t   label_key[] = "key";

    keylen = quic_crypto_aead_key_length(crypto_ctx);
    if(keylen > destlen) {
        return QUIC_ERR_SSL;
    }//end if

    err = quic_crypto_qhkdf_expand(dest, keylen, secret, secretlen, label_key, strlen((const char *)label_key), crypto_ctx, errbuf);
    if(err != QUIC_ERR_NONE) {
        return err;
    }//end if

    *outlen = keylen;
    return QUIC_ERR_NONE;
}//end quic_crypto_derive_packet_protection_key

quic_err_t quic_crypto_derive_packet_protection_iv(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    ssize_t *outlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    size_t                  ivlen;
    quic_err_t              err;
    static const u_int8_t   label_iv[] = "iv";

    ivlen = 8 > quic_crypto_aead_nonce_length(crypto_ctx) ? 8 : quic_crypto_aead_nonce_length(crypto_ctx);
    if(ivlen > destlen) {
        return QUIC_ERR_SSL;
    }//end if

    err = quic_crypto_qhkdf_expand(dest, ivlen, secret, secretlen, label_iv, strlen((const char *)label_iv), crypto_ctx, errbuf);
    if(err != 0) {
        return QUIC_ERR_SSL;
    }//end if

    *outlen = ivlen;
    return QUIC_ERR_NONE;
}//end quic_crypto_derive_packet_protection_iv

quic_err_t quic_crypto_derive_pkt_num_protection_key(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    ssize_t *outlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    size_t                  keylen;
    quic_err_t              err;
    static const u_int8_t   label_pknkey[] = "pn";

    keylen = quic_crypto_aead_key_length(crypto_ctx);
    if(keylen > destlen) {
        return QUIC_ERR_SSL;
    }//end if

    err = quic_crypto_qhkdf_expand(dest, keylen, secret, secretlen, label_pknkey, strlen((const char *)label_pknkey), crypto_ctx, errbuf);
    if(err != 0) {
        return QUIC_ERR_SSL;
    }//end if

    *outlen = keylen;
    return QUIC_ERR_NONE;
}//end quic_crypto_derive_pkt_num_protection_key

quic_err_t quic_crypto_export_client_secret(u_int8_t *dest, size_t destlen, SSL *ssl, char *errbuf) {
    static const u_int8_t label[] = "EXPORTER-QUIC client 1rtt";
    return quic_crypto_export_secret(dest, destlen, ssl, label, strlen((const char *)label), errbuf);
}//end quic_crypto_export_client_secret

quic_err_t quic_crypto_export_server_secret(u_int8_t *dest, size_t destlen, SSL *ssl, char *errbuf) {
    static const u_int8_t label[] = "EXPORTER-QUIC server 1rtt";
    return quic_crypto_export_secret(dest, destlen, ssl, label, strlen((const char *)label), errbuf);
}//end quic_crypto_export_server_secret

quic_err_t quic_crypto_qhkdf_expand(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    const u_int8_t *qlabel, size_t qlabellen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf) {
    size_t                  len;
    u_int8_t                info[256], *p;
    static const u_int8_t   label[] = "QUIC ";

    len = strlen((const char *)label);
    p = info;
    *p++ = destlen / 256;
    *p++ = destlen % 256;
    *p++ = len + qlabellen;
    memcpy(p, label, len);
    p += len;
    memcpy(p, qlabel, qlabellen);
    p += qlabellen;

    return quic_crypto_hkdf_expand(dest, destlen, secret, secretlen, info, p - info, crypto_ctx, errbuf);
}//end quic_crypto_qhkdf_expand

quic_err_t quic_crypto_derive_handshake_secret(
    u_int8_t *dest, size_t destlen,
    const ngtcp2_cid *secret,
    const u_int8_t *salt, size_t saltlen,
    char *errbuf) {
    QUIC_CRYPTO_CTX crypto_ctx;
    crypto_ctx.prf = EVP_sha256();
    return quic_crypto_hkdf_extract(dest, destlen, secret->data, secret->datalen, salt, saltlen, &crypto_ctx, errbuf);
}//end quic_crypto_derive_handshake_secret

quic_err_t quic_crypto_derive_client_handshake_secret(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    char *errbuf) {
    QUIC_CRYPTO_CTX         crypto_ctx;
    static const u_int8_t   label[] = "client hs";

    crypto_ctx.prf = EVP_sha256();
    return quic_crypto_qhkdf_expand(dest, destlen, secret, secretlen, label, strlen((const char *)label), &crypto_ctx, errbuf);
}//end quic_crypto_derive_client_handshake_secret

quic_err_t quic_crypto_derive_server_handshake_secret(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    char *errbuf) {
    QUIC_CRYPTO_CTX         crypto_ctx;
    static const u_int8_t   label[] = "server hs";

    crypto_ctx.prf = EVP_sha256();
    return quic_crypto_qhkdf_expand(dest, destlen, secret, secretlen, label, strlen((const char *)label), &crypto_ctx, errbuf);
}//end quic_crypto_derive_server_handshake_secret