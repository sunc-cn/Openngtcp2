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


#ifndef QUIC_CRYPTO_H
#define QUIC_CRYPTO_H

struct quic_crypto_context_st {
    const EVP_MD        *prf;
    const EVP_CIPHER    *pn;
    const EVP_CIPHER    *aead;

    u_int8_t    tx_secret[64], rx_secret[64];
    size_t      secretlen;
};

quic_err_t quic_crypto_negotiated_prf(SSL *ssl, QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_negotiated_aead(SSL *ssl, QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_hkdf_expand(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    const u_int8_t *info, size_t infolen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_hkdf_extract(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    const u_int8_t *salt, size_t saltlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
ssize_t quic_crypto_encrypt_pn(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    QUIC_CRYPTO_CTX *crypto_ctx,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    char *errbuf);
ssize_t quic_crypto_encrypt(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *plaintext, size_t plaintextlen,
    QUIC_CRYPTO_CTX *crypto_ctx,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    char *errbuf);
ssize_t quic_crypto_decrypt(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *ciphertext, size_t ciphertextlen,
    QUIC_CRYPTO_CTX *crypto_ctx,
    const u_int8_t *key, size_t keylen,
    const u_int8_t *nonce, size_t noncelen,
    const u_int8_t *ad, size_t adlen,
    char *errbuf);
size_t quic_crypto_aead_max_overhead(QUIC_CRYPTO_CTX *crypto_ctx);
size_t quic_crypto_aead_key_length(QUIC_CRYPTO_CTX *crypto_ctx);
size_t quic_crypto_aead_nonce_length(QUIC_CRYPTO_CTX *crypto_ctx);
size_t quic_crypto_aead_tag_length(QUIC_CRYPTO_CTX *crypto_ctx);
quic_err_t quic_crypto_export_early_secret(u_int8_t *dest, size_t destlen, SSL *ssl, char *errbuf);
quic_err_t quic_crypto_export_secret(u_int8_t *dest, size_t destlen, SSL *ssl, const u_int8_t *label, size_t labellen, char *errbuf);
quic_err_t quic_crypto_derive_packet_protection_key_iv_pn(
    u_int8_t *key, size_t keylen, ssize_t *key_outlen,
    u_int8_t *iv, size_t ivlen, ssize_t *iv_outlen,
    u_int8_t *pn, size_t pnlen, ssize_t *pn_outlen,
    const u_int8_t *secret, size_t secretlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_derive_packet_protection_key(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    ssize_t *outlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_derive_packet_protection_iv(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    ssize_t *outlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_derive_pkt_num_protection_key(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    ssize_t *outlen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_export_client_secret(u_int8_t *dest, size_t destlen, SSL *ssl, char *errbuf);
quic_err_t quic_crypto_export_server_secret(u_int8_t *dest, size_t destlen, SSL *ssl, char *errbuf);
quic_err_t quic_crypto_qhkdf_expand(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    const u_int8_t *qlabel, size_t qlabellen,
    QUIC_CRYPTO_CTX *crypto_ctx, char *errbuf);
quic_err_t quic_crypto_derive_handshake_secret(
    u_int8_t *dest, size_t destlen,
    const ngtcp2_cid *secret,
    const u_int8_t *salt, size_t saltlen,
    char *errbuf);
quic_err_t quic_crypto_derive_client_handshake_secret(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    char *errbuf);
quic_err_t quic_crypto_derive_server_handshake_secret(
    u_int8_t *dest, size_t destlen,
    const u_int8_t *secret, size_t secretlen,
    char *errbuf);

#endif /* QUIC_CRYPTO_H */