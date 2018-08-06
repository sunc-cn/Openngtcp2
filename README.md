Openngtcp2
=================
[ngtcp2](https://github.com/ngtcp2/ngtcp2) project is an effort to implement QUIC protocol which is now being discussed in IETF QUICWG for its standardization.

Openngtcp2 is a wrapped library to ngtcp2, that provide a series OpenSSL style API.

Requirements
----------------
* OpenSSL >= 1.1.1
* libevent
* ngtcp2(draft-12)

Build
----------------
```
#!/bin/sh


export OPENSSL_CFLAGS="-I/path/to/openssl/include"
export OPENSSL_LIBS="-L/path/to/openssl/lib -lssl -lcrypto"

export NGTCP2_CFLAGS="-I/path/to/ngtcp2/include"
export NGTCP2_LIBS="-L/path/to/ngtcp2/lib -lngtcp2"

export LIBEVENT_CFLAGS="-I/path/to/libevent/include"
export LIBEVENT_LIBS="-L/path/to/libevent/lib -levent -levent_core"

./configure --prefix=/path/to/openngtcp2

make
make install
```
