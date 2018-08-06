#!/bin/sh


export OPENSSL_CFLAGS="-I/usr/local/opt/openssl@1.1/include"
export OPENSSL_LIBS="-L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto"

export NGTCP2_CFLAGS="-I/tmp/ngtcp2-master/include"
export NGTCP2_LIBS="-L/tmp/ngtcp2-master/lib -lngtcp2"

export LIBEVENT_CFLAGS="-I/usr/local/opt/libevent/include"
export LIBEVENT_LIBS="-L/usr/local/opt/libevent/lib -levent -levent_core"

./configure --prefix=/tmp/openngtcp2 \
    --disable-shared

make -j 8
make -j 8 install