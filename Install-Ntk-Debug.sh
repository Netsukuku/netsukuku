#!/bin/sh

make clean
autoreconf -i
CFLAGS="-g" "-std=c99" ./configure
make
sudo make install
