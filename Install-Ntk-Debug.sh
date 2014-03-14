#!/bin/sh

make clean
autoreconf -i
CFLAGS="-g" ./configure
make
sudo make install
