#!/bin/sh
cd $HOME
wget http://download.dnscrypt.org/libsodium/releases/libsodium-0.2.tar.gz
tar xvf libsodium-0.2
cd libsodium-0.2
./configure --disable-debug --disable-dependency-tracking
make
make check
make install
