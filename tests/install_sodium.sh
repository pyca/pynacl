#!/bin/sh
set -e

cd $HOME
wget http://download.dnscrypt.org/libsodium/releases/libsodium-0.2.tar.gz
tar xvf libsodium-0.2.tar.gz
cd libsodium-0.2
./configure --disable-debug --disable-dependency-tracking
make
make check
make install
