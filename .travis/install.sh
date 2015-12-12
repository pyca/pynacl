#!/bin/bash

set -e
set -x

if [[ $SODIUM_INSTALL == 'system' ]]; then
    wget https://download.libsodium.org/libsodium/releases/LATEST.tar.gz
    tar zxvf LATEST.tar.gz
    cd libsodium-*
    ./configure
    make
    make check
    sudo make install
    sudo ldconfig
fi

if [[ "${TOXENV}" == "pypy" ]]; then
    git clone https://github.com/yyuu/pyenv.git ~/.pyenv
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    pyenv install pypy-4.0.1
    pyenv global pypy-4.0.1
fi

pip install -U tox coveralls
