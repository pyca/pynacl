#!/bin/bash

set -e
set -x

# to pin pyenv version, set the PYENV_COMMIT variable
# to the required version commit identifier/tag like in
# PYENV_COMMIT=v1.0.7

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
    rm -rf ~/.pyenv
    git clone https://github.com/yyuu/pyenv.git ~/.pyenv
    git -C  ~/.pyenv reset --hard ${PYENV_COMMIT:-HEAD}
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    pyenv install pypy-5.3.1
    pyenv global pypy-5.3.1
fi

if [[ "${TOXENV}" == "py26" ]]; then
    rm -rf ~/.pyenv
    git clone https://github.com/yyuu/pyenv.git ~/.pyenv
    git -C  ~/.pyenv reset --hard ${PYENV_COMMIT:-HEAD}
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    pyenv install 2.6.9
    pyenv global 2.6.9
fi

if [[ "${TOXENV}" == "py33" ]]; then
    rm -rf ~/.pyenv
    git clone https://github.com/yyuu/pyenv.git ~/.pyenv
    git -C  ~/.pyenv reset --hard ${PYENV_COMMIT:-HEAD}
    PYENV_ROOT="$HOME/.pyenv"
    PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init -)"
    pyenv install 3.3.6
    pyenv global 3.3.6
fi

pip install -U tox coverage
