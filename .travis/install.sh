#!/bin/bash

set -e
set -x

# pin pyenv at the last known good release
PYENV_COMMIT=99d16707e372143fb35d822c26fe8427719b903c

# the following commit breaks tox virtualenv building
# on travis-ci
#
# PYENV_COMMIT=2657f1049cd45656918f601096509957d5b74e7c

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
