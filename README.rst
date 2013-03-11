PyNaCl
======

.. image:: https://travis-ci.org/dstufft/pynacl.png?branch=master
    :target: https://travis-ci.org/dstufft/pynacl

PyNaCl is a Python binding to the `Networking and Cryptography library`_,
a crypto library with the stated goal of improving usability, security and
speed.

.. _Networking and Cryptography library: http://nacl.cr.yp.to/


Installation
------------

PyNaCl relies on libsodium_, a portable C library which can be compiled
on a variety of systems. It may already be available from your package
manager.

.. _libsodium: https://github.com/jedisct1/libsodium

Once libsodium is installed, PyNaCl can be installed by:

.. code-block:: bash

    $ python setup.py install


Features
--------

* Digital signatures
* Secret-key encryption
* Public-key encryption (coming soon)
* HMAC (coming soon)
