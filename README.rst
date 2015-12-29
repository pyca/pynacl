PyNaCl
======

.. image:: https://pypip.in/version/PyNaCl/badge.svg?style=flat
    :target: https://pypi.python.org/pypi/PyNaCl/
    :alt: Latest Version

.. image:: https://travis-ci.org/pyca/pynacl.svg?branch=master
    :target: https://travis-ci.org/pyca/pynacl

.. image:: https://coveralls.io/repos/pyca/pynacl/badge.svg?branch=master
   :target: https://coveralls.io/r/pyca/pynacl?branch=master

PyNaCl is a Python binding to the `Networking and Cryptography library`_,
a crypto library with the stated goal of improving usability, security and
speed.

.. _Networking and Cryptography library: https://nacl.cr.yp.to/


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
* Public-key encryption
* HMAC (coming soon)


Changes
-------

* master: Python 3.2 support has been dropped.

* 0.3.0: the low-level API (`nacl.c.*`) has been changed to match the
  upstream NaCl C/C++ conventions (as well as those of other NaCl bindings).
  The order of arguments and return values has changed significantly. To
  avoid silent failures, `nacl.c` has been removed, and replaced with
  `nacl.bindings` (with the new argument ordering). If you have code which
  calls these functions (e.g. `nacl.c.crypto_box_keypair()`), you must review
  the new docstrings and update your code/imports to match the new
  conventions.
