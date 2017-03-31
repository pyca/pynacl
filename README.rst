PyNaCl
======

.. image:: https://img.shields.io/pypi/v/pynacl.svg
    :target: https://pypi.python.org/pypi/PyNaCl/
    :alt: Latest Version

.. image:: https://travis-ci.org/pyca/pynacl.svg?branch=master
    :target: https://travis-ci.org/pyca/pynacl

.. image:: https://codecov.io/github/pyca/pynacl/coverage.svg?branch=master
    :target: https://codecov.io/github/pyca/pynacl?branch=master

PyNaCl is a Python binding to `libsodium`_, which is a fork of the
`Networking and Cryptography library`_. These libraries have a stated goal of
improving usability, security and speed. It supports Python 2.7 and 3.3+ as
well as PyPy 2.6+.

.. _Networking and Cryptography library: https://nacl.cr.yp.to/


Installation
------------


Linux
~~~~~

PyNaCl relies on `libsodium`_, a portable C library. A copy is bundled
with PyNaCl so to install you can run:

.. code-block:: console

    $ pip install pynacl

If you'd prefer to use one provided by your distribution you can disable
the bundled copy during install by running:

.. code-block:: console

    $ SODIUM_INSTALL=system pip install pynacl


.. _libsodium: https://github.com/jedisct1/libsodium

Mac OS X & Windows
~~~~~~~~~~~~~~~~~~

PyNaCl ships as a binary wheel on OS X and Windows so all dependencies
are included. Make sure you have an up-to-date pip and run:

.. code-block:: console

    $ pip install pynacl


Features
--------

* Digital signatures
* Secret-key encryption
* Public-key encryption


Changes
-------

* 1.2.0 (UNRELEASED):

  * Update ``libsodium`` to 1.0.12.

* 1.1.2 - 2017-03-31:

  * reorder link time library search path when using bundled
    libsodium

* 1.1.1 - 2017-03-15:

  * Fixed a circular import bug in ``nacl.utils``.

* 1.1.0 - 2017-03-14:

  * Dropped support for Python 2.6.
  * Added ``shared_key()`` method on ``Box``.
  * You can now pass ``None`` to ``nonce`` when encrypting with ``Box`` or
    ``SecretBox`` and it will automatically generate a random nonce.
  * Added support for ``siphash24``.
  * Added support for ``blake2b``.
  * Added support for ``scrypt``.
  * Update ``libsodium`` to 1.0.11.
  * Default to the bundled ``libsodium`` when compiling.
  * All raised exceptions are defined mixing-in
    ``nacl.exceptions.CryptoError``

* 1.0.1:

  * Fix an issue with absolute paths that prevented the creation of wheels.

* 1.0:

  * PyNaCl has been ported to use the new APIs available in cffi 1.0+.
    Due to this change we no longer support PyPy releases older than 2.6.

  * Python 3.2 support has been dropped.

  * Functions to convert between Ed25519 and Curve25519 keys have been added.

* 0.3.0:

  * The low-level API (`nacl.c.*`) has been changed to match the
    upstream NaCl C/C++ conventions (as well as those of other NaCl bindings).
    The order of arguments and return values has changed significantly. To
    avoid silent failures, `nacl.c` has been removed, and replaced with
    `nacl.bindings` (with the new argument ordering). If you have code which
    calls these functions (e.g. `nacl.c.crypto_box_keypair()`), you must review
    the new docstrings and update your code/imports to match the new
    conventions.
