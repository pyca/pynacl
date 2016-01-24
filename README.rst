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


Linux
~~~~~

PyNaCl relies on libsodium_, a portable C library. A copy is bundled
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
