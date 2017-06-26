Installation
============

Linux
-----

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
------------------

PyNaCl ships as a binary wheel on OS X and Windows so all dependencies
are included. Make sure you have an up-to-date pip and run:

.. code-block:: console

    $ pip install pynacl
