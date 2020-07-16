Installation
============

Binary wheel install
--------------------

PyNaCl ships as a binary wheel on macOS, Windows and Linux ``manylinux1`` [#many]_ ,
so all dependencies are included. Make sure you have an up-to-date pip
and run:

.. code-block:: console

    $ pip install pynacl

Faster wheel build
------------------

You can define the environment variable ``LIBSODIUM_MAKE_ARGS`` to pass arguments to ``make``
and enable `parallelization`_:

.. code-block:: console

    $ LIBSODIUM_MAKE_ARGS=-j4 pip install pynacl

Linux source build
------------------

PyNaCl relies on `libsodium`_, a portable C library. A copy is bundled
with PyNaCl so to install you can run:

.. code-block:: console

    $ pip install pynacl

If you'd prefer to use the version of ``libsodium`` provided by your
distribution, you can disable the bundled copy during install by running:

.. code-block:: console

    $ SODIUM_INSTALL=system pip install pynacl

.. warning:: Usage of the legacy ``easy_install`` command provided by setuptools
   is generally discouraged, and is completely unsupported in PyNaCl's case.

.. _parallelization: https://www.gnu.org/software/make/manual/html_node/Parallel.html

.. _libsodium: https://github.com/jedisct1/libsodium

.. [#many] `manylinux1 wheels <https://www.python.org/dev/peps/pep-0513/>`_
    are built on a baseline linux environment based on Centos 5.11
    and should work on most x86 and x86_64 glibc based linux environments.
