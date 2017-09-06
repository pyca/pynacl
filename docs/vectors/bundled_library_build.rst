.. _building-a-local-library:

Building the bundled library
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you you want to avoid a system-wide installation of libsodium's
development files just for compiling and running the tests, you can
instead install the library and header files inside PyNaCl's sources.


Linux systems
"""""""""""""

On Linux (and presumably other UNIX-like systems), after entering the
PyNaCl source directory you must execute the following commands:

.. code-block:: bash

    $ mkdir -p build/libsodium
    $ cd build/libsodium
    $ ../../src/libsodium/configure --prefix=$PWD --disable-shared
    $ make
    $ make install
    $ cd ../..

If all went well,

.. code-block:: bash

    $ ls build/libsodium/{lib,include}

should generate something like the following output:

.. code-block:: bash

    build/libsodium/include:
    sodium  sodium.h

    build/libsodium/lib:
    libsodium.a  libsodium.la  pkgconfig

If you now define and export the

.. code-block:: bash

    $ SODIUMINCL="-I${PWD}/build/libsodium/include"
    $ export SODIUMINCL
    $ SODIUMLIB="-L${PWD}/build/libsodium/lib"
    $ export SODIUMLIB

environment variables, you can instruct the compiler to use the
just-installed library by simply dereferencing the path flags
on the c compier command line

.. code-block:: bash

    $ cc ${SODIUMINCL} ${SODIUMLIB}

