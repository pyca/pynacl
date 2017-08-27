.. _building-a-local-library:

Building the bundled library
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you would avoid a system-wide installation of libsodium's development
files just for compiling a running the tests, you can instead install
the library and header files inside pynacl's sources.


Linux systems
"""""""""""""

On linux (and presumably other unix-like systems), after entering the
pynacl source directory you must execute the following commands:

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
    $ SUDIUMLIB="-L${PWD}/build/libsodium/lib"
    $ export SUDIUMLIB

environment variables, you can instruct the compiler to use the
just-installed library by simply dereferencing the path flags
on the c compier command line

.. code-block:: bash

    $ cc ${SODIUMINCL} ${SUDIUMLIB}

