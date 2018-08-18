secretstream reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since libsodium's tests do not provide reference data for the secretstream
construction, the implementation is verified with a
``secretstream_test_vector`` utility program that produces custom test vectors
by making specific calls to the libsodium API.

To build the ``secretstream_test_vector`` you need a ``C`` language compiler,
a prebuilt libsodium library more recent than version 1.0.14 and the
corresponding include headers.

In a UNIX-like programming environment you should then execute:

.. code-block:: bash

    $ cc -o secretstream_test_vector secretstream_test_vector.c -lsodium -lc

If you prefer using a locally compiled installation of the bundled sources,
refer to :ref:`building-a-local-library` and then run:

.. code-block:: bash

    $ cc -o secretstream_test_vector secretstream_test_vector.c \
      ${SODIUMINCL} ${SODIUMLIB} -lsodium -lc

Vector generation
"""""""""""""""""

.. code-block:: bash

    $ ./secretstream_test_vector -h
    Usage: secretstream_test_vector [-c num_chunks] [-r]

When called, the program will output a JSON dictionary containing
``key``, ``header``, and ``chunks``. The ``chunks`` is a list of individual
messages passed to ``crypto_secretstream_xchacha20poly1305_push`` containing
``tag``, ``message``, ``ad`` and ``ciphertext`` keys.

Source code for the vector checker utility
""""""""""""""""""""""""""""""""""""""""""

The source code for ``secretstream_test_vector`` is available inside
the ``docs/vectors/c-source`` directory of PyNaCl distribution
and can also be directly downloaded from
:download:`secretstream_test_vector.c <./c-source/secretstream_test_vector.c>`.

..
    put the and... sentence under a ..only:: builder_html
    when readthedocs begins to correctly support the directive

.. literalinclude:: c-source/secretstream_test_vector.c
    :language: c
    :caption: secretstream_test_vector.c
