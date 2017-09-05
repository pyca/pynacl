SealedBox reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since libsodium's tests do not provide reference data for the SealedBox
construction, the implementation is verified with a ``sealbox_test_vectors``
utility program that produces and checks custom test vectors
by making specific calls to libsodium API.

To build the ``sealbox_test_vectors`` you need a ``C`` language compiler,
a prebuilt libsodium library more recent than version 1.0.3 and the
corresponding include headers.

In a UNIX-like programming environment you should then execute:

.. code-block:: bash

    $ cc -o sealbox_test_vectors sealbox_test_vectors.c -lsodium -lc

If you prefer using a locally compiled installation of the bundled sources,
refer to :ref:`building-a-local-library` and then run:

.. code-block:: bash

    $ cc -o sealbox_test_vectors sealbox_test_vectors.c \
      ${SODIUMINCL} ${SODIUMLIB} -lsodium -lc

Vector generation
"""""""""""""""""

When called with one or more command line arguments, ``sealbox_test_vectors``
will generate the number of hex-encoded vectors requested as first argument,
with the optional second and third arguments influencing the length of the
randomly generated messages:

.. code-block:: bash

    $ ./sealbox_test_vectors 1
    XXXX...        XXXX...        <len>:XXXX...        <len>:XXXX...

The second argument, if present, sets both a minimum and a maximum length
on generated messages, overriding the default 128 bytes values
respectively with the supplied value and with twice the supplied value.

The third argument, if present, sets the maximum length of generated
messages.

Vector test
"""""""""""

When called without command line arguments, ``sealbox_test_vectors``
will parse and hex-decode the lines given as standard input and
check if decoding the encrypted message will return the original
message. A "OK"/"FAIL" tag will be appended to the input line to
signify success/failure of the test.

To check correct "round-trip" behavior, you can run ``sealbox_test_vectors``
as a test vector generator against itself:

.. code-block:: bash

    $ ./sealbox_test_vectors 1 | ./sealbox_test_vectors
    XXXX...	XXXX... <len>:XXXX...	<len>:XXXX...	OK

If you want to check the vectors distributed with PyNaCl's sources,
after setting the environment variable ``PYNACL_BASE`` to the directory
where the unpacked source for PyNaCl has been extracted/cloned,
you could run:

.. code-block:: bash

    $ ./sealbox_test_vectors < ${PYNACL_BASE}/tests/data/sealed_box_ref.txt
    77076d ... 8c86  OK


Source code for the vector checker utility
""""""""""""""""""""""""""""""""""""""""""

The source code for ``sealbox_test_vectors`` is available inside
the ``docs/vectors/c-source`` directory of PyNaCl distribution
and can also be directly downloaded from
:download:`sealbox_test_vectors.c <./c-source/sealbox_test_vectors.c>`.

..
    put the and... sentence under a ..only:: builder_html
    when readthedocs begins to correctly support the directive

.. literalinclude:: c-source/sealbox_test_vectors.c
    :language: c
    :caption: sealbox_test_vectors.c
