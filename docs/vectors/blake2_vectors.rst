Blake2b reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^^

While the blake2b construction is a keyed hash and variable output
length algorithm which can optionally be initialized with limited
size salt and personalization parameters, the `known answers`_ json
file in the reference `blake2`_ sources just provides vectors for
default length hash with empty salt and personalization.

To fill this test gap, we used both the pyblake and the libsodium implemented
generators provided by `crypto test vectors`_ for the `blake2b` mechanism
to generate twenty vectors in each of
`test/data/crypto-test-vectors-blake2-nosalt-nopersonalization.txt`
and
`test/data/crypto-test-vectors-blake2-salt-personalization.txt`

Vector generation
"""""""""""""""""

After cloning the github project with

.. code-block:: bash

    $ git clone https://github.com/jedisct1/crypto-test-vectors.git

the needed source files will be available in the `nosalt-nopersonalization`
and `salt-personalization` subdirectories of
`crypto-test-vectors/crypto/hash/blake2/blake2b/`.

To run the python generators, after ensuring the needed `pyblake2`_ module
is available in the python environment, it will be enough to run the following
commands at the shell prompt:

.. code-block:: bash

    $ BLAKE="${PWD}/crypto-test-vectors/crypto/hash/blake2/blake2b"
    $ NOPERS="${BLAKE}/nosalt-nopersonalization/generators"
    $ PERSON="${BLAKE}/salt-personalization/generators"
    $ python "${NOPERS}/pyblake2/generator.py" 10 > py_nopers_vectors
    $ python "${PERSON}/pyblake2/generator.py" 10 > py_pers_vectors

On linux systems, after installing the required `libsodium` development
package, the C-language generators, can get built by running:

.. code-block:: bash

    $ BLAKE="${PWD}/crypto-test-vectors/crypto/hash/blake2/blake2b"
    $ NOPERS="${BLAKE}/nosalt-nopersonalization/generators"
    $ PERSON="${BLAKE}/salt-personalization/generators"
    $ for i in "${NOPERS}/libsodium" "${PERSON}/libsodium"; do (cd "${i}" && make); done

and then run by executing:

.. code-block:: bash

    $ BLAKE="${PWD}/crypto-test-vectors/crypto/hash/blake2/blake2b"
    $ NOPERS="${BLAKE}/nosalt-nopersonalization/generators"
    $ PERSON="${BLAKE}/salt-personalization/generators"
    $ "${NOPERS}/libsodium/generator" 10 > py_nopers_vectors_c
    $ "${PERSON}/libsodium/generator" 10 > py_pers_vectors_c


.. _blake2: https://github.com/BLAKE2/BLAKE2

.. _known answers:
   https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2-kat.json

.. _crypto test vectors: https://github.com/jedisct1/crypto-test-vectors

.. _pyblake2: https://pythonhosted.org/pyblake2/
