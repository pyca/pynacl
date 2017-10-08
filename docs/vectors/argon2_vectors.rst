Argon2 constructs reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since libsodium implements a different API for argon2 contructs
than the one exposed by the reference implementation available at
`The password hash Argon2... <https://github.com/P-H-C/phc-winner-argon2/>`,
the ``kats`` data provided along to the reference implementation sources
cannot be directly used as test vectors in PyNaCl tests.

Therefore, we are using a python driver for the command line
``argon2``, which can be built following the instruction in the
reference implementation sources.


Vector generation
"""""""""""""""""

The ``argondriver.py`` requires setting, via the command line option
``-x``, the path to the argon2 executable; and as a default generates
hex-encoded raw hash data on standard output.

Setting the ``-e`` option on the command line allows generating
modular crypt formatted hashes.

The other command line options influence the minimum and maximum sizes
of generated parameters as shown in the driver's command line help,
which is printed by inserting the ``-h`` option in the command line.

To generate vector data files in ``tests/data``, the argondriver.py
have been called to generate password hashes with parameters compatible
with ``libsodium``'s implementation; in particular, the minimum operations
count must be 3 for ``argon2i`` and 1 for ``argon2id``, and the salt
length must be 16 for raw hashes, and can vary for modular crypt formatted
hashes.

The full command lines used in generating the vactors are:

for raw argon2i
    .. code-block:: bash

        python3 docs/vectors/python/argondriver.py \
                     -x ~/phc-winner-argon2/argon2 \
                     -c argon2i \
                     -s 16 -S 16 -p 8 -P 16 -m 14 -M 18 \
                     -l 18 -L 32 -t 3 -T 5 -n 10 \
                     -w  tests/data/raw_argon2id_hashes.json

for raw argon2id
    .. code-block:: bash

        python3 docs/vectors/python/argondriver.py \
                     -x ~/phc-winner-argon2/argon2 \
                     -c argon2id \
                     -s 16 -S 16 -p 8 -P 16 -m 14 -M 18 \
                     -l 18 -L 32 -t 1 -T 5 -n 10 \
                     -w  tests/data/raw_argon2id_hashes.json

for modular crypt argon2i
    .. code-block:: bash

        python3 docs/vectors/python/argondriver.py \
                     -x ~/phc-winner-argon2/argon2 \
                     -c argon2i -e \
                     -s 8 -S 16 -p 8 -P 16 -m 14 -M 18 \
                     -l 18 -L 32 -t 3 -T 5  -n 10 \
                     -w  tests/data/modular_crypt_argon2id_hashes.json

for modular crypt argon2id
    .. code-block:: bash

        python3 docs/vectors/python/argondriver.py \
                     -x ~/phc-winner-argon2/argon2 \
                     -c argon2id -e \
                     -s 8 -S 16 -p 8 -P 16 -m 14 -M 18 \
                     -l 18 -L 32 -t 1 -T 5  -n 10 \
                     -w  tests/data/modular_crypt_argon2id_hashes.json


Code for the vector generator driver
""""""""""""""""""""""""""""""""""""

The code for ``argondriver.py`` is available inside
the ``docs/vectors/python`` directory of PyNaCl distribution
and can also be directly downloaded from
:download:`argondriver.py <./python/argondriver.py>`.

..
    put the and... sentence under a ..only:: builder_html
    when readthedocs begins to correctly support the directive

.. literalinclude:: python/argondriver.py
    :language: python
    :caption: argondriver.py
