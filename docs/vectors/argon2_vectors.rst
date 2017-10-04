Argon2 constructs reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since libsodium implements a different API for argon2 contructs
than the one exposed by the reference implementation available at
`The password hash Argon2... <https://github.com/P-H-C/phc-winner-argon2/>`,
the ``kats`` data provided along to the reference implementation sources
cannot be directly used as test vectors in PyNaCl tests.

Therefore, we are using a python driver for the command line
``argon2`` executable to generate reference vectors for the bindings.


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
