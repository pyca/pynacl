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
``-x``, the path to the argon2 executable, and the contruct to use
in generating test data, which mush be either ``argon2i`` or ``argon2id``.

and as a default generates
hex-encoded raw hash data.

Using the default settings, the driver generates hex-encoded raw hash
data; setting the ``-e`` option on the command line allows generation
of modular crypt formatted data.

The other command line options influence the minimum and maximum sizes
of generated parameters as shown in the driver's command line help:

.. code-block:: bash

    $ python3 docs/vectors/python/argondriver.py

    usage: argondriver.py [-h] -x EXE [-c CONSTRUCT]
                          [-v VERSION] [-e]
                          [-s MNSALTLEN] [-S MXSALTLEN]
                          [-p MNPWLEN] [-P MXPWLEN]
                          [-l MNDGSTLEN] [-L MXDGSTLEN]
                          [-m MNMEM] [-M MXMEM]
                          [-t MNITERS] [-T MXITERS]
                          [-n N]
                          [-w OUTFILE]

    optional arguments:
      -h, --help            show this help message and exit
      -x EXE, --executable EXE
      -c CONSTRUCT, --construction CONSTRUCT
      -v VERSION, --version VERSION
      -e, --encoded
      -s MNSALTLEN, --min-salt-len MNSALTLEN
      -S MXSALTLEN, --max-salt-len MXSALTLEN
      -p MNPWLEN, --min-password-len MNPWLEN
      -P MXPWLEN, --max-password-len MXPWLEN
      -l MNDGSTLEN, --min-digest-len MNDGSTLEN
      -L MXDGSTLEN, --max-digest-len MXDGSTLEN
      -m MNMEM, --min-memory-exponent MNMEM
      -M MXMEM, --max-memory-exponent MXMEM
      -t MNITERS, --min-time-opscount MNITERS
      -T MXITERS, --max-time-opscount MXITERS
      -n N, --count N
      -w OUTFILE, --output OUTFILE

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
