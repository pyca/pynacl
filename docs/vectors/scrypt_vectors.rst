scrypt reference vectors
^^^^^^^^^^^^^^^^^^^^^^^^

Libsodium exposes both a simplified scrypt KDF/password storage API
which parametrizes the CPU and memory load in term of a opslimit parameter
and a memlimit one, and a "traditional" low-level API parametrized in terms
of a (N, r, p) triple.

While we used the vectors from `RFC 7914`_ to test the traditional API,
the simplified API is only implemented by libsodium, and therefore we just
added a KDF generation check using the ascii encoded passphrase
"The quick brown fox jumps over the lazy dog.", and verified the results
were the same we could get from the version of hashlib.scrypt, as provided
in python version 3.6 stdlib.

.. code-block:: python

    >>> import hashlib
    >>> import nacl
    >>> import nacl.bindings
    >>> import nacl.pwhash.scrypt
    >>> pick_scrypt_params = nacl.bindings.nacl_bindings_pick_scrypt_params
    >>> nacl.pwhash.scrypt.kdf(32,
    ...                        b'The quick brown fox jumps over the lazy dog.',
    ...                        b"ef537f25c895bfa782526529a9b63d97",
    ...                        opslimit=20000, memlimit=100 * (2 ** 20))
    b'\x10e>\xc8A8\x11\xde\x07\xf1\x0f\x98EG\xe6}V]\xd4yN\xae\xd3P\x87yP\x1b\xc7+n*'
    >>> n_log2, r, p = pick_scrypt_params(20000, 100 * (2 ** 20))
    >>> print(2 ** n_log2, r, p)
    1024 8 1
    >>> hashlib.scrypt(b'The quick brown fox jumps over the lazy dog.',
    ...                salt=b"ef537f25c895bfa782526529a9b63d97",
    ...                n=1024, r=8, p=1, dklen=32)
    b'\x10e>\xc8A8\x11\xde\x07\xf1\x0f\x98EG\xe6}V]\xd4yN\xae\xd3P\x87yP\x1b\xc7+n*'

.. _RFC 7914: https://tools.ietf.org/html/rfc7914
