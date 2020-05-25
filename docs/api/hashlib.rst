nacl.hashlib
============

.. currentmodule:: nacl.hashlib

The :py:mod:`nacl.hashlib` module exposes directly usable implementations
of raw constructs which libsodium exposes with simplified APIs, like the
ones in :py:mod:`nacl.hash` and in :py:mod:`nacl.pwhash`.

The :py:class:`~.blake2b` and :py:func:`~.scrypt` implementations
are as API compatible as possible with the corresponding ones added
to cpython standard library's hashlib module in cpython's version 3.6.


.. class:: blake2b(data=b'', digest_size=BYTES, key=b'', salt=b'', person=b'')

    Returns an hash object which exposes an API mostly compatible
    to python3.6's hashlib.blake2b (the only difference being missing
    support for tree hashing parameters in the contructor)

    The methods :py:func:`update`, :py:func:`copy`,
    :func:`digest` and :func:`hexdigest` have the same semantics
    as described in hashlib documentation.

    Each instance exposes the :py:attr:`digest_size`, :py:attr:`block_size`
    :py:attr:`name` properties as required by hashlib API.

    .. attribute:: MAX_DIGEST_SIZE

        the maximum allowed value of the requested digest_size

    .. attribute:: MAX_KEY_SIZE

        the maximum allowed size of the password parameter

    .. attribute:: PERSON_SIZE

        the maximimum size of the personalization

    .. attribute:: SALT_SIZE

        the maximimum size of the salt


.. function:: scrypt(password, salt='', n=2**20, r=8, p=1,\
                     maxmem=2**25, dklen=64)

    Derive a raw cryptographic key using the scrypt KDF.

    :param password: the input password
    :type password: bytes
    :param salt: a crypographically-strong random salt
    :type salt: bytes
    :param n: CPU/Memory cost factor
    :type n: int
    :param r: block size multiplier: the used block size will be 128 * r
    :type r: int
    :param p: requested parallelism: the number of indipendently running
              scrypt constructs which will contribute to the final key
              generation
    :type p: int
    :param maxmem: maximum memory the whole scrypt construct will be
                   entitled to use
    :type maxmem: int
    :param dklen: length of the derived key
    :type dklen: int
    :return: a buffer dklen bytes long containing the derived key
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.

    Implements the same signature as the ``hashlib.scrypt`` implemented
    in cpython version 3.6

    The recommended values for n, r, p in 2012 were n = 2**14, r = 8, p = 1;
    as of 2016, libsodium suggests using n = 2**14, r = 8, p = 1
    in a "interactive" setting and n = 2**20, r = 8, p = 1
    in a "sensitive" setting.

    The total memory usage will respectively be a little greater than 16MB
    in the "interactive" setting, and a little greater than 1GB in the
    "sensitive" setting.
