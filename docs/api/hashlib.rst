nacl.hashlib
============

.. currentmodule:: nacl.hashlib

The :py:mod:`nacl.hashlib` module exposes directly usable implementations
of raw constructs which libsodium exposes with simplified APIs, like the
ones in :py:mod:`nacl.hash` and in :py:mod:`nacl.pwhash`.

The :py:class:`~.blake2b` and :py:func:`~.scrypt` implementations
are as API compatible as possible with the corresponding ones added
to cpython standard library's hashlib module in cpython's version 3.6.

.. automodule:: nacl.hashlib
   :members:
