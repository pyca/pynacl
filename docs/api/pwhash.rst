nacl.pwhash
===========

.. module:: nacl.pwhash

The package pwhash provides implementations of modern *memory-hard*
password hashing construction exposing modules with a uniform API.

Functions exposed at top level
------------------------------

The top level module only provides the functions implementing
ascii encoded hashing and verification using the construction
choosen as preferred by the upstream libsodium library.

.. function:: str(password, \
                  opslimit=OPSLIMIT_INTERACTIVE, \
                  memlimit=MEMLIMIT_INTERACTIVE)

    Returns a password verifier hash, generated with the password hasher
    choosen as a default by libsodium.

    :param password: password used to seed the key derivation procedure;
                     it length must be between
                     :py:const:`PASSWD_MIN` and
                     :py:const:`PASSWD_MAX`
    :type password: bytes
    :param opslimit: the time component (operation count)
                     of the key derivation procedure's computational cost;
                     it must be between
                     :py:const:`OPSLIMIT_MIN` and
                     :py:const:`OPSLIMIT_MAX`
    :type opslimit: int
    :param memlimit: the memory occupation component
                     of the key derivation procedure's computational cost;
                     it must be between
                     :py:const:`MEMLIMIT_MIN` and
                     :py:const:`MEMLIMIT_MAX`
    :type memlimit: int
    :returns: the ascii encoded password hash along with a prefix encoding
              the used hashing construct, the random generated salt and
              the operation and memory limits used to generate the password hash
    :rtype: bytes


    As of PyNaCl version 1.2 this is :py:func:`nacl.pwhash.argon2id.str`.

    .. versionadded:: 1.2


.. function:: verify(password_hash, password)

    This function checks if hashing the proposed password, with
    the same construction and parameters encoded in the password hash
    would generate the same encoded string, thus verifying the
    correct password has been proposed in an authentication attempt.

    .. versionadded:: 1.2

.. rubric:: Module level constants

The top level module defines the constants related to the :py:func:`str`
hashing construct and its corresponding :py:func:`verify` password
verifier.

.. py:data:: PASSWD_MIN
.. py:data:: PASSWD_MAX

    minimum and maximum length of the password to hash

.. py:data:: PWHASH_SIZE

    maximum size of the encoded hash

.. py:data:: OPSLIMIT_MIN
.. py:data:: OPSLIMIT_MAX

    minimum and maximum operation count for the hashing construct

.. py:data:: MEMLIMIT_MIN
.. py:data:: MEMLIMIT_MAX

    minimum and maximum memory occupation for the hashing construct

and the recommended values for the opslimit and memlimit parameters

.. py:data:: MEMLIMIT_INTERACTIVE
.. py:data:: OPSLIMIT_INTERACTIVE

    recommended values for the interactive user authentication password
    check case, leading to a sub-second hashing time

.. py:data:: MEMLIMIT_SENSITIVE
.. py:data:: OPSLIMIT_SENSITIVE

    recommended values for generating a password hash/derived key meant to protect
    sensitive data, leading to a multi-second hashing time

.. py:data:: MEMLIMIT_MODERATE
.. py:data:: OPSLIMIT_MODERATE

    values leading to a hashing time and memory cost intermediate between the
    interactive and the sensitive cases

Per-mechanism password hashing implementation modules
-----------------------------------------------------

Along with the respective :py:func:`str` and :py:func:`verify` functions,
the modules implementing named password hashing constructs expose also
a :py:func:`kdf` function returning a raw pseudo-random bytes sequence
derived from the input parameters

nacl.pwhash.argon2i
-------------------

.. automodule:: nacl.pwhash.argon2i
   :members:

nacl.pwhash.argon2id
--------------------

.. automodule:: nacl.pwhash.argon2id
   :members:

nacl.pwhash.scrypt
-------------------

.. automodule:: nacl.pwhash.scrypt
   :members:
