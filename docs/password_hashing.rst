.. _password-hashing:

Password hashing
================

.. currentmodule:: nacl.pwhash

Password hashing and password based key derivation mechanisms in
actual use are all based on the idea of iterating a hash function
many times on a combination of the password and a random ``salt``,
which is stored along with the hash, and allows verifying a proposed
password while avoiding clear-text storage.

The latest developments in password hashing have been *memory-hard*
and *tunable* mechanisms, pioneered by ``scrypt`` [SD2012]_,
and followed-on by the schemes submitted to the **Password Hashing
Competition** [PHC]_.

The :py:mod:`nacl.pwhash` module exposes both the **PHC** recommended
partially data dependent ``argon2id`` and the data independent ``argon2i``
mechanisms alongside to the ``scrypt`` one.

In the case of password storage, it's usually suggested to give preference to
data dependent mechanisms, therefore the default mechanism suggested by
``libsodium`` since version 1.0.15 is ``argon2id``.

If you think in your use-case the risk of potential timing-attacks stemming
from data-dependency is greater than the potential time/memory trade-offs
stemming out of data-independency, you should prefer ``argon2i`` to
``argon2id`` or ``scrypt``


Password storage and verification
---------------------------------

Both :py:func:`~nacl.pwhash.argon2i_str` and
:py:func:`~nacl.pwhash.scryptsalsa208sha256_str`
internally generate a random salt, and return a hash encoded
in ascii modular crypt format, which can be stored in a shadow-like file::

    >>> import nacl.pwhash
    >>> password = b'my password'
    >>> for i in range(4):
    ...     print(nacl.pwhash.argon2i_str(password))
    ...
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    >>> for i in range(4):
    ...     print(nacl.pwhash.scryptsalsa208sha256_str(password))
    ...
    b'$7$C6..../....p9h...'
    b'$7$C6..../....pVs...'
    b'$7$C6..../....qW2...'
    b'$7$C6..../....bxH...'

To verify a user-proposed password, the :py:func:`~nacl.pwhash.verify_argon2i`
and :py:func:`~nacl.pwhash.verify_scryptsalsa208sha256` function
extract the used salt, memory and operation count parameters
from the modular format string and check the compliance of the
proposed password with the stored hash::

    >>> import nacl.pwhash
    >>> hashed = (b'$7$C6..../....qv5tF9KG2WbuMeUOa0TCoqwLHQ8s0TjQdSagne'
    ...           b'9NvU0$3d218uChMvdvN6EwSvKHMASkZIG51XPIsZQDcktKyN7'
    ...           )
    >>> correct = b'my password'
    >>> wrong = b'My password'
    >>> # while the result will be True on password match,
    ... # on mismatch an exception will be raised
    ... res = nacl.pwhash.verify_scryptsalsa208sha256(hashed, correct)
    >>> print(res)
    True
    >>>
    >>> res2 = nacl.pwhash.verify_scryptsalsa208sha256(hashed, wrong)
    Traceback (most recent call last):
        ...
    nacl.exceptions.InvalidkeyError: Wrong password
    >>>


Future-proofing your password verification routine
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A very nice aspect of modular crypt format is the presence of
the ``$identifier$`` prefix, which can be used to dispatch
the correct hash verifier.

This could help continued support for an hash format, even
after choosing a different one as a default storage format
for new passwords.

To prepare yourself in exploiting this feature, you should simply
remember to test the serialized password hash identifier before
verifying a proposed password:

.. code-block:: python

    from nacl.exceptions import ValueError
    from nacl.pwhash import (verify_argon2i, verify_scryptsalsa208sha256)
    def check_password(serialized, proposed):
        if serialized.startswith(b'$7$'):
            res = verify_scryptsalsa208sha256(serialized, proposed)
        if serialized.startswith(b'$argon2i$')
                or serialized.startswith(b'$argon2id$'):
            res = verify_argon2(serialized, proposed)
        else:
            raise ValueError('Unknown serialization format')
        return res

By doing so, if a future version of PyNaCl would get released
with support for a new password hash mechanism, you'll be able
to just insert another ``elif serialized.startswith(b'$newhash$):``
clause to your password checker to begin supporting ``newhash``
without harming the previously hashed passwords.


Key derivation
--------------

Alice needs to send a secret message to Bob, using a shared
password to protect the content. She generates a random salt,
combines it with the password using either
:py:func:`~nacl.pwhash.kdf_argon2i` or
:py:func:`~nacl.pwhash.kdf_scryptsalsa208sha256` and sends
the message along with the salt and key derivation parameters.

.. code-block:: python

    from nacl import pwhash, secret, utils


    password = b'password shared between Alice and Bob'
    message = b"This is a message for Bob's eyes only"

    kdf = pwhash.kdf_argon2i
    salt = utils.random(pwhash.ARGON2I.SALTBYTES)
    ops = pwhash.ARGON2I.OPSLIMIT_SENSITIVE
    mem = pwhash.ARGON2I.MEMLIMIT_SENSITIVE

    # or, if there is a need to use scrypt:
    # kdf = pwhash.kdf_scryptsalsa208sha256
    # salt = utils.random(pwhash.SCRYPT.SALTBYTES)
    # ops = pwhash.SCRYPT.OPSLIMIT_SENSITIVE
    # mem = pwhash.SCRYPT.MEMLIMIT_SENSITIVE

    Alices_key = kdf(secret.SecretBox.KEY_SIZE, password, salt,
                     opslimit=ops, memlimit=mem)
    Alices_box = secret.SecretBox(Alices_key)
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)

    encrypted = Alices_box.encrypt(message, nonce)

    # now Alice must send to Bob both the encrypted message
    # and the KDF parameters: salt, opslimit and memlimit;
    # using the same kdf mechanism, parameters **and password**
    # Bob is able to derive the correct key to decrypt the message


    Bobs_key = kdf(secret.SecretBox.KEY_SIZE, password, salt,
                   opslimit=ops, memlimit=mem)
    Bobs_box = secret.SecretBox(Bobs_key)
    received = Bobs_box.decrypt(encrypted)
    print(received)

if Eve manages to get the encrypted message, and tries to decrypt it
with a incorrect password, even if she does know all of the key
derivation parameters, she would derive a different key. Therefore
the decryption would fail and an exception would be raised::

    >>> from nacl import pwhash, secret, utils
    >>>
    >>> ops = pwhash.ARGON2I.OPSLIMIT_SENSITIVE
    >>> mem = pwhash.ARGON2I.MEMLIMIT_SENSITIVE
    >>>
    >>> salt = utils.random(pwhash.ARGON2I.SALTBYTES)
    >>>
    >>> guessed_pw = b'I think Alice shared this password with Bob'
    >>>
    >>> Eves_key = pwhash.kdf_argon2i(secret.SecretBox.KEY_SIZE,
    ...                               guessed_pw, salt,
    ...                               opslimit=ops, memlimit=mem)
    >>> Eves_box = secret.SecretBox(Eves_key)
    >>> intercepted = Eves_box.decrypt(encrypted)
    Traceback (most recent call last):
        ...
    nacl.exceptions.CryptoError: Decryption failed. Ciphertext failed ...

Contrary to the hashed password storage case where a serialization
format is well-defined, in the raw key derivation case the library
user must take care to store (and retrieve) both a reference to the kdf
used to derive the secret key and all the derivation parameters.
These parameters are needed to later generate the same secret key
from the password.

Constants for construct operation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To help in selecting the correct values for the tweaking parameters for both
the **scrypt** and the **argon2** constructions, the :py:mod:`nacl.pwhash`
provides suggested values for the `opslimit` and `memlimit` parameters, which
are belived to be valid as of CPU/ASIC speeds current in year 2017.

The constants are grouped inside classes named after the mechanism, which
also provide constants describing limits for the input parameters values
or sizes.

for ``scrypt``:

  .. py:class:: SCRYPT

     A class providing constants for the :py:func:`nacl.pwhash.scrypt`
     construction

    .. py:attribute:: nacl.pwhash.SCRYPT.SALTBYTES

    the fixed length of the salt byte sequence which must be provided
    for :py:func:`nacl.pwhash.scrypt` operation

    .. py:attribute:: nacl.pwhash.SCRYPT.PWHASH_SIZE

    the fixed length of the modular crypt formatted scrypt hash

    .. py:attribute:: nacl.pwhash.SCRYPT.OPSLIMIT_INTERACTIVE
                      nacl.pwhash.SCRYPT.MEMLIMIT_INTERACTIVE

    the recommended limits in the interactive authentication case


    .. py:attribute:: nacl.pwhash.SCRYPT.OPSLIMIT_SENSITIVE
                      nacl.pwhash.SCRYPT.MEMLIMIT_SENSITIVE

    the recommended limits in the sensitive key generation case

for argon2i:

  .. py:class::  ARGON2I

    .. py:attribute:: nacl.pwhash.ARGON2I.OPSLIMIT_INTERACTIVE
                      nacl.pwhash.ARGON2I.MEMLIMIT_INTERACTIVE

    the recommended limits in the interactive authentication case

    .. py:attribute:: nacl.pwhash.ARGON2I.OPSLIMIT_SENSITIVE
                      nacl.pwhash.ARGON2I.MEMLIMIT_SENSITIVE

    the recommended limits in the sensitive key generation case

    .. py:attribute:: nacl.pwhash.ARGON2I.OPSLIMIT_MODERATE
                      nacl.pwhash.ARGON2I.MEMLIMIT_MODERATE

    .. py:attribute:: nacl.pwhash.ARGON2I.PWHASH_SIZE
    .. py:attribute:: nacl.pwhash.ARGON2I.SALTBYTES
    .. py:attribute:: nacl.pwhash.ARGON2I.BYTES_MAX
                      nacl.pwhash.ARGON2I.BYTES_MIN
    .. py:attribute:: nacl.pwhash.ARGON2I.MEMLIMIT_MAX
                      nacl.pwhash.ARGON2I.MEMLIMIT_MIN
    .. py:attribute:: nacl.pwhash.ARGON2I.OPSLIMIT_MAX
                      nacl.pwhash.ARGON2I.OPSLIMIT_MIN
    .. py:attribute:: nacl.pwhash.ARGON2I.ALG

for argon2id:

  .. py:class::  ARGON2ID

    .. py:attribute:: nacl.pwhash.ARGON2ID.OPSLIMIT_INTERACTIVE
                      nacl.pwhash.ARGON2ID.MEMLIMIT_INTERACTIVE

    the recommended limits in the interactive authentication case

    .. py:attribute:: nacl.pwhash.ARGON2ID.OPSLIMIT_SENSITIVE
                      nacl.pwhash.ARGON2ID.MEMLIMIT_SENSITIVE

    the recommended limits in the sensitive key generation case

    .. py:attribute:: nacl.pwhash.ARGON2ID.OPSLIMIT_MODERATE
                      nacl.pwhash.ARGON2ID.MEMLIMIT_MODERATE

    .. py:attribute:: nacl.pwhash.ARGON2ID.PWHASH_SIZE
    .. py:attribute:: nacl.pwhash.ARGON2ID.SALTBYTES
    .. py:attribute:: nacl.pwhash.ARGON2ID.BYTES_MAX
                      nacl.pwhash.ARGON2ID.BYTES_MIN
    .. py:attribute:: nacl.pwhash.ARGON2ID.MEMLIMIT_MAX
                      nacl.pwhash.ARGON2ID.MEMLIMIT_MIN
    .. py:attribute:: nacl.pwhash.ARGON2ID.OPSLIMIT_MAX
                      nacl.pwhash.ARGON2ID.OPSLIMIT_MIN
    .. py:attribute:: nacl.pwhash.ARGON2ID.ALG

In general, the _INTERACTIVE values are recommended in the case of hashes
stored for interactive password checking, and lead to a sub-second password
verification time, with a memory consumption in the tens of megabytes range,
while the _SENSITIVE values are meant to store hashes for password protecting
sensitive data, and lead to hashing times exceeding one second, with memory
consumption in the hundred of megabytes range. The _MODERATE values, suggested
for ``argon2`` mechanisms are meant to run the construct at a runtime and
memory cost intermediate between _INTERACTIVE and _SENSITIVE.


.. [SD2012] A nice overview of password hashing history is available
   in Solar Designer's presentation
   `Password security: past, present, future
   <http://www.openwall.com/presentations/Passwords12-The-Future-Of-Hashing/>`_

.. [PHC] The Argon2 recommendation is prominently shown in the
   `Password Hashing Competition <https://password-hashing.net/>`_
   site, along to the special recognition shortlist and the original
   call for submissions.
