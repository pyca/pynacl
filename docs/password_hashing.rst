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
``libsodium`` since version 1.0.15, and therefore by ``PyNaCl`` since version
1.2 is ``argon2id``.

If you think in your use-case the risk of potential timing-attacks stemming
from data-dependency is greater than the potential time/memory trade-offs
stemming out of data-independency, you should prefer ``argon2i`` to
``argon2id`` or ``scrypt``

Hashers and parameters
----------------------

PyNaCl exposes the functions and the associated parameters needed
to exploit the password hashing constructions in a uniform way
in the modules :py:mod:`~nacl.pwhash.argon2id`,
:py:mod:`~nacl.pwhash.argon2i` and :py:mod:`~nacl.pwhash.scrypt`,
therefore, if you need to change your choice of construction, you simply
need to replace one module name with another in the example below.

Further, if you just want to use a default choosen construction, you can
directly call :py:func:`nacl.pwhash.str` or :py:func:`nacl.pwhash.kdf`
to use the preferred construct in modular crypt password hashing
or key derivation mode.

Password storage and verification
---------------------------------

All implementations of the modular crypt hasher `str` function
internally generate a random salt, and return a hash encoded
in ascii modular crypt format, which can be stored in a shadow-like file

.. doctest::
    :pyversion: >= 3.4

    >>> import nacl.pwhash
    >>> password = b'my password'
    >>> for i in range(4):
    ...     print(nacl.pwhash.str(password))
    ...
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    >>>
    >>> # if needed, each hasher is exposed
    ... # in just the same way:
    ... for i in range(4):
    ...     print(nacl.pwhash.scrypt.str(password))
    ...
    b'$7$C6..../...'
    b'$7$C6..../...'
    b'$7$C6..../...'
    b'$7$C6..../...'
    >>>
    >>> for i in range(4):
    ...     print(nacl.pwhash.argon2i.str(password))
    ...
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    b'$argon2i$v=19$m=32768,t=4,p=1$...'
    >>>
    >>> # and
    ...
    >>> for i in range(4):
    ...     print(nacl.pwhash.argon2id.str(password))
    ...
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    b'$argon2id$v=19$m=65536,t=2,p=1$...'
    >>>


To verify a user-proposed password, the :py:func:`~nacl.pwhash.verify`
function checks the stored hash prefix, and dispatches verification to
the correct checker, which in turn extracts the used salt, memory
and operation count parameters from the modular format string
and checks the compliance of the proposed password with the stored hash

.. doctest::
    :pyversion: >= 3.4

    >>> import nacl.pwhash
    >>> hashed = (b'$7$C6..../....qv5tF9KG2WbuMeUOa0TCoqwLHQ8s0TjQdSagne'
    ...           b'9NvU0$3d218uChMvdvN6EwSvKHMASkZIG51XPIsZQDcktKyN7'
    ...           )
    >>> correct = b'my password'
    >>> wrong = b'My password'
    >>> # while the result will be True on password match,
    ... # on mismatch an exception will be raised
    ... res = nacl.pwhash.verify(hashed, correct)
    >>> print(res)
    True
    >>>
    >>> res2 = nacl.pwhash.verify_scryptsalsa208sha256(hashed, wrong)
    Traceback (most recent call last):
        ...
    nacl.exceptions.InvalidkeyError: Wrong password
    >>> # the verify function raises an exception
    ... # also when it is run against a password hash
    ... # starting with a prefix it doesn't know
    ... wrong_hash = (b'$?$C6..../....qv5tF9KG2WbuMeUOa0TCoqwLHQ8s0TjQdSagne'
    ...               b'9NvU0$3d218uChMvdvN6EwSvKHMASkZIG51XPIsZQDcktKyN7'
    ... )
    >>> res = nacl.pwhash.verify(wrong_hash, correct)
    Traceback (most recent call last):
        ...
    nacl.exceptions.CryptPrefixError: given password_hash is not in a supported format


Key derivation
--------------

Alice needs to send a secret message to Bob, using a shared
password to protect the content. She generates a random salt,
combines it with the password using one of the `kdf` functions
and sends the message along with the salt and key derivation
parameters.

.. testcode::

    from nacl import pwhash, secret, utils


    password = b'password shared between Alice and Bob'
    message = b"This is a message for Bob's eyes only"

    kdf = pwhash.argon2i.kdf
    salt = utils.random(pwhash.argon2i.SALTBYTES)
    ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = pwhash.argon2i.MEMLIMIT_SENSITIVE

    # or, if there is a need to use scrypt:
    # kdf = pwhash.scrypt.kdf
    # salt = utils.random(pwhash.scrypt.SALTBYTES)
    # ops = pwhash.scrypt.OPSLIMIT_SENSITIVE
    # mem = pwhash.scrypt.MEMLIMIT_SENSITIVE

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
    print(received.decode('utf-8'))

.. testoutput::

   This is a message for Bob's eyes only


if Eve manages to get the encrypted message, and tries to decrypt it
with a incorrect password, even if she does know all of the key
derivation parameters, she would derive a different key. Therefore
the decryption would fail and an exception would be raised

.. doctest::
    :pyversion: >= 3.4

    >>> # ops, mem and salt are the same used by Alice
    ...
    >>>
    >>> guessed_pw = b'I think Alice shared this password with Bob'
    >>>
    >>> Eves_key = pwhash.argon2i.kdf(secret.SecretBox.KEY_SIZE,
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

Module level constants for operation and memory cost tweaking
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To help in selecting the correct values for the tweaking parameters for
the used construction, all the implementation modules provide suggested values
for the `opslimit` and `memlimit` parameters with the names:

    * `OPSLIMIT_INTERACTIVE`
    * `MEMLIMIT_INTERACTIVE`
    * `OPSLIMIT_SENSITIVE`
    * `MEMLIMIT_SENSITIVE`
    * `OPSLIMIT_MODERATE`
    * `MEMLIMIT_MODERATE`

and the corresponding minimum and maximum allowed values in:

    * `OPSLIMIT_MIN`
    * `MEMLIMIT_MIN`
    * `OPSLIMIT_MAX`
    * `MEMLIMIT_MAX`

Further, for each construction, pwhash modules expose the following
constants:

    * `STRPREFIX`
    * `PWHASH_SIZE`
    * `SALTBYTES`
    * `BYTES_MIN`
    * `BYTES_MAX`

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
