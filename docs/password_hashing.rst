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
mechanisms, pioneered by the ``scrypt`` mechanism [SD2012]_, which
is implemented by functions exposed in :py:mod:`nacl.pwhash`.


Scrypt usage
------------

Password storage and verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :py:func:`~nacl.pwhash.scryptsalsa208sha256_str` internally
generates a random salt, and returns a scrypt hash already encoded
in ascii modular crypt format, which can be stored in a shadow-like file::

    >>> import nacl.pwhash
    >>> password = b'my password'
    >>> for i in range(4):
    ...     print(nacl.pwhash.scryptsalsa208sha256_str(password))
    ...
    b'$7$C6..../....p9h...'
    b'$7$C6..../....pVs...'
    b'$7$C6..../....qW2...'
    b'$7$C6..../....bxH...'


To verify a user-proposed password, the
:py:func:`~nacl.pwhash.scryptsalsa208sha256_verify` function
extracts the used salt and scrypt memory and operation count parameters
from the modular format string and checks the compliance of the
proposed password with the stored hash::

    >>> import nacl.pwhash
    >>> hashed = (b'$7$C6..../....qv5tF9KG2WbuMeUOa0TCoqwLHQ8s0TjQdSagne'
    ...           b'9NvU0$3d218uChMvdvN6EwSvKHMASkZIG51XPIsZQDcktKyN7'
    ...           )
    >>> correct = b'my password'
    >>> wrong = b'My password'
    >>> # the result will be True on password match
    ... # on mismatch
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
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A very nice aspect of modular crypt format is the ``$identifier$``
prefix which can be used to dispatch the correct hash verifier.
This could help continued support for an hash format, even
after choosing a different one as a default storage format
for new passwords.

To prepare yourself in exploiting this feature, you should simply
remember to test the serialized password hash identifier before
verifying a proposed password:

.. code-block:: python

    from nacl.pwhash import verify_scryptsalsa208sha256
    def check_password(serialized, proposed):
        if serialized.startswith(b'$7$'):
            res = verify_scryptsalsa208sha256(serialized, proposed)
        return res

By doing so, if a future version of PyNaCl would get released
with support for a new ``verify_safest_password_hash`` mechanism,
you'll just have to import the new verifier and add an ``elif``
clause to your check_password function:

.. code-block:: python

    from nacl.pwhash import (verify_scryptsalsa208sha256,
                             verify_safest_password_hash,
                             )
    def check_password(serialized, proposed):
        if serialized.startswith(b'$7$'):
            res = verify_scryptsalsa208sha256(serialized, proposed)
        elif serialized.startswith(b'$safest_hash_identifier$'):
            res = verify_safest_password_hash(serialized, proposed)
        return res


Key derivation
~~~~~~~~~~~~~~

Alice needs to send a secret message to Bob, using a shared
password to protect the content. She generates a random salt,
combines it with the password using
:py:func:`~nacl.pwhash.kdf_scryptsalsa208sha256` and sends
the message along with the salt and key derivation parameters.

.. code-block:: python

    from nacl import pwhash, secret, utils

    ops = pwhash.SCRYPT_OPSLIMIT_SENSITIVE
    mem = pwhash.SCRYPT_MEMLIMIT_SENSITIVE

    salt = utils.random(pwhash.SCRYPT_SALTBYTES)

    password = b'password shared between Alice and Bob'
    message = b"This is a message for Bob's eyes only"

    Alices_key = pwhash.kdf_scryptsalsa208sha256(secret.SecretBox.KEY_SIZE,
                                                 password, salt,
                                                 opslimit=ops, memlimit=mem)
    Alices_box = secret.SecretBox(Alices_key)
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)

    encrypted = Alices_box.encrypt(message, nonce)

    # now Alice must send to Bob both the encrypted message
    # and the KDF parameters: salt, opslimit and memlimit;
    # using the same parameters **and password**
    # Bob is able to derive the correct key to decrypt the message


    Bobs_key = pwhash.kdf_scryptsalsa208sha256(secret.SecretBox.KEY_SIZE,
                                               password, salt,
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
    >>> ops = pwhash.SCRYPT_OPSLIMIT_SENSITIVE
    >>> mem = pwhash.SCRYPT_MEMLIMIT_SENSITIVE
    >>>
    >>> salt = utils.random(pwhash.SCRYPT_SALTBYTES)
    >>>
    >>> guessed_pw = b'I think Alice shared this password with Bob'
    >>>
    >>> Eves_key = pwhash.kdf_scryptsalsa208sha256(secret.SecretBox.KEY_SIZE,
    ...                                            guessed_pw, salt,
    ...                                            opslimit=ops, memlimit=mem)
    >>> Eves_box = secret.SecretBox(Eves_key)
    >>> intercepted = Eves_box.decrypt(encrypted)
    Traceback (most recent call last):
        ...
    nacl.exceptions.CryptoError: Decryption failed. Ciphertext failed ...

.. [SD2012] A nice overview of password hashing history is available
   in Solar Designer's presentation
   `Password security: past, present, future
   <http://www.openwall.com/presentations/Passwords12-The-Future-Of-Hashing/>`_
