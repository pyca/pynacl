.. _password-hashing:

Password hashing
================

.. currentmodule:: nacl.pw_hash

An ever important use of cryptographic hashing primitives has been
the password hashing one, starting from the early 1970's years, at
first just to avoid storing clear-text passwords.

To make a long story short [SD2012]_, password hashing and password based key
derivation mechanisms in actual use are all based on the idea of iterating
many times a hash function on a combination of the password and
a random ``salt`` which is stored along with the hash, and allows
verifying a proposed password while avoiding clear-text storage.

The latest developments in password hashing have been mechanisms
pionereed by the ``scrypt`` mechanism, which is implemented by functions
exposed in :py:mod:`nacl.pw_hash`.


Scrypt usage
------------

Password storage and verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :py:func:`~nacl.pw_hash.scryptsalsa208sha256_str` does internally
generate a random salt, and returns a scrypt hash already encoded
in ascii modular crypt format, which can be stored in a shadow-like file::

    >>> import nacl.pw_hash
    >>> password = b'my password'
    >>> for i in range(4):
    ...     print(nacl.pw_hash.scryptsalsa208sha256_str(password))
    ...
    b'$7$C6..../....p9h...'
    b'$7$C6..../....pVs...'
    b'$7$C6..../....qW2...'
    b'$7$C6..../....bxH...'


To verify a user-proposed password, the
:py:func:`~nacl.pw_hash.scryptsalsa208sha256_verify` function
does extract the used salt and scrypt memory and operation count parameters
from the modular format string and checks the compliance of the
proposed password with the stored hash::

    >>> import nacl.pw_hash
    >>> hashed = (b'$7$C6..../....qv5tF9KG2WbuMeUOa0TCoqwLHQ8s0TjQdSagne'
    ...           b'9NvU0$3d218uChMvdvN6EwSvKHMASkZIG51XPIsZQDcktKyN7'
    ...           )
    >>> correct = b'my password'
    >>> wrong = b'My password'
    >>> # the result will be True on password match
    ... # on mismatch
    ... res = nacl.pw_hash.verify_scryptsalsa208sha256(hashed, correct)
    >>> print(res)
    True
    >>>
    >>> res2 = nacl.pw_hash.verify_scryptsalsa208sha256(hashed, wrong)
    Traceback (most recent call last):
        ...
    nacl.exceptions.InvalidkeyError: Wrong password
    >>>


Key derivation
~~~~~~~~~~~~~~

If Alice needs to send a secret message to Bob, using a shared
password to protect the content, she can use a salt, which she
must then send along to the message, to derive a cryptographically
strong key using :py:func:`~nacl.pw_hash.kdf_scryptsalsa208sha256`:

.. code-block:: python

    from nacl import pw_hash, secret, utils

    ops = pw_hash.SCRYPT_OPSLIMIT_SENSITIVE
    mem = pw_hash.SCRYPT_MEMLIMIT_SENSITIVE

    salt = utils.random(pw_hash.SCRYPT_SALTBYTES)

    password = b'password shared between Alice and Bob'
    message = b"This is a message for Bob's eyes only"

    Alices_key = pw_hash.kdf_scryptsalsa208sha256(secret.SecretBox.KEY_SIZE,
                                                  password, salt,
                                                  opslimit=ops, memlimit=mem)
    Alices_box = secret.SecretBox(Alices_key)
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)

    encrypted = Alices_box.encrypt(message, nonce)

    # now Alice must send to Bob both the encrypted message
    # and the KDF parameters: salt, opslimit and memlimit
    # using the same parameters **and password**
    # Bob is able to derive the correct key to decrypt the message


    Bobs_key = pw_hash.kdf_scryptsalsa208sha256(secret.SecretBox.KEY_SIZE,
                                                password, salt,
                                                opslimit=ops, memlimit=mem)
    Bobs_box = secret.SecretBox(Bobs_key)
    received = Bobs_box.decrypt(encrypted)
    print(received)

if Eve's manages to get the encrypted message, and tries to decrypt it
with a wrongly guessed password, even if she does know all of the key
derivation parameters, she would derive a different key, therefore
the decryption would fail and an exception would be raised::

    >>> from nacl import pw_hash, secret, utils
    >>>
    >>> ops = pw_hash.SCRYPT_OPSLIMIT_SENSITIVE
    >>> mem = pw_hash.SCRYPT_MEMLIMIT_SENSITIVE
    >>>
    >>> salt = utils.random(pw_hash.SCRYPT_SALTBYTES)
    >>>
    >>> guessed_pw = b'I think Alice shared this password with Bob'
    >>>
    >>> Eves_key = pw_hash.kdf_scryptsalsa208sha256(secret.SecretBox.KEY_SIZE,
    ...                                             guessed_pw, salt,
    ...                                             opslimit=ops, memlimit=mem)
    >>> Eves_box = secret.SecretBox(Eves_key)
    >>> intercepted = Eves_box.decrypt(encrypted)
    Traceback (most recent call last):
        ...
    nacl.exceptions.CryptoError: Decryption failed. Ciphertext failed ...

.. [SD2012] A nice overview of password hashing history is available
   in Solar Designer's presentation
   `Password security: past, present, future
   <http://www.openwall.com/presentations/Passwords12-The-Future-Of-Hashing/>`_
