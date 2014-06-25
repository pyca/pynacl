Secret Key Encryption
=====================

Secret key encryption is analogous to a safe. You can store something secret
through it and anyone who has the key can open it and view the contents.
:class:`~nacl.secret.SecretBox` functions as just such a safe, and like any
good safe any attempts to tamper with the contents is easily detected.

Secret Key Encryption allows you to store or transmit data over insecure
channels without leaking the contents of that message, nor anything about it
other than the length.

Example
-------

.. code-block:: python

    import nacl.secret
    import nacl.utils

    # This must be kept secret, this is the combination to your safe
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)

    # This is our message to send, it must be a bytestring as SecretBox will
    #   treat is as just a binary blob of data.
    message = b"The president will be exiting through the lower levels"

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonce is just 24 random bytes.
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    # Encrypt our message, it will be exactly 40 bytes longer than the original
    #   message as it stores authentication information and nonce alongside it.
    encrypted = box.encrypt(message, nonce)

    # Decrypt our message, an exception will be raised if the encryption was
    #   tampered with or there was otherwise an error.
    plaintext = box.decrypt(encrypted)


Requirements
------------

Key
~~~

The 32 bytes key given to :class:`~nacl.secret.SecretBox` must be kept secret.
It is the combination to your "safe" and anyone with this key will be able to
decrypt the data, or encrypt new data.


Nonce
~~~~~

The 24-byte nonce (`Number used once <https://en.wikipedia.org/wiki/Cryptographic_nonce>`_)
given to :meth:`~nacl.secret.SecretBox.encrypt` and
:meth:`~nacl.secret.SecretBox.decrypt` must **NEVER** be reused for a
particular key. Reusing a nonce may give an attacker enough information to
decrypt or forge other messages. A nonce is not considered secret and may be
freely transmitted or stored in plaintext alongside the ciphertext.

A nonce does not need to be random or unpredictable, nor does the method of
generating them need to be secret. A nonce could simply be a counter
incremented with each message encrypted, which can be useful in
connection-oriented protocols to reject duplicate messages ("replay
attacks"). A bidirectional connection could use the same key for both
directions, as long as their nonces never overlap (e.g. one direction always
sets the high bit to "1", the other always sets it to "0").

If you use a counter-based nonce along with a key that is persisted from one
session to another (e.g. saved to disk), you must store the counter along
with the key, to avoid accidental nonce reuse on the next session. For this
reason, many protocols derive a new key for each session, reset the counter
to zero with each new key, and never store the derived key or the counter.

You can safely generate random nonces by calling ``nacl.utils.random(SecretBox.NONCE_SIZE)``.


Reference
---------

.. autoclass:: nacl.secret.SecretBox
    :members:

.. autoclass:: nacl.utils.EncryptedMessage
    :members:
    :noindex:


Algorithm details
-----------------

:Encryption: `Salsa20 steam cipher <https://en.wikipedia.org/wiki/Salsa20>`_
:Authentication: `Poly1305 MAC <https://en.wikipedia.org/wiki/Poly1305-AES>`_
