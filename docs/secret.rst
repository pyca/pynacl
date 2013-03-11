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

.. code:: python

    import nacl
    import nacl.secret

    # This must be kept secret, this is the combination to your safe
    key = nacl.random(nacl.secret.SecretBox.KEY_SIZE)

    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)

    # This is our message to send, it must be a bytestring as SecretBox will
    #   treat is as just a binary blob of data.
    message = b"The president will be exiting through the lower levels"

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonce is just 24 random bytes.
    nonce = nacl.random(24)

    # Encrypt our message, it will be exactly 16 bytes longer than the original
    #   message as it stores authentication information alongside it.
    ciphertext = box.encrypt(message, nonce)

    # Decrypt our message, an exception will be raised if the encryption was
    #   tampered with or there was otherwise an error.
    plaintext = box.decrypt(ciphertext, nonce)


Requirements
------------

Key
~~~

The 32 bytes key given to :class:`~nacl.secret.SecretBox` must be kept secret.
It is the combination to your "safe" and anyone with this key will be able to
decrypt the data, or encrypt new data.


Nonce
~~~~~

The 24 bytes nonce (`Number used once <https://en.wikipedia.org/wiki/Cryptographic_nonce>`_)
given to :meth:`~nacl.secret.SecretBox.encrypt` and :meth:`~nacl.secret.SecretBox.decrypt`
must **NEVER** be reused for a particular key. Reusing the nonce means an
attacker will have enough information to recover your secret key and encrypt or
decrypt arbitrary messages. A nonce is not considered secret and may be freely
transmitted or stored in plaintext alongside the ciphertext.

A nonce does not need to be random, nor does the method of generating them need
to be secret. A nonce could simply be a counter incremented with each message
encrypted.

Both the sender and the receiver should record every nonce both that they've
used and they've received from the other. They should reject any message which
reuses a nonce and they should make absolutely sure never to reuse a nonce. It
is not enough to simply use a random value and hope that it's not being reused
(simply generating random values would open up the system to a
`Birthday Attack <https://en.wikipedia.org/wiki/Birthday_attack>`_).

One good method of generating nonces is for each person to pick a unique prefix,
for example ``b"p1"`` and ``b"p2"``. When each person generates a nonce they
prefix it, so instead of ``nacl.random(24)`` you'd do ``b"p1" + nacl.random(22)``.
This prefix serves as a guarantee that no two messages from different people
will inadvertently overlap nonces while in transit. They should still record
every nonce they've personally used and every nonce they've received to prevent
reuse or replays.


Reference
---------

.. autoclass:: nacl.secret.SecretBox
    :members:


Algorithm details
-----------------

:Encryption: `Salsa20 steam cipher <https://en.wikipedia.org/wiki/Salsa20>`_
:Authentication: `Poly1305 MAC <https://en.wikipedia.org/wiki/Poly1305-AES>`_
