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


Usage Information
-----------------

* :class:`~nacl.secret.SecretBox` requires a 32 byte key that must be kept
  secret. It is the combination to your "safe" and anyone with this key will
  be able to decrypt the data.
* :class:`~nacl.secret.SecretBox` requires a new 24 bytes nonce with every
  encrypted message. This nonce is *not* secret and be freely transfered or
  stored in plaintext alongside the ciphertext. However it is absolutely
  imperative that you **NEVER** reuse a nonce with the same key. Reusing the
  nonce with the same key provides enough information for an attacker
  to decrypt any and all messages made with your key.


Reference
---------

.. autoclass:: nacl.secret.SecretBox
    :members:


Algorithm details
-----------------

:Encryption: `Salsa20 steam cipher <https://en.wikipedia.org/wiki/Salsa20>`_
:Authentication: `Poly1305 MAC <https://en.wikipedia.org/wiki/Poly1305-AES>`_
