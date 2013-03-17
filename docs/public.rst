Public Key Encryption
=====================

Imagine Alice wants something valuable shipped to her. Because it's valuable,
she wants to make sure it arrives securely (i.e. hasn't been opened or
tampered with) and that it's not a forgery (i.e. it's actually from the sender
she's expecting it to be from and nobody's pulling the old switcheroo)

One way she can do this is by providing the sender (let's call him Bob) with a
high-security box of her choosing. She provides Bob with this box, and
something else: a padlock, but a padlock without a key. Alice is keeping that
key all to herself. Bob can put items in the box then put the padlock onto it,
but once the padlock snaps shut, the box cannot be opened by anyone who
doesn't have Alice's private key.

Here's the twist though, Bob also puts a padlock onto the box. This padlock
uses a key Bob has published to the world, such that if you have one of Bob's
keys, you know a box came from him because Bob's keys will open Bob's padlocks
(let's imagine a world where padlocks cannot be forged even if you know the
key). Bob then sends the box to Alice.

In order for Alice to open the box, she needs two keys: her private key that
opens her own padlock, and Bob's well-known key. If Bob's key doesn't open the
second padlock then Alice knows that this is not the box she was expecting
from Bob, it's a forgery.

This bidirectional guarantee around identity is known as mutual authentication.


Example
-------

The :class:`~nacl.public.Box` class uses the given public and private (secret)
keys to derive a shared key, which is used with the nonce given to encrypt the
given messages and decrypt the given ciphertexts.  The same shared key will
generated from both pairing of keys, so given two keypairs belonging to alice
(pkalice, skalice) and bob(pkbob, skbob), the key derived from (pkalice, skbob)
with equal that from (pkbob, skalice).  This is how the system works:

.. code:: python

    import nacl.utils
    from nacl.public import PrivateKey, Box

    # generate the private key which must be kept secret
    skbob = PrivateKey.generate()

    # the public key can be given to anyone wishing to send
    # Bob an encrypted message
    pkbob = skbob.public_key

    # Alice does the same and then
    #     sends her public key to Bob and Bob his public key to Alice
    skalice = PrivateKey.generate()
    pkalice = skalice.public_key

    # Bob wishes to send Alice an encrypted message
    # So Bob must make a Box with his private key and Alice's public key
    bob_box = Box(pkalice, skbob)

    # This is our message to send, it must be a bytestring as Box will
    #   treat is as just a binary blob of data.
    message = b"Kill all humans"

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonce is just 24 random bytes.
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    # Encrypt our message, it will be exactly 16 bytes longer than the original
    #   message as it stores authentication information alongside it.
    ciphertext = bob_box.encrypt(message, nonce)

    # Alice creates a second box with her private key to decrypt the message
    alice_box = Box(pkbob, skalice)

    # Decrypt our message, an exception will be raised if the encryption was
    #   tampered with or there was otherwise an error.
    plaintext = alice_box.decrypt(ciphertext, nonce)



Reference
---------

.. autoclass:: nacl.public.PublicKey
    :members:
.. autoclass:: nacl.public.PrivateKey
    :members:
.. autoclass:: nacl.public.Box
    :members:
