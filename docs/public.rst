Public Key Encryption
=====================

Imagine Alice wants something valuable shipped to her. Because it's valuable,
she wants to make sure it arrives securely (i.e. hasn't been opened or
tampered with) and that it's not a forgery (i.e. it's actually from the sender
she's expecting it to be from and nobody's pulling the old switcheroo).

One way she can do this is by providing the sender (let's call him Bob) with a
high-security box of her choosing. She provides Bob with this box, and
something else: a padlock, but a padlock without a key. Alice is keeping that
key all to herself. Bob can put items in the box then put the padlock onto it.
But once the padlock snaps shut, the box cannot be opened by anyone who
doesn't have Alice's private key.

Here's the twist though: Bob also puts a padlock onto the box. This padlock
uses a key Bob has published to the world, such that if you have one of Bob's
keys, you know a box came from him because Bob's keys will open Bob's padlocks
(let's imagine a world where padlocks cannot be forged even if you know the
key). Bob then sends the box to Alice.

In order for Alice to open the box, she needs two keys: her private key that
opens her own padlock, and Bob's well-known key. If Bob's key doesn't open the
second padlock, then Alice knows that this is not the box she was expecting
from Bob, it's a forgery.

This bidirectional guarantee around identity is known as mutual authentication.


Examples
--------

nacl.public.Box
~~~~~~~~~~~~~~~

The :class:`nacl.public.Box` class uses the given public and private (secret)
keys to derive a shared key, which is used with the nonce given to encrypt the
given messages and to decrypt the given ciphertexts.  The same shared key will
be generated from both pairing of keys, so given two keypairs belonging to
Alice (pkalice, skalice) and Bob (pkbob, skbob), the key derived from
(pkalice, skbob) will equal that from (pkbob, skalice).

This is how the system works:

.. testcode::

    import nacl.utils
    from nacl.public import PrivateKey, Box

    # Generate Bob's private key, which must be kept secret
    skbob = PrivateKey.generate()

    # Bob's public key can be given to anyone wishing to send
    #   Bob an encrypted message
    pkbob = skbob.public_key

    # Alice does the same and then Alice and Bob exchange public keys
    skalice = PrivateKey.generate()
    pkalice = skalice.public_key

    # Bob wishes to send Alice an encrypted message so Bob must make a Box with
    #   his private key and Alice's public key
    bob_box = Box(skbob, pkalice)

    # This is our message to send, it must be a bytestring as Box will treat it
    #   as just a binary blob of data.
    message = b"Kill all humans"

PyNaCl can automatically generate a random nonce for us, making the encryption
very simple:

.. testcode::

    # Encrypt our message, it will be exactly 40 bytes longer than the
    #   original message as it stores authentication information and the
    #   nonce alongside it.
    encrypted = bob_box.encrypt(message)

However, if we need to use an explicit nonce, it can be passed along with the
message:

.. testcode::

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonces are just sequences of 24 random bytes.
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    encrypted = bob_box.encrypt(message, nonce)

Finally, the message is decrypted (regardless of how the nonce was generated):

.. testcode::

    # Alice creates a second box with her private key to decrypt the message
    alice_box = Box(skalice, pkbob)

    # Decrypt our message, an exception will be raised if the encryption was
    #   tampered with or there was otherwise an error.
    plaintext = alice_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))

.. testoutput::

    Kill all humans


nacl.public.SealedBox
~~~~~~~~~~~~~~~~~~~~~

The :class:`nacl.public.SealedBox` class encrypts messages addressed
to a specified key-pair by using ephemeral sender's keypairs, which
will be discarded just after encrypting a single plaintext message.

This kind of construction allows sending messages, which only the recipient
can decrypt without providing any kind of cryptographic proof of sender's
authorship.

.. warning:: By design, the recipient will have no means to trace
    the ciphertext to a known author, since the sending
    keypair itself is not bound to any sender's identity, and
    the sender herself will not be able to decrypt the ciphertext
    she just created, since the private part of the key cannot be
    recovered after use.

This is how the system works:

.. testcode::

    import nacl.utils
    from nacl.public import PrivateKey, SealedBox

    # Generate Bob's private key, as we've done in the Box example
    skbob = PrivateKey.generate()
    pkbob = skbob.public_key

    # Alice wishes to send a encrypted message to Bob,
    # but prefers the message to be untraceable
    sealed_box = SealedBox(pkbob)

    # This is Alice's message
    message = b"Kill all kittens"

    # Encrypt the message, it will carry the ephemeral key public part
    # to let Bob decrypt it
    encrypted = sealed_box.encrypt(message)

Now, Bob wants to read the secret message he just received; therefore
he must create a SealedBox using his own private key:

.. testcode::

    unseal_box = SealedBox(skbob)
    # decrypt the received message
    plaintext = unseal_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))

.. testoutput::

    Kill all kittens


Reference
---------

See the module API reference, available at :mod:`nacl.public`.


Algorithm
~~~~~~~~~

* **Public Keys:** `Curve25519 high-speed elliptic curve cryptography <https://cr.yp.to/ecdh.html>`_
