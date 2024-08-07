Secret Key Encryption
=====================

.. currentmodule:: nacl.secret

Secret key encryption (also called symmetric key encryption) is analogous to a
safe. You can store something secret through it and anyone who has the key can
open it and view the contents. :class:`~nacl.secret.SecretBox` and
:class:`~nacl.secret.Aead` functions as just such a safe, and like any
good safe any attempts to tamper with the contents are easily detected.

Secret key encryption allows you to store or transmit data over insecure
channels without leaking the contents of that message, nor anything about it
other than the length.

Example with SecretBox
----------------------

.. testcode::

    import nacl.secret
    import nacl.utils

    # This must be kept secret, this is the combination to your safe
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)

    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.SecretBox(key)

    # This is our message to send, it must be a bytestring as SecretBox will
    #   treat it as just a binary blob of data.
    message = b"The president will be exiting through the lower levels"

PyNaCl can automatically generate a random nonce for us, making the encryption
very simple:

.. testcode::

    # Encrypt our message, it will be exactly 40 bytes longer than the
    #   original message as it stores authentication information and the
    #   nonce alongside it.
    encrypted = box.encrypt(message)

    assert len(encrypted) == len(message) + box.NONCE_SIZE + box.MACBYTES

However, if we need to use an explicit nonce, it can be passed along with the
message:

.. testcode::

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonces are just sequences of 24 random bytes.
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    encrypted = box.encrypt(message, nonce)

If you need to get the ciphertext and the authentication data
without the nonce, you can get the `ciphertext` attribute of the
:class:`~nacl.utils.EncryptedMessage` instance returned by
:meth:`~nacl.secret.SecretBox.encrypt`:

.. testcode::

    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    encrypted = box.encrypt(message, nonce)

    # since we are transmitting the nonce by some other means,
    # we just need to get the ciphertext and authentication data

    ctext = encrypted.ciphertext

    # ctext is just nacl.secret.SecretBox.MACBYTES longer
    # than the original message

    assert len(ctext) == len(message) + box.MACBYTES

Finally, the message is decrypted (regardless of how the nonce was generated):

.. testcode::

    # Decrypt our message, an exception will be raised if the encryption was
    #   tampered with or there was otherwise an error.
    plaintext = box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))

.. testoutput::

    The president will be exiting through the lower levels

Example with Aead
-----------------

.. testcode::

    import nacl.secret
    import nacl.utils

    # This must be kept secret, this is the combination to your safe
    key = nacl.utils.random(nacl.secret.Aead.KEY_SIZE)

    # This is your safe, you can use it to encrypt or decrypt messages
    box = nacl.secret.Aead(key)

    # This is our message to send, it must be a bytestring as Aead will
    #   treat it as just a binary blob of data.
    message = b"The president will be exiting through the upper levels"

PyNaCl can automatically generate a random nonce for us, making the encryption
very simple:

.. testcode::

    # Encrypt our message with (optionally) additional authenticated data,
    # it will be exactly 40 bytes longer than the original message as it
    # stores authentication information and the nonce alongside it.

    aad = b'POTUS'

    encrypted = box.encrypt(message, aad)

    #encrypted = box.encrypt(message) would suffice if aad is not needed.

    assert len(encrypted) == len(message) + box.NONCE_SIZE + box.MACBYTES

However, if we need to use an explicit nonce, it can be passed along with the
message:

.. testcode::

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonces are just sequences of 24 random bytes.
    nonce = nacl.utils.random(nacl.secret.Aead.NONCE_SIZE)

    encrypted = box.encrypt(message, aad, nonce)

If you need to get the ciphertext and the authentication data
without the nonce, you can get the `ciphertext` attribute of the
:class:`~nacl.utils.EncryptedMessage` instance returned by
:meth:`~nacl.secret.Aead.encrypt`:

.. testcode::

    aad = b'POTUS'

    nonce = nacl.utils.random(nacl.secret.Aead.NONCE_SIZE)

    encrypted = box.encrypt(message, aad, nonce)

    # since we are transmitting the nonce by some other means,
    # we just need to get the ciphertext and authentication data

    ctext = encrypted.ciphertext

    # ctext is just nacl.secret.Aead.MACBYTES longer
    # than the original message

    assert len(ctext) == len(message) + box.MACBYTES

Finally, the message is decrypted (regardless of how the nonce was generated):

.. testcode::

    # Decrypt our message, an exception will be raised if the encryption was
    # tampered with or there was otherwise an error.

    aad = b'POTUS'

    plaintext = box.decrypt(encrypted, aad)
    #plaintext = box.decrypt(encrypted) would suffice if aad was not used.

    print(plaintext.decode('utf-8'))

.. testoutput::

    The president will be exiting through the upper levels


Requirements
------------

Key
~~~

The 32 bytes key given to :class:`~nacl.secret.SecretBox`
or :class:`~nacl.secret.Aead` must be kept secret. It is
the combination to your "safe" and anyone with this key will
be able to decrypt the data, or encrypt new data.


Nonce
~~~~~

The 24-byte nonce (`Number used once <https://en.wikipedia.org/wiki/Cryptographic_nonce>`_)
given to :meth:`~nacl.secret.SecretBox.encrypt`,
:meth:`~nacl.secret.SecretBox.decrypt`, :meth:`~nacl.secret.Aead.encrypt` and
:meth:`~nacl.secret.Aead.decrypt` must **NEVER** be reused for a
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

You can safely generate random nonces by calling:
:func:`~nacl.utils.random` with ``SecretBox.NONCE_SIZE`` for SecretBox and
:func:`~nacl.utils.random` with ``Aead.NONCE_SIZE`` for Aead.


Aad
~~~

:class:`~nacl.secret.Aead` supports Authenticated Encryption with
Associated Data. :meth:`~nacl.secret.Aead.encrypt` and
:meth:`~nacl.secret.Aead.decrypt` accept an optional, arbitrary long
“additional data” parameter. These data are not present in the ciphertext,
but are mixed in the computation of the authentication tag.
A typical use for these data is to authenticate version numbers,
timestamps or monotonically increasing counters in order to discard
previous messages and prevent replay attacks.

A default empty bytes object will be used if not set when calling
:meth:`~nacl.secret.Aead.encrypt` or :meth:`~nacl.secret.Aead.decrypt`.


Reference
---------

.. class:: SecretBox(key, encoder)

    The SecretBox class encrypts and decrypts messages using the given secret
    key.

    The ciphertexts generated by :class:`~nacl.secret.Secretbox` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param bytes key: The secret key used to encrypt and decrypt messages.
    :param encoder: A class that is able to decode the ``key``.

    .. method:: encrypt(plaintext, nonce, encoder)

        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is **VITALLY** important that the nonce is a nonce,
            i.e. it is a number used only once for any given key. If you fail
            to do this, you compromise the privacy of the messages encrypted.
            Give your nonces a different prefix, or have one side use an odd
            counter and one an even counter. Just make sure they are different.

        :param bytes plaintext: The plaintext message to encrypt.
        :param bytes nonce: The nonce to use in the encryption.
        :param encoder:  A class that is able to decode the ciphertext.

        :return: An instance of :class:`~nacl.utils.EncryptedMessage`.

    .. method:: decrypt(ciphertext, nonce, encoder)

        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param bytes ciphertext: The encrypted message to decrypt.
        :param bytes nonce: The nonce to use in the decryption.
        :param encoder: A class that is able to decode the plaintext.

        :return bytes: The decrypted plaintext.

.. class:: Aead(key, encoder)

    The AEAD class encrypts and decrypts messages using the given secret key.

    Unlike :class:`~nacl.secret.SecretBox`, AEAD supports authenticating
    non-confidential data received alongside the message, such as a length
    or type tag.

    Like :class:`~nacl.secret.Secretbox`, this class provides authenticated
    encryption. An inauthentic message will cause the decrypt function to raise
    an exception.

    Likewise, the authenticator should not be mistaken for a (public-key)
    signature: recipients (with the ability to decrypt messages) are capable of
    creating arbitrary valid message; in particular, this means AEAD messages
    are repudiable. For non-repudiable messages, sign them after encryption.

    :param key: The secret key used to encrypt and decrypt messages
    :param encoder: The encoder class used to decode the given key

    .. method:: encrypt(plaintext, aad, nonce, encoder)

        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is vitally important for :param nonce: to be unique.
            By default, it is generated randomly; [:class:`Aead`] uses XChacha20
            for extended (192b) nonce size, so the risk of reusing random nonces
            is negligible.  It is *strongly recommended* to keep this behaviour,
            as nonce reuse will compromise the privacy of encrypted messages.
            Should implicit nonces be inadequate for your application, the
            second best option is using split counters; e.g. if sending messages
            encrypted under a shared key between 2 users, each user can use the
            number of messages it sent so far, prefixed or suffixed with a 1bit
            user id.  Note that the counter must **never** be rolled back (due
            to overflow, on-disk state being rolled back to an earlier backup,
            ...)

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param aad: [:class:`bytes`] The aad to be used in the authentication process
        :param nonce: [:class:`bytes`] The nonce to use in the encryption
        :param encoder: The encoder to use to encode the ciphertext

        :return: An instance of :class:`~nacl.utils.EncryptedMessage`.

    .. method:: decrypt(ciphertext, aad, nonce, encoder)

        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param aad: [:class:`bytes`] The aad to be used in the authentication process
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.

        :return bytes: The decrypted plaintext.

Algorithm details
-----------------

:Encryption for SecretBox: `XSalsa20 stream cipher <https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xsalsa20>`_
:Encryption for Aead: `XChaCha20 stream cipher <https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xchacha20>`_
:Aead Construction: `IETF ChaCha20 Poly1305 <https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/ietf_chacha20-poly1305_construction>`_
:Authentication: `Poly1305 MAC <https://en.wikipedia.org/wiki/Poly1305-AES>`_
