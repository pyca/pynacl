nacl.hash
=========

.. currentmodule:: nacl.hash

.. function:: sha256(message, encoder)

    Hashes ``message`` with SHA256.

    :param bytes message: The message to hash.
    :param encoder: A class that is able to encode the hashed message.
    :return bytes: The hashed message.

.. function:: sha512(message, encoder)

    Hashes ``message`` with SHA512.

    :param bytes message: The message to hash.
    :param encoder: A class that is able to encode the hashed message.
    :return bytes: The hashed message.

.. function:: blake2b(data, digest_size=BLAKE2B_BYTES, key=b'', \
                      salt=b'', person=b'', encoder=nacl.encoding.HexEncoder)

    One-shot blake2b digest

    :param data: the digest input byte sequence
    :type data: bytes
    :param digest_size: the requested digest size; must be at most
                        :py:data:`.BLAKE2B_BYTES_MAX`;
                        the default digest size is :py:data:`.BLAKE2B_BYTES`
    :type digest_size: int
    :param key: the key to be set for keyed MAC/PRF usage; if set, the key
                must be at most :py:data:`.BLAKE2B_KEYBYTES_MAX` long
    :type key: bytes
    :param salt: an initialization salt at most
                 :py:data:`.BLAKE2B_SALTBYTES` long; it will be zero-padded
                 if needed
    :type salt: bytes
    :param person: a personalization string at most
                     :py:data:`.BLAKE2B_PERSONALBYTES` long; it will be
                     zero-padded if needed
    :type person: bytes
    :param encoder: the encoder to use on returned digest
    :type encoder: class
    :return: encoded bytes data
    :rtype: the return type of the choosen encoder


.. function:: siphash24(message, key=b'', encoder=nacl.encoding.HexEncoder)

    Computes a keyed MAC of ``message`` using siphash-2-4

    :param message: The message to hash.
    :type message: bytes
    :param key: the message authentication key to be used
                It must be a :py:data:`.SIPHASH_KEYBYTES` long
                bytes sequence
    :type key: bytes(:py:data:`.SIPHASH_KEYBYTES`)
    :param encoder: A class that is able to encode the hashed message.
    :return: The hashed message.
    :rtype: bytes(:py:data:`.SIPHASH_BYTES`) long bytes sequence


.. function:: siphashx24(message, key=b'', encoder=nacl.encoding.HexEncoder)

    .. versionadded:: 1.2

    Computes a keyed MAC of ``message`` using the extended output length
    variant of siphash-2-4

    :param message: The message to hash.
    :type message: bytes
    :param key: the message authentication key to be used
                It must be a :py:data:`.SIPHASHX_KEYBYTES` long
                bytes sequence
    :type key: bytes(:py:data:`.SIPHASHX_KEYBYTES`)
    :param encoder: A class that is able to encode the hashed message.
    :return: The hashed message.
    :rtype: bytes(:py:data:`.SIPHASHX_BYTES`) long bytes sequence
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
