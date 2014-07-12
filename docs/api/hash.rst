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
