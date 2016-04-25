Utilities
=========

.. currentmodule:: nacl.utils

.. class:: EncryptedMessage

    A ``bytes`` subclass that holds a message that has been encrypted by a
    :class:`~nacl.secret.SecretBox` or :class:`~nacl.public.Box`. The full
    content of the ``bytes`` object is the combined ``nonce`` and
    ``ciphertext``.

    .. attribute:: nonce

        The nonce used during the encryption of the :class:`EncryptedMessage`.

    .. attribute:: ciphertext

        The ciphertext contained within the :class:`EncryptedMessage`.

.. function:: random(size=32)

    Returns a random bytestring with the given ``size``.

    :param bytes size: The size of the random bytestring.
    :return bytes: The random bytestring.
