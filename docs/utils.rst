Utility Classes
===============

.. class:: EncryptedMessage

    A ``bytes`` subclass that holds a message that has been encrypted by a
    :class:`~nacl.secret.SecretBox` or :class:`~nacl.public.Box`.

    .. attribute:: nonce

        The nonce used during the encryption of the :class:`EncryptedMessage`.

    .. attribute:: ciphertext

        The ciphertext contained within the :class:`EncryptedMessage`.
