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

.. function:: randombytes_deterministic(size, seed, encoder=encoding.RawEncoder)

    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a 32 byte seed.

    :param bytes size: The size of the random bytestring.
    :param bytes seed: The seed for the bytestring. This should be 32 bytes
                            or a TypeError will be thrown.
    :param encoder: The encoder class used to encode the produced bytes.
    :return bytes: The random bytestring.

.. function:: ensure(cond, *args, raising=nacl.exceptions.AssertionError)

    Returns if a condition is true, otherwise raise a caller-configurable
    :py:class:`Exception`

    :param cond: the condition to be checked
    :type cond: bool
    :param sequence args: the arguments to be passed to the exception's
                          constructor
    :param raising: the exception to be raised if `cond` is `False`
    :type raising: exception

