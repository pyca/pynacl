from __future__ import absolute_import
from __future__ import division

from . import nacl
from . import six


class EncryptedMessage(six.binary_type):
    """
    A bytes subclass that holds a messaged that has been encrypted by a
    :class:`SecretBox`.
    """

    @classmethod
    def _from_parts(cls, nonce, ciphertext, combined):
        obj = cls(combined)
        obj._nonce = nonce
        obj._ciphertext = ciphertext
        return obj

    @property
    def nonce(self):
        """
        The nonce used during the encryption of the :class:`EncryptedMessage`.
        """
        return self._nonce

    @property
    def ciphertext(self):
        """
        The ciphertext contained within the :class:`EncryptedMessage`.
        """
        return self._ciphertext


def random(size=32):
    data = nacl.ffi.new("unsigned char[]", size)
    nacl.lib.randombytes(data, size)
    return nacl.ffi.buffer(data, size)[:]
