from __future__ import absolute_import
from __future__ import division

from . import six

from . import nacl, encoding
from .exceptions import CryptoError


class SecretBox(encoding.Encodable, six.StringFixer, object):

    KEY_SIZE = nacl.lib.crypto_secretbox_KEYBYTES

    def __init__(self, key, encoder=encoding.RawEncoder):
        key = encoder.decode(key)

        if len(key) != self.KEY_SIZE:
            raise ValueError("The key must be exactly %s bytes long" %
                                nacl.lib.crypto_secretbox_KEYBYTES)

        self._key = key

    def __bytes__(self):
        return self._key

    def encrypt(self, plaintext, nonce, encoder=encoding.RawEncoder):
        if len(nonce) != nacl.lib.crypto_secretbox_NONCEBYTES:
            raise ValueError("The nonce must be exactly %s bytes long" %
                                nacl.lib.crypto_secretbox_NONCEBYTES)

        padded = b"\x00" * nacl.lib.crypto_secretbox_ZEROBYTES + plaintext
        ciphertext = nacl.ffi.new("unsigned char[]", len(padded))

        if not nacl.lib.crypto_secretbox(
                    ciphertext, padded, len(padded), nonce, self._key,
                ):
            raise CryptoError("Encryption failed")

        box_zeros = nacl.lib.crypto_secretbox_BOXZEROBYTES
        ciphertext = nacl.ffi.buffer(ciphertext, len(padded))[box_zeros:]

        return encoder.encode(ciphertext)

    def decrypt(self, ciphertext, nonce, encoder=encoding.RawEncoder):
        if len(nonce) != nacl.lib.crypto_secretbox_NONCEBYTES:
            raise ValueError("The nonce must be exactly %s bytes long" %
                                nacl.lib.crypto_secretbox_NONCEBYTES)

        ciphertext = encoder.decode(ciphertext)

        padded = b"\x00" * nacl.lib.crypto_secretbox_BOXZEROBYTES + ciphertext
        plaintext = nacl.ffi.new("unsigned char[]", len(padded))

        if not nacl.lib.crypto_secretbox_open(
                    plaintext, padded, len(padded), nonce, self._key,
                ):
            raise CryptoError(
                        "Decryption failed. Ciphertext failed verification")

        box_zeros = nacl.lib.crypto_secretbox_ZEROBYTES
        plaintext = nacl.ffi.buffer(plaintext, len(padded))[box_zeros:]

        return plaintext
