
from __future__ import absolute_import, division, print_function

from nacl import encoding
import nacl.bindings
from nacl.utils import EncryptedMessage, StringFixer

class AES256GCM(encoding.Encodable, StringFixer, object):
    
    KEY_SIZE = nacl.bindings.crypto_aead_aes256gcm_KEYBYTES
    NONCE_SIZE = nacl.bindings.crypto_aead_aes256gcm_NPUBBYTES

    def __init__(self, key, encoder=encoding.RawEncoder):
        key = encoder.decode(key)
        
        if not isinstance(key, bytes):
            raise TypeError("AES256GCM must be created from crypto_aead_aes256gcm_KEYBYTES bytes")

        if len(key) != self.KEY_SIZE:
            raise ValueError(
                "The key must be exactly %s bytes long" %
                self.KEY_SIZE,
            )

        self._key = key

    def __bytes__(self):
        return self._key

    def decrypt_and_verify(self, cipher, tag, nonce, encoder=encoding.RawEncoder):
        cipher = encoder.decode(cipher)

        
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        plaintext = nacl.bindings.crypto_aead_aes256gcm_decrypt(cipher, tag, nonce ,self._key)

        return plaintext
