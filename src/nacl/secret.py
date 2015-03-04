# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

from nacl import encoding
import nacl.c
from nacl.utils import EncryptedMessage, StringFixer


class SecretBox(encoding.Encodable, StringFixer, object):

    KEY_SIZE = nacl.c.crypto_secretbox_KEYBYTES
    NONCE_SIZE = nacl.c.crypto_secretbox_NONCEBYTES

    def __init__(self, key, encoder=encoding.RawEncoder):
        key = encoder.decode(key)
        if not isinstance(key, bytes):
            raise TypeError("SecretBox must be created from 32 bytes")

        if len(key) != self.KEY_SIZE:
            raise ValueError(
                "The key must be exactly %s bytes long" %
                self.KEY_SIZE,
            )

        self._key = key

    def __bytes__(self):
        return self._key

    def encrypt(self, plaintext, nonce, encoder=encoding.RawEncoder):

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        ciphertext = nacl.c.crypto_secretbox(plaintext, nonce, self._key)

        encoded_nonce = encoder.encode(nonce)
        encoded_ciphertext = encoder.encode(ciphertext)

        return EncryptedMessage._from_parts(
            encoded_nonce,
            encoded_ciphertext,
            encoder.encode(nonce + ciphertext),
        )

    def decrypt(self, ciphertext, nonce=None, encoder=encoding.RawEncoder):

        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[:self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE:]

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                "The nonce must be exactly %s bytes long" % self.NONCE_SIZE,
            )

        plaintext = nacl.c.crypto_secretbox_open(ciphertext, nonce, self._key)

        return plaintext
