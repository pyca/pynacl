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
import nacl.bindings
from nacl.utils import EncryptedMessage, StringFixer, random


class PublicKey(encoding.Encodable, StringFixer, object):

    SIZE = nacl.bindings.crypto_box_PUBLICKEYBYTES

    def __init__(self, public_key, encoder=encoding.RawEncoder):
        self._public_key = encoder.decode(public_key)
        if not isinstance(self._public_key, bytes):
            raise TypeError("PublicKey must be created from 32 bytes")

        if len(self._public_key) != self.SIZE:
            raise ValueError("The public key must be exactly %s bytes long" %
                             self.SIZE)

    def __bytes__(self):
        return self._public_key


class PrivateKey(encoding.Encodable, StringFixer, object):

    SIZE = nacl.bindings.crypto_box_SECRETKEYBYTES

    def __init__(self, private_key, encoder=encoding.RawEncoder):
        # Decode the secret_key
        private_key = encoder.decode(private_key)
        if not isinstance(private_key, bytes):
            raise TypeError("PrivateKey must be created from a 32 byte seed")

        # Verify that our seed is the proper size
        if len(private_key) != self.SIZE:
            raise ValueError(
                "The secret key must be exactly %d bytes long" % self.SIZE)

        raw_public_key = nacl.bindings.crypto_scalarmult_base(private_key)

        self._private_key = private_key
        self.public_key = PublicKey(raw_public_key)

    def __bytes__(self):
        return self._private_key

    @classmethod
    def generate(cls):
        return cls(random(PrivateKey.SIZE), encoder=encoding.RawEncoder)


class Box(encoding.Encodable, StringFixer, object):

    NONCE_SIZE = nacl.bindings.crypto_box_NONCEBYTES

    def __init__(self, private_key, public_key):
        if private_key and public_key:
            if ((not isinstance(private_key, PrivateKey) or
                 not isinstance(public_key, PublicKey))):
                raise TypeError("Box must be created from "
                                "a PrivateKey and a PublicKey")
            self._shared_key = nacl.bindings.crypto_box_beforenm(
                public_key.encode(encoder=encoding.RawEncoder),
                private_key.encode(encoder=encoding.RawEncoder),
            )
        else:
            self._shared_key = None

    def __bytes__(self):
        return self._shared_key

    @classmethod
    def decode(cls, encoded, encoder=encoding.RawEncoder):
        # Create an empty box
        box = cls(None, None)

        # Assign our decoded value to the shared key of the box
        box._shared_key = encoder.decode(encoded)

        return box

    def encrypt(self, plaintext, nonce, encoder=encoding.RawEncoder):

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("The nonce must be exactly %s bytes long" %
                             self.NONCE_SIZE)

        ciphertext = nacl.bindings.crypto_box_afternm(
            plaintext,
            nonce,
            self._shared_key,
        )

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
            raise ValueError("The nonce must be exactly %s bytes long" %
                             self.NONCE_SIZE)

        plaintext = nacl.bindings.crypto_box_open_afternm(
            ciphertext,
            nonce,
            self._shared_key,
        )

        return plaintext
