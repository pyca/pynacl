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

import nacl.bindings
from nacl import encoding
from nacl import exceptions as exc
from nacl.utils import EncryptedMessage, StringFixer, random


class PublicKey(encoding.Encodable, StringFixer, object):
    """
    The public key counterpart to an Curve25519 :class:`nacl.public.PrivateKey`
    for encrypting messages.

    :param public_key: [:class:`bytes`] Encoded Curve25519 public key
    :param encoder: A class that is able to decode the `public_key`

    :cvar SIZE: The size that the public key is required to be
    """

    SIZE = nacl.bindings.crypto_box_PUBLICKEYBYTES

    def __init__(self, public_key, encoder=encoding.RawEncoder):
        self._public_key = encoder.decode(public_key)
        if not isinstance(self._public_key, bytes):
            raise exc.TypeError("PublicKey must be created from 32 bytes")

        if len(self._public_key) != self.SIZE:
            raise exc.ValueError(
                "The public key must be exactly {0} bytes long".format(
                                                                    self.SIZE)
            )

    def __bytes__(self):
        return self._public_key

    def __hash__(self):
        return hash(bytes(self))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other):
        return not (self == other)


class PrivateKey(encoding.Encodable, StringFixer, object):
    """
    Private key for decrypting messages using the Curve25519 algorithm.

    .. warning:: This **must** be protected and remain secret. Anyone who
        knows the value of your :class:`~nacl.public.PrivateKey` can decrypt
        any message encrypted by the corresponding
        :class:`~nacl.public.PublicKey`

    :param private_key: The private key used to decrypt messages
    :param encoder: The encoder class used to decode the given keys

    :cvar SIZE: The size that the private key is required to be
    """

    SIZE = nacl.bindings.crypto_box_SECRETKEYBYTES

    def __init__(self, private_key, encoder=encoding.RawEncoder):
        # Decode the secret_key
        private_key = encoder.decode(private_key)
        if not isinstance(private_key, bytes):
            raise exc.TypeError(
                "PrivateKey must be created from a 32 byte seed")

        # Verify that our seed is the proper size
        if len(private_key) != self.SIZE:
            raise exc.ValueError(
                "The secret key must be exactly %d bytes long" % self.SIZE)

        raw_public_key = nacl.bindings.crypto_scalarmult_base(private_key)

        self._private_key = private_key
        self.public_key = PublicKey(raw_public_key)

    def __bytes__(self):
        return self._private_key

    def __hash__(self):
        return hash(bytes(self))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other):
        return not (self == other)

    @classmethod
    def generate(cls, ext_e=b''):
        """
        Generates a random :class:`~nacl.public.PrivateKey` object

        :param ext_e: Optional external entropy provided by user. XORed with
            system entropy. If empty, only nacl.utils.random() is used.

        :rtype: :class:`~nacl.public.PrivateKey`
        """

        if not isinstance(ext_e, bytes):
            raise TypeError("External entropy provided must be bytes")

        # If no external entropy is provided, create string of zero-bytes.
        if not ext_e:
            ext_e = str(bytearray(PrivateKey.SIZE))

        # Verify that external entropy is the proper size.
        if len(ext_e) != PrivateKey.SIZE:
            raise ValueError(
                "External entropy must be exactly %d bytes long"
                % PrivateKey.SIZE)

        nacl_e = random(PrivateKey.SIZE)

        # XOR nacl.utils.random with ext. entropy / string of zero-bytes.
        final = ''.join(chr(ord(n) ^ ord(e)) for n, e in zip(nacl_e, ext_e))

        return cls(final, encoder=encoding.RawEncoder)

class Box(encoding.Encodable, StringFixer, object):
    """
    The Box class boxes and unboxes messages between a pair of keys

    The ciphertexts generated by :class:`~nacl.public.Box` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param private_key: :class:`~nacl.public.PrivateKey` used to encrypt and
        decrypt messages
    :param public_key: :class:`~nacl.public.PublicKey` used to encrypt and
        decrypt messages

    :cvar NONCE_SIZE: The size that the nonce is required to be.
    """

    NONCE_SIZE = nacl.bindings.crypto_box_NONCEBYTES

    def __init__(self, private_key, public_key):
        if private_key and public_key:
            if ((not isinstance(private_key, PrivateKey) or
                 not isinstance(public_key, PublicKey))):
                raise exc.TypeError("Box must be created from "
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

    def encrypt(self, plaintext, nonce=None, encoder=encoding.RawEncoder):
        """
        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is **VITALLY** important that the nonce is a nonce,
            i.e. it is a number used only once for any given key. If you fail
            to do this, you compromise the privacy of the messages encrypted.

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param nonce: [:class:`bytes`] The nonce to use in the encryption
        :param encoder: The encoder to use to encode the ciphertext
        :rtype: [:class:`nacl.utils.EncryptedMessage`]
        """
        if nonce is None:
            nonce = random(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError("The nonce must be exactly %s bytes long" %
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
        """
        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.
        :rtype: [:class:`bytes`]
        """
        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[:self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE:]

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError("The nonce must be exactly %s bytes long" %
                                 self.NONCE_SIZE)

        plaintext = nacl.bindings.crypto_box_open_afternm(
            ciphertext,
            nonce,
            self._shared_key,
        )

        return plaintext

    def shared_key(self):
        """
        Returns the Curve25519 shared secret, that can then be used as a key in
        other symmetric ciphers.

        .. warning:: It is **VITALLY** important that you use a nonce with your
            symmetric cipher. If you fail to do this, you compromise the
            privacy of the messages encrypted. Ensure that the key length of
            your cipher is 32 bytes.
        :rtype: [:class:`bytes`]
        """

        return self._shared_key
