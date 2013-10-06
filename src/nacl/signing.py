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
from __future__ import absolute_import
from __future__ import division

from . import six

from . import nacl, encoding
from .exceptions import CryptoError
from .utils import random


class BadSignatureError(CryptoError):
    """
    Raised when the signature was forged or otherwise corrupt.
    """


class SignedMessage(six.binary_type):
    """
    A bytes subclass that holds a messaged that has been signed by a
    :class:`SigningKey`.
    """

    @classmethod
    def _from_parts(cls, signature, message, combined):
        obj = cls(combined)
        obj._signature = signature
        obj._message = message
        return obj

    @property
    def signature(self):
        """
        The signature contained within the :class:`SignedMessage`.
        """
        return self._signature

    @property
    def message(self):
        """
        The message contained within the :class:`SignedMessage`.
        """
        return self._message


class VerifyKey(encoding.Encodable, six.StringFixer, object):
    """
    The public key counterpart to an Ed25519 SigningKey for producing digital
    signatures.

    :param key: [:class:`bytes`] Serialized Ed25519 public key
    :param encoder: A class that is able to decode the `key`
    """

    def __init__(self, key, encoder=encoding.RawEncoder):
        # Decode the key
        key = encoder.decode(key)

        if len(key) != nacl.lib.crypto_sign_PUBLICKEYBYTES:
            raise ValueError("The key must be exactly %s bytes long" %
                                nacl.lib.crypto_sign_PUBLICKEYBYTES)

        self._key = key

    def __bytes__(self):
        return self._key

    def verify(self, smessage, signature=None, encoder=encoding.RawEncoder):
        """
        Verifies the signature of a signed message, returning the message
        if it has not been tampered with else raising
        :class:`~nacl.signing.BadSignatureError`.

        :param smessage: [:class:`bytes`] Either the original messaged or a
            signature and message concated together.
        :param signature: [:class:`bytes`] If an unsigned message is given for
            smessage then the detached signature must be provded.
        :param encoder: A class that is able to decode the secret message and
            signature.
        :rtype: :class:`bytes`
        """
        if signature is not None:
            # If we were given the message and signature separately, combine
            #   them.
            smessage = signature + smessage

        # Decode the signed message
        smessage = encoder.decode(smessage)

        message = nacl.ffi.new("unsigned char[]", len(smessage))
        message_len = nacl.ffi.new("unsigned long long *")

        if not nacl.lib.crypto_sign_open(message, message_len, smessage, len(smessage), self._key):
            raise BadSignatureError("Signature was forged or corrupt")

        return nacl.ffi.buffer(message, message_len[0])[:]


class SigningKey(encoding.Encodable, six.StringFixer, object):
    """
    Private key for producing digital signatures using the Ed25519 algorithm.

    Signing keys are produced from a 32-byte (256-bit) random seed value. This
    value can be passed into the :class:`~nacl.signing.SigningKey` as a
    :func:`bytes` whose length is 32.

    .. warning:: This **must** be protected and remain secret. Anyone who knows
        the value of your :class:`~nacl.signing.SigningKey` or it's seed can
        masquerade as you.

    :param seed: [:class:`bytes`] Random 32-byte value (i.e. private key)
    :param encoder: A class that is able to decode the seed

    :ivar: verify_key: [:class:`~nacl.signing.VerifyKey`] The verify
        (i.e. public) key that corresponds with this signing key.
    """

    def __init__(self, seed, encoder=encoding.RawEncoder):
        # Decode the seed
        seed = encoder.decode(seed)

        # Verify that our seed is the proper size
        seed_size = nacl.lib.crypto_sign_SECRETKEYBYTES // 2
        if len(seed) != seed_size:
            raise ValueError(
                'The seed must be exactly %d bytes long' % (seed_size,))

        pk = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_sign_PUBLICKEYBYTES)
        sk = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_sign_SECRETKEYBYTES)

        if not nacl.lib.crypto_sign_seed_keypair(pk, sk, seed):
            raise CryptoError("Failed to generate a key pair")

        # Secret values
        self._seed = seed
        self._signing_key = nacl.ffi.buffer(sk, nacl.lib.crypto_sign_SECRETKEYBYTES)[:]

        # Public values
        self.verify_key = VerifyKey(nacl.ffi.buffer(pk, nacl.lib.crypto_sign_PUBLICKEYBYTES)[:])

    def __bytes__(self):
        return self._seed

    @classmethod
    def generate(cls):
        """
        Generates a random :class:`~nacl.signing.SingingKey` object.

        :rtype: :class:`~nacl.signing.SigningKey`
        """
        return cls(random(nacl.lib.crypto_sign_SECRETKEYBYTES // 2),
                    encoder=encoding.RawEncoder,
                )

    def sign(self, message, encoder=encoding.RawEncoder):
        """
        Sign a message using this key.

        :param message: [:class:`bytes`] The data to be signed.
        :param encoder: A class that is used to encode the signed message.
        :rtype: :class:`~nacl.signing.SignedMessage`
        """
        sm = nacl.ffi.new("unsigned char[]", len(message) + nacl.lib.crypto_sign_BYTES)
        smlen = nacl.ffi.new("unsigned long long *")

        if not nacl.lib.crypto_sign(sm, smlen, message, len(message), self._signing_key):
            raise CryptoError("Failed to sign the message")

        raw_signed = nacl.ffi.buffer(sm, smlen[0])[:]

        signature = encoder.encode(raw_signed[:nacl.lib.crypto_sign_BYTES])
        message = encoder.encode(raw_signed[nacl.lib.crypto_sign_BYTES:])
        signed = encoder.encode(raw_signed)

        return SignedMessage._from_parts(signature, message, signed)
