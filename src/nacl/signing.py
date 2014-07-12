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

import six

import nacl.c

from . import encoding
from .utils import StringFixer, random


class SignedMessage(six.binary_type):

    @classmethod
    def _from_parts(cls, signature, message, combined):
        obj = cls(combined)
        obj._signature = signature
        obj._message = message
        return obj

    @property
    def signature(self):
        return self._signature

    @property
    def message(self):
        return self._message


class VerifyKey(encoding.Encodable, StringFixer, object):

    def __init__(self, key, encoder=encoding.RawEncoder):
        # Decode the key
        key = encoder.decode(key)

        if len(key) != nacl.c.crypto_sign_PUBLICKEYBYTES:
            raise ValueError(
                "The key must be exactly %s bytes long" %
                nacl.c.crypto_sign_PUBLICKEYBYTES,
            )

        self._key = key

    def __bytes__(self):
        return self._key

    def verify(self, smessage, signature=None, encoder=encoding.RawEncoder):
        if signature is not None:
            # If we were given the message and signature separately, combine
            #   them.
            smessage = signature + smessage

        # Decode the signed message
        smessage = encoder.decode(smessage)

        return nacl.c.crypto_sign_open(smessage, self._key)


class SigningKey(encoding.Encodable, StringFixer, object):

    def __init__(self, seed, encoder=encoding.RawEncoder):
        # Decode the seed
        seed = encoder.decode(seed)

        # Verify that our seed is the proper size
        if len(seed) != nacl.c.crypto_sign_SEEDBYTES:
            raise ValueError(
                "The seed must be exactly %d bytes long" %
                nacl.c.crypto_sign_SEEDBYTES
            )

        public_key, secret_key = nacl.c.crypto_sign_seed_keypair(seed)

        self._seed = seed
        self._signing_key = secret_key
        self.verify_key = VerifyKey(public_key)

    def __bytes__(self):
        return self._seed

    @classmethod
    def generate(cls):
        return cls(
            random(nacl.c.crypto_sign_SEEDBYTES),
            encoder=encoding.RawEncoder,
        )

    def sign(self, message, encoder=encoding.RawEncoder):
        raw_signed = nacl.c.crypto_sign(message, self._signing_key)

        signature = encoder.encode(raw_signed[:nacl.c.crypto_sign_BYTES])
        message = encoder.encode(raw_signed[nacl.c.crypto_sign_BYTES:])
        signed = encoder.encode(raw_signed)

        return SignedMessage._from_parts(signature, message, signed)
