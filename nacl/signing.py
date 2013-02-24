from __future__ import division

from . import six

from . import nacl
from .exceptions import CryptoError
from .random import random


class SignedMessage(six.binary_type):

    @property
    def signature(self):
        return self[:nacl.lib.crypto_sign_BYTES]

    @property
    def message(self):
        return self[nacl.lib.crypto_sign_BYTES:]


class SigningKey(object):

    def __init__(self, seed):
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

    @classmethod
    def generate(cls):
        return cls(random(nacl.lib.crypto_sign_SECRETKEYBYTES // 2))

    def sign(self, message):
        sm = nacl.ffi.new("unsigned char[]", len(message) + nacl.lib.crypto_sign_BYTES)
        smlen = nacl.ffi.new("unsigned long long *")

        if not nacl.lib.crypto_sign(sm, smlen, message, len(message), self._signing_key):
            raise CryptoError("Failed to sign the message")

        return SignedMessage(nacl.ffi.buffer(sm, smlen[0])[:])
