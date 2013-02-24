from __future__ import absolute_import
from __future__ import division

import binascii

from . import nacl
from .exceptions import CryptoError


def sha256(message, binary=False):
    digest = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_hash_sha256_BYTES)
    if not nacl.lib.crypto_hash_sha256(digest, message, len(message)):
        raise CryptoError("Hashing failed")
    digest = nacl.ffi.buffer(digest, nacl.lib.crypto_hash_sha256_BYTES)[:]

    if binary:
        return digest
    return binascii.hexlify(digest)


def sha512(message, binary=False):
    digest = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_hash_sha512_BYTES)
    if not nacl.lib.crypto_hash_sha512(digest, message, len(message)):
        raise CryptoError("Hashing failed")
    digest = nacl.ffi.buffer(digest, nacl.lib.crypto_hash_sha512_BYTES)[:]

    if binary:
        return digest
    return binascii.hexlify(digest)
