from __future__ import absolute_import
from __future__ import division

from . import nacl
from .encoding import encoder
from .exceptions import CryptoError


def sha256(message, encoding="hex"):
    digest = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_hash_sha256_BYTES)
    if not nacl.lib.crypto_hash_sha256(digest, message, len(message)):
        raise CryptoError("Hashing failed")
    digest = nacl.ffi.buffer(digest, nacl.lib.crypto_hash_sha256_BYTES)[:]

    return encoder[encoding].encode(digest)


def sha512(message, encoding="hex"):
    digest = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_hash_sha512_BYTES)
    if not nacl.lib.crypto_hash_sha512(digest, message, len(message)):
        raise CryptoError("Hashing failed")
    digest = nacl.ffi.buffer(digest, nacl.lib.crypto_hash_sha512_BYTES)[:]

    return encoder[encoding].encode(digest)
