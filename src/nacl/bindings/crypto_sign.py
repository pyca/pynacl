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

from nacl._lib import lib
from nacl.exceptions import BadSignatureError, CryptoError


crypto_sign_BYTES = lib.crypto_sign_bytes()
# crypto_sign_SEEDBYTES = lib.crypto_sign_seedbytes()
crypto_sign_SEEDBYTES = lib.crypto_sign_secretkeybytes() // 2
crypto_sign_PUBLICKEYBYTES = lib.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = lib.crypto_sign_secretkeybytes()


def crypto_sign_keypair():
    """
    Returns a randomly generated public key and secret key.

    :rtype: (bytes(public_key), bytes(secret_key))
    """
    pk = lib.ffi.new("unsigned char[]", crypto_sign_PUBLICKEYBYTES)
    sk = lib.ffi.new("unsigned char[]", crypto_sign_SECRETKEYBYTES)

    if lib.crypto_sign_keypair(pk, sk) != 0:
        raise CryptoError("An error occurred while generating keypairs")

    return (
        lib.ffi.buffer(pk, crypto_sign_PUBLICKEYBYTES)[:],
        lib.ffi.buffer(sk, crypto_sign_SECRETKEYBYTES)[:],
    )


def crypto_sign_seed_keypair(seed):
    """
    Computes and returns the public key and secret key using the seed ``seed``.

    :param seed: bytes
    :rtype: (bytes(public_key), bytes(secret_key))
    """
    if len(seed) != crypto_sign_SEEDBYTES:
        raise ValueError("Invalid seed")

    pk = lib.ffi.new("unsigned char[]", crypto_sign_PUBLICKEYBYTES)
    sk = lib.ffi.new("unsigned char[]", crypto_sign_SECRETKEYBYTES)

    if lib.crypto_sign_seed_keypair(pk, sk, seed) != 0:
        raise CryptoError("An error occurred while generating keypairs")

    return (
        lib.ffi.buffer(pk, crypto_sign_PUBLICKEYBYTES)[:],
        lib.ffi.buffer(sk, crypto_sign_SECRETKEYBYTES)[:],
    )


def crypto_sign(message, sk):
    """
    Signs the message ``message`` using the secret key ``sk`` and returns the
    signed message.

    :param message: bytes
    :param sk: bytes
    :rtype: bytes
    """
    signed = lib.ffi.new("unsigned char[]", len(message) + crypto_sign_BYTES)
    signed_len = lib.ffi.new("unsigned long long *")

    if lib.crypto_sign(signed, signed_len, message, len(message), sk) != 0:
        raise CryptoError("Failed to sign the message")

    return lib.ffi.buffer(signed, signed_len[0])[:]


def crypto_sign_open(signed, pk):
    """
    Verifies the signature of the signed message ``signed`` using the public
    key ``pk`` and returns the unsigned message.

    :param signed: bytes
    :param pk: bytes
    :rtype: bytes
    """
    message = lib.ffi.new("unsigned char[]", len(signed))
    message_len = lib.ffi.new("unsigned long long *")

    if lib.crypto_sign_open(
            message, message_len, signed, len(signed), pk) != 0:
        raise BadSignatureError("Signature was forged or corrupt")

    return lib.ffi.buffer(message, message_len[0])[:]
