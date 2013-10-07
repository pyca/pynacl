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
from nacl.exceptions import CryptoError


__all__ = ["crypto_box_keypair", "crypto_box"]


crypto_box_SECRETKEYBYTES = lib.crypto_box_secretkeybytes()
crypto_box_PUBLICKEYBYTES = lib.crypto_box_publickeybytes()
crypto_box_NONCEBYTES = lib.crypto_box_noncebytes()
crypto_box_ZEROBYTES = lib.crypto_box_zerobytes()
crypto_box_BOXZEROBYTES = lib.crypto_box_boxzerobytes()
crypto_box_BEFORENMBYTES = lib.crypto_box_beforenmbytes()


def crypto_box_keypair():
    """
    Returns a randomly generated secret and public key.

    :rtype: (bytes(secret_key), bytes(public_key))
    """
    sk = lib.ffi.new("unsigned char[]", crypto_box_SECRETKEYBYTES)
    pk = lib.ffi.new("unsigned char[]", crypto_box_PUBLICKEYBYTES)

    if lib.crypto_box_keypair(pk, sk) != 0:
        raise CryptoError("An error occurred trying to generate the keypair")

    return (
        lib.ffi.buffer(sk, crypto_box_SECRETKEYBYTES)[:],
        lib.ffi.buffer(pk, crypto_box_PUBLICKEYBYTES)[:],
    )


def crypto_box(sk, pk, message, nonce):
    """
    Encrypts and returns a message ``message`` using the secret key ``sk``,
    public key ``pk``, and the nonce ``nonce``.

    :param sk: bytes
    :param pk: bytes
    :param message: bytes
    :param nonce: bytes
    :rtype: bytes
    """
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")

    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce size")

    padded = (b"\x00" * crypto_box_ZEROBYTES) + message
    ciphertext = lib.ffi.new("unsigned char[]", len(padded))

    if lib.crypto_box(ciphertext, padded, len(padded), nonce, pk, sk) != 0:
        raise CryptoError("An error occurred trying to encrypt the message")

    return lib.ffi.buffer(ciphertext, len(padded))[crypto_box_BOXZEROBYTES:]


def crypto_box_open(sk, pk, ciphertext, nonce):
    """
    Decrypts and returns an encrypted message ``ciphertext``, using the secret
    key ``sk``, public key ``pk``, and the nonce ``nonce``.

    :param sk: bytes
    :param pk: bytes
    :param ciphertext: bytes
    :param nonce: bytes
    :rtype: bytes
    """
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")

    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce size")

    padded = (b"\x00" * crypto_box_BOXZEROBYTES) + ciphertext
    plaintext = lib.ffi.new("unsigned char[]", len(padded))

    if lib.crypto_box_open(plaintext, padded, len(padded), nonce, pk, sk) != 0:
        raise CryptoError("An error occurred trying to decrypt the message")

    return lib.ffi.buffer(plaintext, len(padded))[crypto_box_ZEROBYTES:]


def crypto_box_beforenm(sk, pk):
    """
    Computes and returns the shared key for the secret key ``sk`` and the
    public key ``pk``. This can be used to speed up operations where the same
    set of keys is going to be used multiple times.

    :param sk: bytes
    :param pk: bytes
    :rtype: bytes
    """
    if len(sk) != crypto_box_SECRETKEYBYTES:
        raise ValueError("Invalid secret key")

    if len(pk) != crypto_box_PUBLICKEYBYTES:
        raise ValueError("Invalid public key")

    k = lib.ffi.new("unsigned char[]", crypto_box_BEFORENMBYTES)

    if lib.crypto_box_beforenm(k, pk, sk) != 0:
        raise CryptoError("An error occurred computing the shared key.")

    return lib.ffi.buffer(k, crypto_box_BEFORENMBYTES)[:]


def crypto_box_afternm(k, message, nonce):
    """
    Encrypts and returns the message ``message`` using the shared key ``k`` and
    the nonce ``nonce``.

    :param k: bytes
    :param message: bytes
    :param nonce: bytes
    :rtype: bytes
    """
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError("Invalid shared key")

    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")

    padded = b"\x00" * crypto_box_ZEROBYTES + message
    ciphertext = lib.ffi.new("unsigned char[]", len(padded))

    if lib.crypto_box_afternm(ciphertext, padded, len(padded), nonce, k) != 0:
        raise CryptoError("An error occurred trying to encrypt the message")

    return lib.ffi.buffer(ciphertext, len(padded))[crypto_box_BOXZEROBYTES:]


def crypto_box_open_afternm(k, ciphertext, nonce):
    """
    Decrypts and returns the encrypted message ``ciphertext``, using the shared
    key ``k`` and the nonce ``nonce``.

    :param k: bytes
    :param ciphertext: bytes
    :param nonce: bytes
    :rtype: bytes
    """
    if len(k) != crypto_box_BEFORENMBYTES:
        raise ValueError("Invalid shared key")

    if len(nonce) != crypto_box_NONCEBYTES:
        raise ValueError("Invalid nonce")

    padded = (b"\x00" * crypto_box_BOXZEROBYTES) + ciphertext
    plaintext = lib.ffi.new("unsigned char[]", len(padded))

    if lib.crypto_box_open_afternm(
            plaintext, padded, len(padded), nonce, k) != 0:
        raise CryptoError("An error occurred trying to decrypt the message")

    return lib.ffi.buffer(plaintext, len(padded))[crypto_box_ZEROBYTES:]
