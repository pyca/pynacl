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

from nacl.c import lib
from nacl.exceptions import CryptoError


__all__ = ["crypto_box_keypair", "crypto_box"]


def crypto_box_keypair():
    """
    Returns a randomly generated secret and public key.

    :rtype: (bytes(secret_key), bytes(public_key))
    """
    sk_size = lib.crypto_box_secretkeybytes()
    pk_size = lib.crypto_box_publickeybytes()

    sk = lib.ffi.new("unsigned char[]", sk_size)
    pk = lib.ffi.new("unsigned char[]", pk_size)

    if lib.crypto_box_keypair(pk, sk) != 0:
        raise CryptoError("An error occurred trying to generate the keypair")

    return (lib.ffi.buffer(sk, sk_size)[:], lib.ffi.buffer(pk, pk_size)[:])


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
    sk_size = lib.crypto_box_secretkeybytes()
    pk_size = lib.crypto_box_publickeybytes()
    n_size = lib.crypto_box_noncebytes()
    zero_bytes = lib.crypto_box_zerobytes()
    box_zeros = lib.crypto_box_boxzerobytes()

    if len(sk) != sk_size:
        raise ValueError("Invalid secret key")

    if len(pk) != pk_size:
        raise ValueError("Invalid public key")

    if len(nonce) != n_size:
        raise ValueError("Invalid nonce size")

    padded = (b"\x00" * zero_bytes) + message
    ciphertext = lib.ffi.new("unsigned char[]", len(padded))

    if lib.crypto_box(ciphertext, message, len(message), nonce, pk, sk) != 0:
        raise CryptoError("An error occurred trying to encrypt the message")

    return lib.ffi.buffer(ciphertext, len(padded))[box_zeros:]


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
    sk_size = lib.crypto_box_secretkeybytes()
    pk_size = lib.crypto_box_publickeybytes()
    n_size = lib.crypto_box_noncebytes()
    box_zeros = lib.crypto_box_boxzerobytes()
    zero_bytes = lib.crypto_box_zerobytes()

    if len(sk) != sk_size:
        raise ValueError("Invalid secret key")

    if len(pk) != pk_size:
        raise ValueError("Invalid public key")

    if len(nonce) != n_size:
        raise ValueError("Invalid nonce size")

    padded = (b"\x00" * box_zeros) + ciphertext
    plaintext = lib.ffi.new("unsigned char[]", len(padded))

    if lib.crypto_box_open(
            plaintext, ciphertext, len(ciphertext), nonce, pk, sk):
        raise CryptoError("An error occurred trying to decrypt the message")

    return lib.ffi.buffer(plaintext, len(padded))[zero_bytes:]
