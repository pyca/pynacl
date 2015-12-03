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

from nacl._sodium import ffi, lib
from nacl.exceptions import CryptoError


crypto_secretbox_KEYBYTES = lib.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES = lib.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES = lib.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES = lib.crypto_secretbox_boxzerobytes()


def crypto_secretbox(message, nonce, key):
    """
    Encrypts and returns the message ``message`` with the secret ``key`` and
    the nonce ``nonce``.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")

    padded = b"\x00" * crypto_secretbox_ZEROBYTES + message
    ciphertext = ffi.new("unsigned char[]", len(padded))

    if lib.crypto_secretbox(ciphertext, padded, len(padded), nonce, key) != 0:
        raise CryptoError("Encryption failed")

    ciphertext = ffi.buffer(ciphertext, len(padded))
    return ciphertext[crypto_secretbox_BOXZEROBYTES:]


def crypto_secretbox_open(ciphertext, nonce, key):
    """
    Decrypt and returns the encrypted message ``ciphertext`` with the secret
    ``key`` and the nonce ``nonce``.

    :param ciphertext: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise ValueError("Invalid nonce")

    padded = b"\x00" * crypto_secretbox_BOXZEROBYTES + ciphertext
    plaintext = ffi.new("unsigned char[]", len(padded))

    if lib.crypto_secretbox_open(
            plaintext, padded, len(padded), nonce, key) != 0:
        raise CryptoError("Decryption failed. Ciphertext failed verification")

    plaintext = ffi.buffer(plaintext, len(padded))
    return plaintext[crypto_secretbox_ZEROBYTES:]
