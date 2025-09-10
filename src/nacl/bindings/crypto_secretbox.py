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


from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


crypto_secretbox_KEYBYTES: int = lib.crypto_secretbox_keybytes()
crypto_secretbox_NONCEBYTES: int = lib.crypto_secretbox_noncebytes()
crypto_secretbox_ZEROBYTES: int = lib.crypto_secretbox_zerobytes()
crypto_secretbox_BOXZEROBYTES: int = lib.crypto_secretbox_boxzerobytes()
crypto_secretbox_MACBYTES: int = lib.crypto_secretbox_macbytes()
crypto_secretbox_MESSAGEBYTES_MAX: int = (
    lib.crypto_secretbox_messagebytes_max()
)


def crypto_secretbox(message: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Encrypts and returns the message ``message`` with the secret ``key`` and
    the nonce ``nonce``.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise exc.ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise exc.ValueError("Invalid nonce")

    nonce = ffi.from_buffer(nonce)
    key = ffi.from_buffer(key)

    padded = b"\x00" * crypto_secretbox_ZEROBYTES + message
    ciphertext = ffi.new("unsigned char[]", len(padded))

    res = lib.crypto_secretbox(ciphertext, padded, len(padded), nonce, key)
    ensure(res == 0, "Encryption failed", raising=exc.CryptoError)

    ciphertext = ffi.buffer(ciphertext, len(padded))
    return ciphertext[crypto_secretbox_BOXZEROBYTES:]


def crypto_secretbox_open(
    ciphertext: bytes, nonce: bytes, key: bytes
) -> bytes:
    """
    Decrypt and returns the encrypted message ``ciphertext`` with the secret
    ``key`` and the nonce ``nonce``.

    :param ciphertext: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise exc.ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise exc.ValueError("Invalid nonce")

    nonce = ffi.from_buffer(nonce)
    key = ffi.from_buffer(key)

    padded = b"\x00" * crypto_secretbox_BOXZEROBYTES + ciphertext
    plaintext = ffi.new("unsigned char[]", len(padded))

    res = lib.crypto_secretbox_open(plaintext, padded, len(padded), nonce, key)
    ensure(
        res == 0,
        "Decryption failed. Ciphertext failed verification",
        raising=exc.CryptoError,
    )

    plaintext = ffi.buffer(plaintext, len(padded))
    return plaintext[crypto_secretbox_ZEROBYTES:]


def crypto_secretbox_easy(message: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Encrypts and returns the message ``message`` with the secret ``key`` and
    the nonce ``nonce``.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise exc.ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise exc.ValueError("Invalid nonce")

    _mlen = len(message)
    _clen = crypto_secretbox_MACBYTES + _mlen

    ciphertext = ffi.new("unsigned char[]", _clen)

    res = lib.crypto_secretbox_easy(ciphertext, message, _mlen, nonce, key)
    ensure(res == 0, "Encryption failed", raising=exc.CryptoError)

    ciphertext = ffi.buffer(ciphertext, _clen)
    return ciphertext[:]


def crypto_secretbox_open_easy(
    ciphertext: bytes, nonce: bytes, key: bytes
) -> bytes:
    """
    Decrypt and returns the encrypted message ``ciphertext`` with the secret
    ``key`` and the nonce ``nonce``.

    :param ciphertext: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    if len(key) != crypto_secretbox_KEYBYTES:
        raise exc.ValueError("Invalid key")

    if len(nonce) != crypto_secretbox_NONCEBYTES:
        raise exc.ValueError("Invalid nonce")

    _clen = len(ciphertext)

    ensure(
        _clen >= crypto_secretbox_MACBYTES,
        "Input ciphertext must be at least {} long".format(
            crypto_secretbox_MACBYTES
        ),
        raising=exc.TypeError,
    )

    _mlen = _clen - crypto_secretbox_MACBYTES

    plaintext = ffi.new("unsigned char[]", max(1, _mlen))

    res = lib.crypto_secretbox_open_easy(
        plaintext, ciphertext, _clen, nonce, key
    )
    ensure(
        res == 0,
        "Decryption failed. Ciphertext failed verification",
        raising=exc.CryptoError,
    )

    plaintext = ffi.buffer(plaintext, _mlen)
    return plaintext[:]
