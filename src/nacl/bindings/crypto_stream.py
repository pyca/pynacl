# Copyright 2026 Donald Stufft and individual contributors
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

crypto_stream_KEYBYTES: int = lib.crypto_stream_keybytes()
crypto_stream_NONCEBYTES: int = lib.crypto_stream_noncebytes()
crypto_stream_MESSAGEBYTES_MAX: int = lib.crypto_stream_messagebytes_max()


def _checkparams(nonce: bytes, key: bytes) -> None:
    """Check stream key and nonce parameters"""
    ensure(
        isinstance(nonce, bytes),
        "Nonce must be a bytes sequence",
        raising=exc.TypeError,
    )

    ensure(
        isinstance(key, bytes),
        "Key must be a bytes sequence",
        raising=exc.TypeError,
    )

    ensure(
        len(key) == crypto_stream_KEYBYTES,
        "Invalid key length",
        raising=exc.ValueError,
    )

    ensure(
        len(nonce) == crypto_stream_NONCEBYTES,
        "Invalid nonce length",
        raising=exc.ValueError,
    )


def crypto_stream(length: int, nonce: bytes, key: bytes) -> bytes:
    """
    Generate and return ``length`` bytes of the XSalsa20 keystream for the
    given ``key`` and ``nonce``.

    :param length: int
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    _checkparams(nonce, key)

    ensure(
        isinstance(length, int),
        "Length must be an integer number",
        raising=exc.TypeError,
    )

    ensure(
        length >= 0,
        "Length must be non-negative",
        raising=exc.ValueError,
    )

    ensure(
        length <= crypto_stream_MESSAGEBYTES_MAX,
        "Length is too long",
        raising=exc.ValueError,
    )

    keystream = ffi.new("unsigned char[]", length)

    res = lib.crypto_stream(keystream, length, nonce, key)
    ensure(res == 0, "Keystream generation failed", raising=exc.CryptoError)

    return ffi.buffer(keystream, length)[:]


def crypto_stream_xor(message: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Encrypt and return ``message`` by XORing it with the XSalsa20 keystream
    derived from ``key`` and ``nonce``. Applying this function a second time
    to the result with the same ``key`` and ``nonce`` recovers the original
    ``message``.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes
    :rtype: bytes
    """
    _checkparams(nonce, key)

    ensure(
        isinstance(message, bytes),
        "Message must be a bytes sequence",
        raising=exc.TypeError,
    )

    ensure(
        len(message) <= crypto_stream_MESSAGEBYTES_MAX,
        "Message is too long",
        raising=exc.ValueError,
    )

    ciphertext = ffi.new("unsigned char[]", len(message))

    res = lib.crypto_stream_xor(ciphertext, message, len(message), nonce, key)
    ensure(res == 0, "Encryption failed", raising=exc.CryptoError)

    return ffi.buffer(ciphertext, len(message))[:]


def crypto_stream_keygen() -> bytes:
    """
    Generate a random key for use with :func:`crypto_stream_xor`.

    :rtype: bytes
    """
    keybuf = ffi.new("unsigned char[]", crypto_stream_KEYBYTES)
    lib.crypto_stream_keygen(keybuf)
    return ffi.buffer(keybuf)[:]
