# Copyright 2013-2018 Donald Stufft and individual contributors
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

from six import integer_types

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure

crypto_stream_chacha20_KEYBYTES = lib.crypto_stream_chacha20_keybytes()
crypto_stream_chacha20_NONCEBYTES = lib.crypto_stream_chacha20_noncebytes()
crypto_stream_chacha20_MESSAGEBYTES_MAX = \
    lib.crypto_stream_chacha20_messagebytes_max()

crypto_stream_chacha20_ietf_KEYBYTES = \
    lib.crypto_stream_chacha20_ietf_keybytes()
crypto_stream_chacha20_ietf_NONCEBYTES = \
    lib.crypto_stream_chacha20_ietf_noncebytes()
crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX = \
    lib.crypto_stream_chacha20_ietf_messagebytes_max()

has_crypto_stream_xchacha20 = bool(lib.PYNACL_HAS_CRYPTO_STREAM_XCHACHA20)

crypto_stream_xchacha20_KEYBYTES = 0
crypto_stream_xchacha20_NONCEBYTES = 0
crypto_stream_xchacha20_MESSAGEBYTES_MAX = 0

if has_crypto_stream_xchacha20:
    crypto_stream_xchacha20_KEYBYTES = lib.crypto_stream_xchacha20_keybytes()
    crypto_stream_xchacha20_NONCEBYTES = \
        lib.crypto_stream_xchacha20_noncebytes()
    crypto_stream_xchacha20_MESSAGEBYTES_MAX = \
        lib.crypto_stream_xchacha20_messagebytes_max()


def crypto_stream_chacha20_keygen():
    """
    Generate a key for use with chacha20.

    :rtype: bytes

    """
    keybuf = ffi.new("unsigned char[]", crypto_stream_chacha20_KEYBYTES)
    lib.crypto_stream_chacha20_keygen(keybuf)
    return ffi.buffer(keybuf, crypto_stream_chacha20_KEYBYTES)[:]


def crypto_stream_chacha20(clen, nonce, key):
    """
    Generates `clen` pseudorandom bytes using `nonce` and `key`.

    :param clen: int
    :param nonce: bytes
    :param key: bytes

    :rtype: bytes

    """
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_chacha20_NONCEBYTES,
        'Nonce length must be crypto_stream_chacha20_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_chacha20_KEYBYTES,
        'Key length must be crypto_stream_chacha20_KEYBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(clen, integer_types),
        'clen must be an integer.',
        raising=exc.TypeError
    )
    ensure(
        clen <= crypto_stream_chacha20_MESSAGEBYTES_MAX,
        'clen cannot be greater than' +
        'crypto_stream_chacha20_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )

    cbuf = ffi.new("unsigned char[]", clen)
    ret = lib.crypto_stream_chacha20(cbuf, clen, nonce, key)

    ensure(
        ret == 0,
        'Unexepected failure in encryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_chacha20_xor(message, nonce, key):
    """
    Encrypts or decrypts a message using chacha20.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes

    :rtype: bytes

    """
    ensure(
        isinstance(message, bytes),
        'Message must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(message) <= crypto_stream_chacha20_MESSAGEBYTES_MAX,
        'Message cannot be greater than' +
        'crypto_stream_chacha20_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_chacha20_NONCEBYTES,
        'Nonce length must be crypto_stream_chacha20_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_chacha20_KEYBYTES,
        'Key length must be crypto_stream_chacha20_KEYBYTES.',
        raising=exc.ValueError
    )

    clen = len(message)
    cbuf = ffi.new("unsigned char[]", clen)

    ret = lib.crypto_stream_chacha20_xor(cbuf, message, clen, nonce, key)
    ensure(
        ret == 0,
        'Unexpected failure in encryption/decryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_chacha20_xor_ic(message, nonce, ic, key):
    """
    Encrypts or decrypts a message using chacha20 with initial counter `ic`.

    :param message: bytes
    :param nonce: bytes
    :param ic: int
    :param key: bytes

    :rtype: bytes

    """
    ensure(
        isinstance(message, bytes),
        'Message must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(message) <= crypto_stream_chacha20_MESSAGEBYTES_MAX,
        'Message cannot be greater than' +
        'crypto_stream_chacha20_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_chacha20_NONCEBYTES,
        'Nonce length must be crypto_stream_chacha20_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_chacha20_KEYBYTES,
        'Key length must be crypto_stream_chacha20_KEYBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(ic, integer_types),
        'ic must be an integer.',
        raising=exc.TypeError
    )

    clen = len(message)
    cbuf = ffi.new("unsigned char[]", clen)

    ret = lib.crypto_stream_chacha20_xor_ic(
        cbuf, message, clen, nonce, ic, key)
    ensure(
        ret == 0,
        'Unexpected failure in encryption/decryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_chacha20_ietf_keygen():
    """
    Generate a key for use with chacha20_ietf.

    :rtype: bytes

    """
    keybuf = ffi.new("unsigned char[]", crypto_stream_chacha20_ietf_KEYBYTES)
    lib.crypto_stream_chacha20_ietf_keygen(keybuf)
    return ffi.buffer(keybuf, crypto_stream_chacha20_ietf_KEYBYTES)[:]


def crypto_stream_chacha20_ietf(clen, nonce, key):
    """
    Generates `clen` pseudorandom bytes using `nonce` and `key`.

    :param clen: int
    :param nonce: bytes
    :param key: bytes

    :rtype: bytes

    """
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_chacha20_ietf_NONCEBYTES,
        'Nonce length must be crypto_stream_chacha20_ietf_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_chacha20_ietf_KEYBYTES,
        'Key length must be crypto_stream_chacha20_ietf_KEYBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(clen, integer_types),
        'clen must be an integer.',
        raising=exc.TypeError
    )
    ensure(
        clen <= crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX,
        'clen cannot be greater than' +
        'crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )

    cbuf = ffi.new("unsigned char[]", clen)
    ret = lib.crypto_stream_chacha20_ietf(cbuf, clen, nonce, key)

    ensure(
        ret == 0,
        'Unexepected failure in encryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_chacha20_ietf_xor(message, nonce, key):
    """
    Encrypts or decrypts a message using chacha20_ietf.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes

    :rtype: bytes

    """
    ensure(
        isinstance(message, bytes),
        'Message must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(message) <= crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX,
        'Message cannot be greater than' +
        'crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_chacha20_ietf_NONCEBYTES,
        'Nonce length must be crypto_stream_chacha20_ietf_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_chacha20_ietf_KEYBYTES,
        'Key length must be crypto_stream_chacha20_ietf_KEYBYTES.',
        raising=exc.ValueError
    )

    clen = len(message)
    cbuf = ffi.new("unsigned char[]", clen)

    ret = lib.crypto_stream_chacha20_ietf_xor(
        cbuf, message, clen, nonce, key)
    ensure(
        ret == 0,
        'Unexpected failure in encryption/decryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_chacha20_ietf_xor_ic(message, nonce, ic, key):
    """
    Encrypts or decrypts a message using chacha20_ietf
    with initial counter `ic`.

    :param message: bytes
    :param nonce: bytes
    :param ic: int
    :param key: bytes

    :rtype: bytes

    """
    ensure(
        isinstance(message, bytes),
        'Message must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(message) <= crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX,
        'Message cannot be greater than' +
        'crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_chacha20_ietf_NONCEBYTES,
        'Nonce length must be crypto_stream_chacha20_ietf_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_chacha20_ietf_KEYBYTES,
        'Key length must be crypto_stream_chacha20_ietf_KEYBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(ic, integer_types),
        'ic must be an integer.',
        raising=exc.TypeError
    )

    clen = len(message)
    cbuf = ffi.new("unsigned char[]", clen)

    ret = lib.crypto_stream_chacha20_ietf_xor_ic(
        cbuf, message, clen, nonce, ic, key)
    ensure(
        ret == 0,
        'Unexpected failure in encryption/decryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_xchacha20_keygen():
    """
    Generate a key for use with xchacha20.

    :rtype: bytes

    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.

    """
    ensure(
        has_crypto_stream_xchacha20,
        'Not available in minimal build',
        raising=exc.UnavailableError,
    )
    keybuf = ffi.new("unsigned char[]", crypto_stream_xchacha20_KEYBYTES)
    lib.crypto_stream_chacha20_keygen(keybuf)
    return ffi.buffer(keybuf, crypto_stream_xchacha20_KEYBYTES)[:]


def crypto_stream_xchacha20(clen, nonce, key):
    """
    Generates `clen` pseudorandom bytes using `nonce` and `key`.

    :param clen: int
    :param nonce: bytes
    :param key: bytes

    :rtype: bytes

    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.

    """
    ensure(
        has_crypto_stream_xchacha20,
        'Not available in minimal build',
        raising=exc.UnavailableError,
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_xchacha20_NONCEBYTES,
        'Nonce length must be crypto_stream_xchacha20_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_xchacha20_KEYBYTES,
        'Key length must be crypto_stream_xchacha20_KEYBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(clen, integer_types),
        'clen must be an integer.',
        raising=exc.TypeError
    )
    ensure(
        clen <= crypto_stream_xchacha20_MESSAGEBYTES_MAX,
        'clen cannot be greater than' +
        'crypto_stream_xchacha20_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )

    cbuf = ffi.new("unsigned char[]", clen)
    ret = lib.crypto_stream_xchacha20(cbuf, clen, nonce, key)

    ensure(
        ret == 0,
        'Unexepected failure in encryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_xchacha20_xor(message, nonce, key):
    """
    Encrypts or decrypts a message using xchacha20.

    :param message: bytes
    :param nonce: bytes
    :param key: bytes

    :rtype: bytes

    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.

    """
    ensure(
        has_crypto_stream_xchacha20,
        'Not available in minimal build',
        raising=exc.UnavailableError,
    )
    ensure(
        isinstance(message, bytes),
        'Message must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(message) <= crypto_stream_xchacha20_MESSAGEBYTES_MAX,
        'Message cannot be greater than' +
        'crypto_stream_xchacha20_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_xchacha20_NONCEBYTES,
        'Nonce length must be crypto_stream_xchacha20_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_xchacha20_KEYBYTES,
        'Key length must be crypto_stream_xchacha20_KEYBYTES.',
        raising=exc.ValueError
    )

    clen = len(message)
    cbuf = ffi.new("unsigned char[]", clen)
    ret = lib.crypto_stream_xchacha20_xor(cbuf, message, clen, nonce, key)

    ensure(
        ret == 0,
        'Unexpected failure encryption/decryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]


def crypto_stream_xchacha20_xor_ic(message, nonce, ic, key):
    """
    Encrypts or decrypts a message using xchacha20 with initial counter `ic`.

    :param message: bytes
    :param nonce: bytes
    :param ic: int
    :param key: bytes

    :rtype: bytes

    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.

    """
    ensure(
        has_crypto_stream_xchacha20,
        'Not available in minimal build',
        raising=exc.UnavailableError,
    )
    ensure(
        isinstance(message, bytes),
        'Message must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(message) <= crypto_stream_xchacha20_MESSAGEBYTES_MAX,
        'Message cannot be greater than' +
        'crypto_stream_xchacha20_MESSAGEBYTES_MAX.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(nonce, bytes),
        'Nonce must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(nonce) == crypto_stream_xchacha20_NONCEBYTES,
        'Nonce length must be crypto_stream_xchacha20_NONCEBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(key, bytes),
        'Key must be bytes.',
        raising=exc.TypeError
    )
    ensure(
        len(key) == crypto_stream_xchacha20_KEYBYTES,
        'Key length must be crypto_stream_xchacha20_KEYBYTES.',
        raising=exc.ValueError
    )
    ensure(
        isinstance(ic, integer_types),
        'ic must be an integer.',
        raising=exc.TypeError
    )

    clen = len(message)
    cbuf = ffi.new("unsigned char[]", clen)

    ret = lib.crypto_stream_xchacha20_xor_ic(
        cbuf, message, clen, nonce, ic, key)
    ensure(
        ret == 0,
        'Unexpected failure in encryption/decryption',
        raising=exc.CryptoError
    )

    return ffi.buffer(cbuf, clen)[:]
