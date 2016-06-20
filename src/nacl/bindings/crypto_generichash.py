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

crypto_generichash_BYTES = lib.crypto_generichash_blake2b_bytes()
crypto_generichash_BYTES_MIN = lib.crypto_generichash_blake2b_bytes_min()
crypto_generichash_BYTES_MAX = lib.crypto_generichash_blake2b_bytes_max()
crypto_generichash_KEYBYTES = lib.crypto_generichash_blake2b_keybytes()
crypto_generichash_KEYBYTES_MIN = lib.crypto_generichash_blake2b_keybytes_min()
crypto_generichash_KEYBYTES_MAX = lib.crypto_generichash_blake2b_keybytes_max()
crypto_generichash_SALTBYTES = lib.crypto_generichash_blake2b_saltbytes()
crypto_generichash_PERSONALBYTES = \
    lib.crypto_generichash_blake2b_personalbytes()
crypto_generichash_STATEBYTES = lib.crypto_generichash_statebytes()


def generichash_blake2b_salt_personal(data,
                                      digest_size=crypto_generichash_BYTES,
                                      key=b'', salt=b'', personal=b''):
    """One time hash interface"""
    digest = ffi.new("unsigned char[]", digest_size)
    _salt = ffi.new("char []", crypto_generichash_SALTBYTES)
    _personal = ffi.new("char []", crypto_generichash_PERSONALBYTES)

    ffi.memmove(_salt, salt, min(len(salt), crypto_generichash_SALTBYTES))
    ffi.memmove(_personal, personal,
                min(len(personal), crypto_generichash_PERSONALBYTES)
                )
    # _salt and _personal will be truncated or zero-padded
    # to the correct length

    rc = lib.crypto_generichash_blake2b_salt_personal(digest, digest_size,
                                                      data, len(data),
                                                      key, len(key),
                                                      _salt, _personal)
    assert rc == 0
    return ffi.buffer(digest, digest_size)[:]


def generichash_blake2b_init(key=b'', salt=b'',
                             personal=b'',
                             digest_size=crypto_generichash_BYTES):
    """
    Create a new initialized blake2b hash state

    :param key: len(key) must be comprised between
                :py:data:`.crypto_generichash_KEYBYTES_MIN` and
                :py:data:`.crypto_generichash_KEYBYTES_MAX`
    :type key: bytes
    :param salt: will be zero-padded or truncated to
                 :py:data:`.crypto_generichash_SALTBYTES`
    :type salt: bytes
    :param personal: will be zero-padded or truncated to
                    :py:data:`.crypto_generichash_PERSONALBYTES`
    :type personal: bytes
    :param digest_size: must be comprised between
                        :py:data:`.crypto_generichash_BYTES_MIN`
                        and :py:data:`.crypto_generichash_BYTES_MAX`;
                        the default value is
                        :py:data:`.crypto_generichash_BYTES`
    :type digest_size: int
    :return: an initizialized state buffer
    :rtype: bytes
    """

    statebuf = ffi.new("unsigned char[]", crypto_generichash_STATEBYTES)
    _state = ffi.cast("struct crypto_generichash_blake2b_state *", statebuf)

    _salt = ffi.new("char []", crypto_generichash_SALTBYTES)
    _personal = ffi.new("char []", crypto_generichash_PERSONALBYTES)

    ffi.memmove(_salt, salt, min(len(salt), crypto_generichash_SALTBYTES))
    ffi.memmove(_personal, personal,
                min(len(personal), crypto_generichash_PERSONALBYTES)
                )

    rc = lib.crypto_generichash_blake2b_init_salt_personal(_state,
                                                           key, len(key),
                                                           digest_size,
                                                           _salt, _personal)
    assert rc == 0
    return statebuf


def generichash_blake2b_update(statebuf, data):
    """Update the blake2b hash state

    :param statebuf: an initialized blake2b state buffer as returned from
                     :py:func:`.crypto_generichash_blake2b_init`
    :type name: bytes
    :param data:
    :type data: bytes
    """

    _state = ffi.cast("struct crypto_generichash_blake2b_state *", statebuf)

    rc = lib.crypto_generichash_blake2b_update(_state, data, len(data))
    assert rc == 0


def generichash_blake2b_final(statebuf, digest_size):
    """Finalize the blake2b hash state and return the digest.

    :param statebuf:
    :type statebuf: bytes
    :param digest_size:
    :type digest_size: int
    :return: the blake2 digest of the passed-in data stream
    :rtype: bytes
    """

    _digest = ffi.new("unsigned char[]", crypto_generichash_BYTES_MAX)
    _state = ffi.cast("struct crypto_generichash_blake2b_state *", statebuf)
    rc = lib.crypto_generichash_blake2b_final(_state, _digest, digest_size)

    assert rc == 0
    return ffi.buffer(_digest, digest_size)[:]


def generichash_blake2b_state_copy(statebuf):
    """Return a copy of the given blake2b hash state"""

    _statebuf = ffi.new("unsigned char[]", crypto_generichash_STATEBYTES)
    ffi.memmove(_statebuf, statebuf, crypto_generichash_STATEBYTES)

    return _statebuf
