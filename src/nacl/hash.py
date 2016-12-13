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

import nacl.bindings
import nacl.encoding

BYTES = nacl.bindings.crypto_generichash_BYTES
BYTES_MIN = nacl.bindings.crypto_generichash_BYTES_MIN
BYTES_MAX = nacl.bindings.crypto_generichash_BYTES_MAX
KEYBYTES = nacl.bindings.crypto_generichash_KEYBYTES
KEYBYTES_MIN = nacl.bindings.crypto_generichash_KEYBYTES_MIN
KEYBYTES_MAX = nacl.bindings.crypto_generichash_KEYBYTES_MAX
SALTBYTES = nacl.bindings.crypto_generichash_SALTBYTES
PERSONALBYTES = nacl.bindings.crypto_generichash_PERSONALBYTES

_b2b_hash = nacl.bindings.crypto_generichash_blake2b_salt_personal


def sha256(message, encoder=nacl.encoding.HexEncoder):
    return encoder.encode(nacl.bindings.crypto_hash_sha256(message))


def sha512(message, encoder=nacl.encoding.HexEncoder):
    return encoder.encode(nacl.bindings.crypto_hash_sha512(message))


def generichash(data, digest_size=BYTES, key=b'',
                encoder=nacl.encoding.HexEncoder):
    """
    One-shot generichash digest

    :param data:
    :type data: bytes
    :param digest_size: the requested digest size; must be between
                        :py:data:`.BYTES_MIN` and :py:data:`.BYTES_MAX`;
                        the default length is :py:data:`.BYTES`
    :type digest_size: int
    :param key: the key to be set for keyed MAC/PRF usage; if set, key size
                should be comprised between :py:data:`.KEYBYTES_MIN`
                and :py:data:`.KEYBYTES_MAX`
    :type key: bytes
    :param encoder: the encoder to use on returned digest
    :type encoder: :py:data:`types.FunctionType`
    :return: the encoded digest of input data
    :rtype: the return type of `encoder`
    """

    digest = _b2b_hash(data, digest_size=digest_size, key=key)
    return encoder.encode(digest)


def blake2b(data, digest_size=BYTES, key=b'',
            salt=b'', personal=b'',
            encoder=nacl.encoding.HexEncoder):
    """
    One-shot blake2b digest

    :param data: the digest input byte sequence
    :type data: bytes
    :param digest_size: the requested digest size; must be between
                        :py:data:`.BYTES_MIN` and :py:data:`.BYTES_MAX`;
                        the default length is :py:data:`.BYTES`
    :type digest_size: int
    :param key: the key to be set for keyed MAC/PRF usage; if set, key size
                should be comprised between :py:data:`.KEYBYTES_MIN`
                and :py:data:`.KEYBYTES_MAX`
    :type key: bytes
    :param salt: an initialization salt of lenght :py:data:`.SALTBYTES`.
                 It will be zero-padded or truncated if needed.
    :type salt: bytes
    :param personal: a personalization string of lenght
                     :py:data:`.PERSONALBYTES`. It will be zero-padded
                     or truncated if needed.
    :type personal: bytes
    :param encoder: the encoder to use on returned digest
    :type encoder: :py:data:`types.FunctionType`
    :return: encoded bytes data
    :rtype: the return type of the choosen encoder
    """

    digest = _b2b_hash(data, digest_size=digest_size, key=key,
                       salt=salt, personal=personal)
    return encoder.encode(digest)
