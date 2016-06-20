# Copyright 2016 Donald Stufft and individual contributors
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

import binascii

import nacl.bindings

from nacl.utils import bytes_as_string

BYTES = nacl.bindings.crypto_generichash_BYTES
BYTES_MIN = nacl.bindings.crypto_generichash_BYTES_MIN
BYTES_MAX = nacl.bindings.crypto_generichash_BYTES_MAX
KEYBYTES = nacl.bindings.crypto_generichash_KEYBYTES
KEYBYTES_MIN = nacl.bindings.crypto_generichash_KEYBYTES_MIN
KEYBYTES_MAX = nacl.bindings.crypto_generichash_KEYBYTES_MAX
SALTBYTES = nacl.bindings.crypto_generichash_SALTBYTES
PERSONALBYTES = nacl.bindings.crypto_generichash_PERSONALBYTES

_b2b_init = nacl.bindings.crypto_generichash_blake2b_init
_b2b_final = nacl.bindings.crypto_generichash_blake2b_final
_b2b_copy = nacl.bindings.crypto_generichash_blake2b_state_copy
_b2b_update = nacl.bindings.crypto_generichash_blake2b_update


class blake2b(object):
    """
    :py:mod:`hashlib` API compatible blake2b algorithm implementation
    """

    def __init__(self, data=b'', digest_size=BYTES, key=b'',
                 salt=b'', personal=b''):
        """
        :py:class:`.blake2b` algorithm initializer

        :param data:
        :type data: bytes
        :param key: the key to be set for keyed MAC/PRF usage; if set,
                    key size should be comprised between
                    :py:data:`.KEYBYTES_MIN` and :py:data:`.KEYBYTES_MAX`
        :type key: bytes
        :param int digest_size: the requested digest size; must be between
                                :py:data:`.BYTES_MIN`
                                and :py:data:`.BYTES_MAX`;
                                the default length is :py:data:`.BYTES`
        :param bytes salt: an initialization salt. It will be
                           zero-padded or truncated up to a length
                           of :py:data:`.SALTBYTES`
        :param bytes personal: a personalization string. It will be
                               zero-padded or truncated up to a length
                               of :py:data:`.PERSONALBYTES`
        """

        self.state = _b2b_init(key=key, salt=salt, personal=personal,
                               digest_size=digest_size)
        self.digest_size = digest_size

        if data:
            self.update(data)

    def update(self, data):
        _b2b_update(self.state, data)

    def digest(self):
        _st = nacl.bindings.crypto_generichash_blake2b_state_copy(self.state)
        return _b2b_final(_st, self.digest_size)

    def hexdigest(self):
        return bytes_as_string(binascii.hexlify(self.digest()))

    def copy(self):
        _cp = type(self)(digest_size=self.digest_size)
        _st = _b2b_copy(self.state)
        _cp.state = _st
        return _cp


class generic(blake2b):
    """
    :py:mod:hashlib API compatible
    libsodium generichash algorithm implementation
    """
    def __init__(self, data=b'', digest_size=BYTES, key=b''):
        """
        :py:class:`.generic` algorithm initializer

        :param bytes data:
        :param key: the key to be set for keyed MAC/PRF usage; if set,
                    key size should be comprised between
                    :py:data:`.KEYBYTES_MIN` and :py:data:`.KEYBYTES_MAX`
        :param int digest_size: the requested digest size; must be between
                                :py:data:BYTES_MIN and :py:data:BYTES_MAX;
                                the default length is :py:data:BYTES
        """
        blake2b.__init__(self, data=data, key=key, digest_size=digest_size)
