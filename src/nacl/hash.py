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
from __future__ import absolute_import
from __future__ import division

from . import encoding
from .c import _lib as nacl
from .exceptions import CryptoError


def sha256(message, encoder=encoding.HexEncoder):
    digest = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_hash_sha256_BYTES)
    if not nacl.lib.crypto_hash_sha256(digest, message, len(message)):
        raise CryptoError("Hashing failed")
    digest = nacl.ffi.buffer(digest, nacl.lib.crypto_hash_sha256_BYTES)[:]

    return encoder.encode(digest)


def sha512(message, encoder=encoding.HexEncoder):
    digest = nacl.ffi.new("unsigned char[]", nacl.lib.crypto_hash_sha512_BYTES)
    if not nacl.lib.crypto_hash_sha512(digest, message, len(message)):
        raise CryptoError("Hashing failed")
    digest = nacl.ffi.buffer(digest, nacl.lib.crypto_hash_sha512_BYTES)[:]

    return encoder.encode(digest)