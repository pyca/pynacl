# Copyright 2018 Pablo Martinez and individual contributors
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

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure

crypto_stream_chacha20_KEYBYTES = lib.crypto_stream_chacha20_keybytes()
crypto_stream_chacha20_NONCEBYTES = lib.crypto_stream_chacha20_noncebytes()
crypto_stream_chacha20_MESSAGEBYTES_MAX = lib.crypto_stream_chacha20_messagebytes_max()
crypto_stream_chacha20_ietf_KEYBYTES = lib.crypto_stream_chacha20_ietf_keybytes()
crypto_stream_chacha20_ietf_NONCEBYTES = lib.crypto_stream_chacha20_ietf_noncebytes()
crypto_stream_chacha20_ietf_MESSAGEBYTES = lib.crypto_stream_chacha20_ietf_messagebytes_max()


def crypto_stream_chacha20_xor(message, nonce, key):
    ensure(isinstance(message, bytes),
        raising=exc.TypeError)
    ensure(isinstance(nonce, bytes),
        raising=exc.TypeError)
    ensure(isinstance(key, bytes),
        raising=exc.TypeError)

    outlen = len(message)
    outbuf = ffi.new("unsigned char[]", outlen)
    ret = lib.crypto_stream_chacha20_xor(outbuf, message, outlen, nonce, key)
    
    ensure(ret == 0, 'Unexpected failure in key derivation',
           raising=exc.RuntimeError)

    return ffi.buffer(outbuf, outlen)[:]

def crypto_stream_keygen():
    outbuf = ffi.new("unsigned char[]", crypto_stream_chacha20_KEYBYTES)
    ret = lib.crypto_stream_chacha20_keygen(outbuf)
    
    ensure(ret == 0, 'Unexpected failure in key derivation',
           raising=exc.RuntimeError)

    return ffi.buffer(outbuf, crypto_stream_chacha20_KEYBYTES)[:]