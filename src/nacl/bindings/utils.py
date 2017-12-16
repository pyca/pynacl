# Copyright 2013-2017 Donald Stufft and individual contributors
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

import nacl.exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


def sodium_memcmp(inp1, inp2):
    """
    Compare contents of two memory regions in constant time
    """
    ensure(isinstance(inp1, bytes),
           raising=exc.TypeError)
    ensure(isinstance(inp2, bytes),
           raising=exc.TypeError)

    ln = max(len(inp1), len(inp2))

    buf1 = ffi.new("char []", ln)
    buf2 = ffi.new("char []", ln)

    ffi.memmove(buf1, inp1, len(inp1))
    ffi.memmove(buf2, inp2, len(inp2))

    eqL = len(inp1) == len(inp2)
    eqC = lib.sodium_memcmp(buf1, buf2, ln) == 0

    return eqL and eqC


def sodium_pad(s, blocksize):
    """
    Pad the input bytearray ``s`` to a multiple of ``blocksize``
    using the ISO/IEC 7816-4 algorithm

    :param s: input bytes string
    :type s: bytes
    :param blocksize:
    :type blocksize: int
    :return: padded string
    :rtype: bytes
    """
    ensure(isinstance(s, bytes),
           raising=exc.TypeError)
    ensure(isinstance(blocksize, integer_types),
           raising=exc.TypeError)
    if blocksize <= 0:
        raise exc.ValueError
    s_len = len(s)
    m_len = s_len + blocksize
    buf = ffi.new("unsigned char []", m_len)
    p_len = ffi.new("size_t []", 1)
    ffi.memmove(buf, s, s_len)
    rc = lib.sodium_pad(p_len, buf, s_len, blocksize, m_len)
    ensure(rc == 0, "Padding failure", raising=exc.CryptoError)
    return ffi.buffer(buf, p_len[0])[:]


def sodium_unpad(s, blocksize):
    """
    Remove ISO/IEC 7816-4 padding from the input byte array ``s``

    :param s: input bytes string
    :type s: bytes
    :param blocksize:
    :type blocksize: int
    :return: unpadded string
    :rtype: bytes
    """
    ensure(isinstance(s, bytes),
           raising=exc.TypeError)
    ensure(isinstance(blocksize, integer_types),
           raising=exc.TypeError)
    s_len = len(s)
    u_len = ffi.new("size_t []", 1)
    rc = lib.sodium_unpad(u_len, s, s_len, blocksize)
    if rc != 0:
        raise exc.CryptoError("Unpadding failure")
    return s[:u_len[0]]
