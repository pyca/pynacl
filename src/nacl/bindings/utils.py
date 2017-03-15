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
