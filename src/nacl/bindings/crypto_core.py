# Copyright 2018 Donald Stufft and individual contributors
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


crypto_core_ed25519_BYTES = lib.crypto_core_ed25519_bytes()


def crypto_core_ed25519_is_valid_point(p):
    """
    Check if ``p`` represents a point on the edwards25519 curve, in canonical
    form, on the main subgroup, and that the point doesn't have a small order.

    :param p: a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
              representing a point on the edwards25519 curve
    :type p: bytes
    :return: point validity
    :rtype: bool

    """
    ensure(isinstance(p, bytes) and len(p) == crypto_core_ed25519_BYTES,
           'Point must be a crypto_core_ed25519_BYTES long bytes sequence',
           raising=exc.TypeError)

    rc = lib.crypto_core_ed25519_is_valid_point(p)
    return rc == 1


def crypto_core_ed25519_add(p, q):
    """
    Add two points on the edwards25519 curve.

    :param p: a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
              representing a point on the edwards25519 curve
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
              representing a point on the edwards25519 curve
    :type q: bytes
    :return: a point on the edwards25519 curve represented as
             a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(isinstance(p, bytes) and isinstance(q, bytes) and
           len(p) == crypto_core_ed25519_BYTES and
           len(q) == crypto_core_ed25519_BYTES,
           'Each point must be a {} long bytes sequence'.format(
           'crypto_core_ed25519_BYTES'),
           raising=exc.TypeError)

    r = ffi.new("unsigned char[]", crypto_core_ed25519_BYTES)

    rc = lib.crypto_core_ed25519_add(r, p, q)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(r, crypto_core_ed25519_BYTES)[:]


def crypto_core_ed25519_sub(p, q):
    """
    Subtract a point from another on the edwards25519 curve.

    :param p: a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
              representing a point on the edwards25519 curve
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
              representing a point on the edwards25519 curve
    :type q: bytes
    :return: a point on the edwards25519 curve represented as
             a :py:data:`.crypto_core_ed25519_BYTES` long bytes sequence
    :rtype: bytes
    """
    ensure(isinstance(p, bytes) and isinstance(q, bytes) and
           len(p) == crypto_core_ed25519_BYTES and
           len(q) == crypto_core_ed25519_BYTES,
           'Each point must be a {} long bytes sequence'.format(
           'crypto_core_ed25519_BYTES'),
           raising=exc.TypeError)

    r = ffi.new("unsigned char[]", crypto_core_ed25519_BYTES)

    rc = lib.crypto_core_ed25519_sub(r, p, q)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(r, crypto_core_ed25519_BYTES)[:]
