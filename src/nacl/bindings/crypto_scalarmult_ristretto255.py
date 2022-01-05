# Copyright 2021 Donald Stufft and individual contributors
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

has_crypto_scalarmult_ristretto25519 = bool(
    lib.PYNACL_HAS_CRYPTO_SCALARMULT_RISTRETTO25519
)

crypto_scalarmult_ristretto255_BYTES = 0
crypto_scalarmult_ristretto255_SCALAR_BYTES = 0

if has_crypto_scalarmult_ristretto25519:  # pragma: no branch
    # Size of a Ristretto255 point.
    # Should equal crypto_core_ristretto255_BYTES
    crypto_scalarmult_ristretto255_BYTES = (
        lib.crypto_scalarmult_ristretto255_bytes()
    )

    # Size of scalars for the two functions.
    crypto_scalarmult_ristretto255_SCALAR_BYTES = (
        lib.crypto_scalarmult_ristretto255_scalarbytes()
    )


def crypto_scalarmult_ristretto255_base(n: bytes) -> bytes:
    """
    Multiply the scalar ``n`` with the Ed25519 base point.

    :param n: a sequence of
              :py:data:`.crypto_scalarmult_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the scalar
    :raises exc.RuntimeError: on error or if result is zero
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_scalarmult_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(n, bytes)
        and len(n) == crypto_scalarmult_ristretto255_SCALAR_BYTES,
        "Scalar must be a sequence of {} bytes".format(
            crypto_scalarmult_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    q = ffi.new("unsigned char[]", crypto_scalarmult_ristretto255_BYTES)
    rc = lib.crypto_scalarmult_ristretto255_base(q, n)

    # An error is returned iff the result is zero. For consistency with
    # crypto_scalarmult_ristretto255 and in case a future version of libsodium
    # returns an error for other reasons, raise an error.
    ensure(
        rc == 0,
        "Unexpected library error. Zero operand?",
        raising=exc.RuntimeError,
    )

    return ffi.buffer(q, crypto_scalarmult_ristretto255_BYTES)[:]


def crypto_scalarmult_ristretto255(n: bytes, p: bytes) -> bytes:
    """
    Multiply the scalar ``n`` with point ``p``.

    :param n: a sequence of
              :py:data:`.crypto_scalarmult_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the scalar
    :param p: a sequence of :py:data:`.crypto_scalarmult_ristretto255_BYTES`
              bytes in little endian order representing the point
    :raises exc.RuntimeError: on error or if result is zero
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_scalarmult_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(n, bytes)
        and len(n) == crypto_scalarmult_ristretto255_SCALAR_BYTES,
        "Scalar must be a sequence of {} bytes".format(
            crypto_scalarmult_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(p, bytes)
        and len(p) == crypto_scalarmult_ristretto255_BYTES,
        "Point must be a sequence of {} bytes".format(
            crypto_scalarmult_ristretto255_BYTES
        ),
        raising=exc.TypeError,
    )

    q = ffi.new("unsigned char[]", crypto_scalarmult_ristretto255_BYTES)
    rc = lib.crypto_scalarmult_ristretto255(q, n, p)

    # An error is returned also if the result is zero. This cannot be
    # distinguished from other errors like invalid points.
    # https://github.com/jedisct1/libsodium/issues/836#issuecomment-493710969
    ensure(
        rc == 0,
        "Unexpected library error. Zero operand?",
        raising=exc.RuntimeError,
    )

    return ffi.buffer(q, crypto_scalarmult_ristretto255_BYTES)[:]
