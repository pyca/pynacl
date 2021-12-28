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

has_crypto_core_ristretto25519 = bool(
    lib.PYNACL_HAS_CRYPTO_CORE_RISTRETTO25519
)

# Group order L of both the scalar group and group of points.
crypto_core_ristretto255_GROUP_ORDER = (
    2 ** 252 + 27742317777372353535851937790883648493
)

crypto_core_ristretto255_SCALAR_BYTES = 0
crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES = 0

if has_crypto_core_ristretto25519:  # pragma: no branch
    # Size of a Ristretto255 scalar.
    crypto_core_ristretto255_SCALAR_BYTES = (
        lib.crypto_core_ristretto255_scalarbytes()
    )

    # Size of values that are reduced modulo the order to a Ristretto255 scalar.
    crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES = (
        lib.crypto_core_ristretto255_nonreducedscalarbytes()
    )


def crypto_core_ristretto255_scalar_add(x: bytes, y: bytes) -> bytes:
    """
    Compute the sum of the scalars ``x`` and ``y`` modulo ``L``.

    :param x: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the first scalar
    :param y: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the second scalar
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(x, bytes)
        and len(x) == crypto_core_ristretto255_SCALAR_BYTES,
        "First scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(y, bytes)
        and len(y) == crypto_core_ristretto255_SCALAR_BYTES,
        "Second scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    z = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_add(z, x, y)

    return ffi.buffer(z, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_complement(s: bytes) -> bytes:
    """
    Compute the complement of ``s`` such that ``s + comp = 1 (mod L)``.

    :param s: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the scalar
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(s, bytes)
        and len(s) == crypto_core_ristretto255_SCALAR_BYTES,
        "Scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    comp = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_complement(comp, s)

    return ffi.buffer(comp, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_invert(s: bytes) -> bytes:
    """
    Compute the multiplicative inverse of ``s`` such that
    ``recip * s = 1 (mod L)``.

    :param s: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the scalar
    :raises ValueError: if the value is not invertible
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(s, bytes)
        and len(s) == crypto_core_ristretto255_SCALAR_BYTES,
        "Scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    recip = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    rc = lib.crypto_core_ristretto255_scalar_invert(recip, s)

    ensure(rc == 0, "Value is not invertible", raising=ValueError)

    return ffi.buffer(recip, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_mul(x: bytes, y: bytes) -> bytes:
    """
    Compute the product of the scalars ``x`` and ``y`` modulo ``L``.

    :param x: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the first scalar
    :param y: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the second scalar
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(x, bytes)
        and len(x) == crypto_core_ristretto255_SCALAR_BYTES,
        "First scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(y, bytes)
        and len(y) == crypto_core_ristretto255_SCALAR_BYTES,
        "Second scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    z = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_mul(z, x, y)

    return ffi.buffer(z, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_negate(s: bytes) -> bytes:
    """
    Compute the additive inverse of the scalar ``s`` such that
    ``neg + s = 0 (mod L)``.

    :param s: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the scalar
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )
    ensure(
        isinstance(s, bytes)
        and len(s) == crypto_core_ristretto255_SCALAR_BYTES,
        "Scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    neg = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_negate(neg, s)

    return ffi.buffer(neg, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_random() -> bytes:
    """
    Generate a random non-zero scalar modulo ``L``.

    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_random(r)

    return ffi.buffer(r, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_reduce(s: bytes) -> bytes:
    """
    Reduce little endian value ``s`` modulo ``L``. ``s`` should have at least
    317 bits to ensure almost uniformity of ``r`` over ``L``.

    :param s: a sequence of
              :py:data:`.crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES`
              bytes in little endian order representing the value to reduce
              to a Ristretto255 scalar
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(s, bytes)
        and len(s) == crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES,
        "Input must be a {} bytes long sequence".format(
            crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_reduce(r, s)

    return ffi.buffer(r, crypto_core_ristretto255_SCALAR_BYTES)[:]


def crypto_core_ristretto255_scalar_sub(x: bytes, y: bytes) -> bytes:
    """
    Subtract scalar ``y`` from scalar ``x`` modulo ``L``.

    :param x: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the first scalar
    :param y: a sequence of :py:data:`.crypto_core_ristretto255_SCALAR_BYTES`
              bytes in little endian order representing the second scalar
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(x, bytes)
        and len(x) == crypto_core_ristretto255_SCALAR_BYTES,
        "First scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(y, bytes)
        and len(y) == crypto_core_ristretto255_SCALAR_BYTES,
        "Second scalar must be a sequence of {} bytes".format(
            crypto_core_ristretto255_SCALAR_BYTES
        ),
        raising=exc.TypeError,
    )

    z = ffi.new("unsigned char[]", crypto_core_ristretto255_SCALAR_BYTES)
    lib.crypto_core_ristretto255_scalar_sub(z, x, y)

    return ffi.buffer(z, crypto_core_ristretto255_SCALAR_BYTES)[:]


if has_crypto_core_ristretto25519:
    # Size of a Ristretto255 point.
    crypto_core_ristretto255_BYTES = lib.crypto_core_ristretto255_bytes()

    # Size of the input to crypto_core_ristretto255_from_hash
    crypto_core_ristretto255_HASH_BYTES = (
        lib.crypto_core_ristretto255_hashbytes()
    )
else:  # pragma: no cover
    crypto_core_ristretto255_BYTES = 0
    crypto_core_ristretto255_HASH_BYTES = 0


def crypto_core_ristretto255_add(p: bytes, q: bytes) -> bytes:
    """
    Compute the sum of the points ``p`` and ``q``.

    :param p: a sequence of :py:data:`.crypto_core_ristretto255_BYTES`
              bytes representing the first point
    :param q: a sequence of :py:data:`.crypto_core_ristretto255_BYTES`
              bytes representing the second point
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(p, bytes) and len(p) == crypto_core_ristretto255_BYTES,
        "First point must be a sequence of {} bytes".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(q, bytes) and len(q) == crypto_core_ristretto255_BYTES,
        "Second point must be a sequence of {} bytes".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=exc.TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)
    rc = lib.crypto_core_ristretto255_add(r, p, q)

    ensure(rc == 0, "Unexpected library error", raising=exc.RuntimeError)

    return ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]


def crypto_core_ristretto255_from_hash(r: bytes) -> bytes:
    """
    Map 64 bytes of input, e.g. the result of a hash function, to a group
    point. This might be the zero point, e.g. if input is all zeros.

    :param r: a sequence of :py:data:`.crypto_core_ristretto255_HASH_BYTES`
              bytes representing the value to convert
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(r, bytes) and len(r) == crypto_core_ristretto255_HASH_BYTES,
        "Input must be a sequence of {} bytes".format(
            crypto_core_ristretto255_HASH_BYTES
        ),
        raising=exc.TypeError,
    )

    q = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)
    rc = lib.crypto_core_ristretto255_from_hash(q, r)

    ensure(rc == 0, "Unexpected library error", raising=exc.RuntimeError)

    return ffi.buffer(q, crypto_core_ristretto255_BYTES)[:]


def crypto_core_ristretto255_is_valid_point(p: bytes) -> bytes:
    """
    Check if ``p`` is a valid point.

    :param p: a sequence of :py:data:`.crypto_core_ristretto255_BYTES`
              bytes representing the value to check
    :return: False if invalid, True if valid
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(p, bytes) and len(p) == crypto_core_ristretto255_BYTES,
        "Input must be a sequence of {} bytes".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=exc.TypeError,
    )

    rc = lib.crypto_core_ristretto255_is_valid_point(p)

    return rc == 1


def crypto_core_ristretto255_random() -> bytes:
    """
    Generate a random Ristretto255 point. This might be,
    although astronomically unlikely, the zero point.

    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    p = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)
    lib.crypto_core_ristretto255_random(p)

    return ffi.buffer(p, crypto_core_ristretto255_BYTES)[:]


def crypto_core_ristretto255_sub(p: bytes, q: bytes) -> bytes:
    """
    Subtract point ``q`` from ``p``.

    :param p: a sequence of :py:data:`.crypto_core_ristretto255_BYTES`
              bytes representing the first point
    :param q: a sequence of :py:data:`.crypto_core_ristretto255_BYTES`
              bytes representing the second point
    :raises nacl.exceptions.UnavailableError: If called when using a
        minimal build of libsodium.
    """
    ensure(
        has_crypto_core_ristretto25519,
        "Not available in minimal build",
        raising=exc.UnavailableError,
    )

    ensure(
        isinstance(p, bytes) and len(p) == crypto_core_ristretto255_BYTES,
        "First point must be a sequence of {} bytes".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=exc.TypeError,
    )

    ensure(
        isinstance(q, bytes) and len(q) == crypto_core_ristretto255_BYTES,
        "Second point must be a sequence of {} bytes".format(
            crypto_core_ristretto255_BYTES
        ),
        raising=exc.TypeError,
    )

    r = ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)
    rc = lib.crypto_core_ristretto255_sub(r, p, q)

    ensure(rc == 0, "Unexpected library error", raising=exc.RuntimeError)

    return ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]
