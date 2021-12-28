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

from fractions import Fraction
from typing import ClassVar, Union

import nacl.bindings
from nacl import exceptions as exc
from nacl.utils import random


# Python types accepted as scalars
_ScalarType = Union["Ristretto255Scalar", bytes, int, Fraction]


class Ristretto255Scalar:
    SIZE = nacl.bindings.crypto_core_ristretto255_SCALAR_BYTES
    NONREDUCED_SIZE = (
        nacl.bindings.crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES
    )
    ORDER = nacl.bindings.crypto_core_ristretto255_GROUP_ORDER

    def __init__(self, value):
        self._value = self._convert(value)

    @staticmethod
    def _convert(value: object) -> bytes:
        """
        Convert various types to a byte array containing the reduced scalar value in little-endian order.

        :param value: Value of the scalar. Will be converted according to its type.
        :return: Canonical represention of the passed value, as byte array.
        :raises exc.TypeError: Type not supported
        """
        if isinstance(value, Ristretto255Scalar):
            return value._value

        if isinstance(value, bytes):
            if len(value) != Ristretto255Scalar.SIZE:
                raise exc.ValueError

            # Reduce value modulo the group order to ensure a canonical encoding.
            zero = bytes(Ristretto255Scalar.SIZE)
            return nacl.bindings.crypto_core_ristretto255_scalar_add(
                value, zero
            )

        if isinstance(value, int):
            return (value % Ristretto255Scalar.ORDER).to_bytes(
                Ristretto255Scalar.SIZE, "little"
            )

        if isinstance(value, Fraction):
            numerator = Ristretto255Scalar._convert(value.numerator)
            denominator = Ristretto255Scalar._convert(value.denominator)

            # Compute fraction [a / b] as [a * (b ** -1)]
            return nacl.bindings.crypto_core_ristretto255_scalar_mul(
                numerator,
                nacl.bindings.crypto_core_ristretto255_scalar_invert(
                    denominator
                ),
            )

        raise exc.TypeError(f"Unsupported type: {type(value).__name__!r}")

    @classmethod
    def random(cls):
        """
        Get a non-zero random scalar.
        """

        return cls(nacl.bindings.crypto_core_ristretto255_scalar_random())

    @classmethod
    def random_zero(cls):
        """
        Get a random scalar that could also be zero.
        """
        return cls.reduce(random(cls.NONREDUCED_SIZE))

    @classmethod
    def reduce(cls, value):
        """
        Reduce a larger value, e.g. the output of a hash function, to a scalar.
        There should be at least 317 bits to ensure almost uniformity.
        """
        return cls(nacl.bindings.crypto_core_ristretto255_scalar_reduce(value))

    @property
    def inverse(self):
        """
        Get multiplicative inverse such that ``x.inverse * x == 1``.
        """

        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_invert(self._value)
        )

    @property
    def complement(self):
        """
        Get the complement such that ``x.complement + x == 1``.
        """
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_complement(
                self._value
            )
        )

    def __add__(self, other):
        """
        Add two scalars.
        """
        try:
            value = self._convert(other)
        except exc.TypeError:
            return NotImplemented

        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_add(
                self._value, value
            )
        )

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        """
        Subtract to scalars.
        """
        try:
            value = self._convert(other)
        except exc.TypeError:
            return NotImplemented

        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_sub(
                self._value, value
            )
        )

    def __rsub__(self, other):
        return -(self - other)

    def __mul__(self, other):
        """
        Multiply two scalars.
        """

        try:
            value = self._convert(other)
        except exc.TypeError:
            return NotImplemented

        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_mul(
                self._value, value
            )
        )

    def __rmul__(self, other):
        return self * other

    def __neg__(self):
        """
        Get the additive inverse such that ``-x + x == 0``.
        """
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_negate(self._value)
        )

    def __truediv__(self, other):
        """
        Divide two scalars.
        """

        try:
            value = self._convert(other)
        except exc.TypeError:
            return NotImplemented

        inverse = nacl.bindings.crypto_core_ristretto255_scalar_invert(value)
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_mul(
                self._value, inverse
            )
        )

    def __rtruediv__(self, other):
        Divide two scalars.
        """

        return self.inverse * other

    def __eq__(self, other):
        """
        Check if two scalars are identical. Comparing with other types such as
        ``int`` will return False.
        """
        if not isinstance(other, self.__class__):
            return False

        return nacl.bindings.sodium_memcmp(self._value, other._value)

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self._value)

    def __bytes__(self):
        return self._value

    def __int__(self):
        return int.from_bytes(self._value, "little")

    def __bool__(self):
        return not nacl.bindings.sodium_is_zero(self._value)

    def __repr__(self):
        return "Ristretto255Scalar({})".format(int(self))

    def __str__(self):
        return repr(self)


if nacl.bindings.has_crypto_core_ristretto25519:  # pragma: no branch
    # Neutral additive element
    Ristretto255Scalar.ZERO = Ristretto255Scalar(0)

    # Neutral multiplicative element
    Ristretto255Scalar.ONE = Ristretto255Scalar(1)

    # Constant needed for inverting points
    Ristretto255Scalar.MINUS_ONE = Ristretto255Scalar(-1)


class Ristretto255Point:
    SIZE = nacl.bindings.crypto_core_ristretto255_BYTES
    HASH_SIZE = nacl.bindings.crypto_core_ristretto255_HASH_BYTES
    ORDER = nacl.bindings.crypto_core_ristretto255_GROUP_ORDER

    def __init__(self, value, _assume_valid=False):
        if not _assume_valid:
            if not nacl.bindings.crypto_core_ristretto255_is_valid_point(
                value
            ):
                raise exc.ValueError("Not a valid point")
        self._value = value

    @classmethod
    def from_hash(cls, value):
        """
        Map 64 bytes of input, e.g. the result of a hash function, to a group
        point. This might be the zero point, e.g. if input is all zeros.
        """
        return cls(
            nacl.bindings.crypto_core_ristretto255_from_hash(value),
            _assume_valid=True,
        )

    @classmethod
    def random(cls):
        """
        Generate a random Ristretto255 point. This might be,
        although astronomically unlikely, the zero point.
        """
        return cls(
            nacl.bindings.crypto_core_ristretto255_random(), _assume_valid=True
        )

    @classmethod
    def base_mul(cls, n):
        """
        Multiply the non-zero scalar *n* with the Ed25519 base point.
        """
        return cls(
            nacl.bindings.crypto_scalarmult_ristretto255_base(
                Ristretto255Scalar._convert(n)
            ),
            _assume_valid=True,
        )

    def __neg__(self):
        """
        Get inverse element such that ``-x + x == Ristretto255Point.ZERO``.
        """
        return self * Ristretto255Scalar.MINUS_ONE

    def __add__(self, other):
        """
        Add two points.
        """
        if not isinstance(other, Ristretto255Point):
            return NotImplemented  # type: ignore[unreachable]

        return Ristretto255Point(
            nacl.bindings.crypto_core_ristretto255_add(
                self._value, other._value
            ),
            _assume_valid=True,
        )

    def __sub__(self, other):
        """
        Subtract two points.
        """
        if not isinstance(other, Ristretto255Point):
            return NotImplemented  # type: ignore[unreachable]

        return Ristretto255Point(
            nacl.bindings.crypto_core_ristretto255_sub(
                self._value, other._value
            ),
            _assume_valid=True,
        )

    def __mul__(self, other):
        """
        Multiply the non-zero scalar *other* with the point.
        """
        return Ristretto255Point(
            nacl.bindings.crypto_scalarmult_ristretto255(
                Ristretto255Scalar._convert(other), self._value
            ),
            _assume_valid=True,
        )

    def __rmul__(self, other):
        """
        Multiply the point with the non-zero scalar *other*.
        """
        return self * other

    def __bool__(self):
        """
        Check if this is *not* the zero / neutral / identity point.

        :return: False if zero point, else True
        :rtype: bool
        """
        return not nacl.bindings.sodium_is_zero(self._value)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        return nacl.bindings.sodium_memcmp(self._value, other._value)

    def __ne__(self, other):
        return not (self == other)

    def __bytes__(self):
        return self._value

    def __hash__(self):
        return hash(self._value)

    def __repr__(self):
        return "Ristretto255Point({!r})".format(bytes(self))

    def __str__(self):
        return "Ristretto255Point({})".format(bytes(self).hex())




if nacl.bindings.has_crypto_core_ristretto25519:  # pragma: no branch
    # Neutral element
    Ristretto255Point.ZERO = Ristretto255Point(
        bytes(Ristretto255Point.SIZE), _assume_valid=True
    )
