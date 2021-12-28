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
    """
    Scalar field modulo prime :py:const:`ORDER`. Each element is a scalar value.

    :cvar ZERO: Scalar with value 0
    :cvar ONE: Scalar with value 1
    :cvar MINUS_ONE: Scalar with value -1 (modulo :py:const:`ORDER`)
    :cvar SIZE: Size of Scalars in bytes (32)
    :cvar NONREDUCED_SIZE: Size of non reduced scalar (64); see :py:meth:`reduce`.
    :cvar ORDER: Group order (``2 ** 252 + 27742317777372353535851937790883648493``)
    """

    ZERO: ClassVar["Ristretto255Scalar"]
    ONE: ClassVar["Ristretto255Scalar"]
    MINUS_ONE: ClassVar["Ristretto255Scalar"]
    SIZE: ClassVar[int] = nacl.bindings.crypto_core_ristretto255_SCALAR_BYTES
    NONREDUCED_SIZE: ClassVar[
        int
    ] = nacl.bindings.crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES
    ORDER: ClassVar[int] = nacl.bindings.crypto_core_ristretto255_GROUP_ORDER

    # Actual value; 32 bytes in little endian order
    _value: bytes

    def __init__(self, value: _ScalarType) -> None:
        """
        Create a new :py:class:`Ristretto255Scalar`.

        :param value: Value of the scalar. Will be converted according to its type.
        :raises exc.TypeError: Type not supported

        Value can be one of:

        * :py:class:`Ristretto255Scalar`: Create a new object with the same value.
        * *bytes*: *value* must be :py:CONST:`SIZE` bytes in little-endian order.
        * *int*: *value* will be reduced modulo :py:CONST:`ORDER`.
        * `Fraction <https://docs.python.org/3/library/fractions.html#fractions.Fraction>`__:
          Numerator of *value* multiplied with the inverse of its denominator.
        """
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
    def random(cls) -> "Ristretto255Scalar":
        """
        Create non-zero random scalar.

        :return: Random scalar
        """
        return cls(nacl.bindings.crypto_core_ristretto255_scalar_random())

    @classmethod
    def random_zero(cls) -> "Ristretto255Scalar":
        """
        Create a random scalar that could be zero.

        :return: Ristretto255Scalar: Random scalar
        """
        return cls.reduce(random(cls.NONREDUCED_SIZE))

    @classmethod
    def reduce(cls, value: bytes) -> "Ristretto255Scalar":
        """
        Reduce a larger value, e.g. the output of a hash function, to a scalar.
        There should be at least 317 bits to ensure almost uniformity.

        :param value: :py:const:`NONREDUCED_SIZE` bytes in little-endian encoding
        :return: Value reduced modulo :py:CONST:`ORDER`
        """
        return cls(nacl.bindings.crypto_core_ristretto255_scalar_reduce(value))

    @property
    def inverse(self) -> "Ristretto255Scalar":
        """
        Get multiplicative inverse such that ``x.inverse * x == Ristretto255Scalar.ONE``.

        :return: Multiplicative inverse reduced modulo :py:CONST:`ORDER`
        """
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_invert(self._value)
        )

    @property
    def complement(self) -> "Ristretto255Scalar":
        """
        Get the complement such that ``x.complement + x == Ristretto255Scalar.ONE``.

        Note that this is *not* the two's complement where ``~x + x == -1``.

        :return: Complemental value reduced modulo :py:CONST:`ORDER`
        """
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_complement(
                self._value
            )
        )

    def __add__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Add two scalars.

        :param other: Any of the types supported by the constructor
        :return: Sum of *self* and *other* reduced modulo :py:CONST:`ORDER`
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

    def __radd__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Add two scalars.

        :param other: Any of the types supported by the constructor
        :return: Sum of *other* and *self* reduced modulo :py:CONST:`ORDER`
        """
        return self + other

    def __sub__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Subtract *other* from *self*.

        :param other: Any of the types supported by the constructor
        :return: Difference of *self* and *other* reduced modulo :py:CONST:`ORDER`
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

    def __rsub__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Subtract *self* from *other*.

        :param other: Any of the types supported by the constructor
        :return: Difference of *other* and *self* reduced modulo :py:CONST:`ORDER`
        """
        return -(self - other)

    def __mul__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Multiply two scalars.

        :param other: Any of the types supported by the constructor
        :return: Product of *self* and *other* modulo :py:CONST:`ORDER`
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

    def __rmul__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Multiply two scalars.

        :param other: Any of the types supported by the constructor
        :return: Product of *other* and *self* modulo :py:CONST:`ORDER`
        """
        return self * other

    def __truediv__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Divide two scalars.

        :param other: Any of the types supported by the constructor
        :return: Product of *self* and inverse of *other* modulo :py:CONST:`ORDER`
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

    def __rtruediv__(self, other: _ScalarType) -> "Ristretto255Scalar":
        """
        Divide two scalars.

        :param other: Any of the types supported by the constructor
        :return: Product of *other* and inverse of *self* modulo :py:CONST:`ORDER`
        """

        return self.inverse * other

    def __neg__(self) -> "Ristretto255Scalar":
        """
        Get the additive inverse such that ``-x + x == Ristretto255Scalar.ZERO``.

        :return: Additive inverse
        """

        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_negate(self._value)
        )

    def __eq__(self, other: object) -> bool:
        """
        Check if two scalars are identical. Comparing with other types such as
        ``int`` will return False.

        :return: True if equal, False otherwise
        """
        if not isinstance(other, self.__class__):
            return False

        return nacl.bindings.sodium_memcmp(self._value, other._value)

    def __ne__(self, other: object) -> bool:
        """
        Check if two scalars are not identical. Comparing with other types such as
        ``int`` will return True.

        :return: False if equal, True otherwise
        """
        return not (self == other)

    def __hash__(self) -> int:
        """
        Compute a hash value.

        :return: Hash value
        """
        return hash(self._value)

    def __bytes__(self) -> bytes:
        """
        Get byte representation of scalar.

        :return: Value of scalar in little-endian encoding
        """
        return self._value

    def __int__(self) -> int:
        """
        Get integer representation of scalar.

        :return: Value of scalar reduced modulo :py:CONST:`ORDER`
        """
        return int.from_bytes(self._value, "little")

    def __bool__(self) -> bool:
        """
        Check if scalar is non-zero.

        :return: True if non-zero, False otherwise
        """
        return not nacl.bindings.sodium_is_zero(self._value)

    def __repr__(self) -> str:
        """
        Get representation of scalar which, when evaluated, will yield an equal scalar.

        :return: Representation of scalar
        """
        return f"Ristretto255Scalar({int(self)})"

    def __str__(self) -> str:
        """
        Get human readable representation of scalar.

        :return: Representation of scalar
        """
        return repr(self)


if nacl.bindings.has_crypto_core_ristretto25519:  # pragma: no branch
    # Neutral additive element
    Ristretto255Scalar.ZERO = Ristretto255Scalar(0)

    # Neutral multiplicative element
    Ristretto255Scalar.ONE = Ristretto255Scalar(1)

    # Constant needed for inverting points
    Ristretto255Scalar.MINUS_ONE = Ristretto255Scalar(-1)


class Ristretto255Point:
    """
    Ristretto255 group. Each element is a curve point.

    :cvar ORDER: Group order
    :cvar SIZE: Size of Points in bytes (32)
    :cvar HASH_SIZE: Size input for :py:meth:`from_hash` (64).
    :cvar ZERO: Neutral element
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_core_ristretto255_BYTES
    HASH_SIZE: ClassVar[
        int
    ] = nacl.bindings.crypto_core_ristretto255_HASH_BYTES
    ORDER: ClassVar[int] = nacl.bindings.crypto_core_ristretto255_GROUP_ORDER
    ZERO: ClassVar["Ristretto255Point"]

    # Actual value; 32 bytes in little endian order
    _value: bytes

    def __init__(self, value: bytes, _assume_valid: bool = False) -> None:
        """
        Create a new :py:class:`Ristretto255Point`.

        :param value: Value of point in little-endian order
        :param _assume_valid: For internal use only: Skip check for valid point
        :raises exc.ValueError: Invalid point
        """
        if not _assume_valid:
            if not nacl.bindings.crypto_core_ristretto255_is_valid_point(
                value
            ):
                raise exc.ValueError("Not a valid point")
        self._value = value

    @classmethod
    def from_hash(cls, value: bytes) -> "Ristretto255Point":
        """
        Map 64 bytes of input, e.g. the result of a hash function, to a group
        point. This might be the zero point, e.g. if hash value is all zeros.

        :param value: :py:const:`HASH_SIZE` bytes in little-endian encoding
        :return: Point created from *value*
        """
        return cls(
            nacl.bindings.crypto_core_ristretto255_from_hash(value),
            _assume_valid=True,
        )

    @classmethod
    def random(cls) -> "Ristretto255Point":
        """
        Generate a random Ristretto255 point. This might be,
        although astronomically unlikely, the zero point.

        :return: Random point
        """
        return cls(
            nacl.bindings.crypto_core_ristretto255_random(), _assume_valid=True
        )

    @classmethod
    def base_mul(cls, n: _ScalarType) -> "Ristretto255Point":
        """
        Multiply the non-zero scalar *n* with the Ed25519 base point.

        :param n: Scalar value, any type supported by :py:class:`Ristretto255Scalar`.
        :return: Product of the Ed25519 base point and *n*
        """
        return cls(
            nacl.bindings.crypto_scalarmult_ristretto255_base(
                Ristretto255Scalar._convert(n)
            ),
            _assume_valid=True,
        )

    def __neg__(self) -> "Ristretto255Point":
        """
        Get inverse element such that ``-self + self == Ristretto255Point.ZERO``.

        :return: Inverse of *self*
        """
        return self * Ristretto255Scalar.MINUS_ONE

    def __add__(self, other: "Ristretto255Point") -> "Ristretto255Point":
        """
        Add two points.

        :arg other: A group point
        :return: Sum of *self* and *other*
        """
        if not isinstance(other, Ristretto255Point):
            return NotImplemented  # type: ignore[unreachable]

        return Ristretto255Point(
            nacl.bindings.crypto_core_ristretto255_add(
                self._value, other._value
            ),
            _assume_valid=True,
        )

    def __sub__(self, other: "Ristretto255Point") -> "Ristretto255Point":
        """
        Subtract two points.

        :arg other: A group point
        :return: Difference of *self* and *other*
        """
        if not isinstance(other, Ristretto255Point):
            return NotImplemented  # type: ignore[unreachable]

        return Ristretto255Point(
            nacl.bindings.crypto_core_ristretto255_sub(
                self._value, other._value
            ),
            _assume_valid=True,
        )

    def __mul__(self, other: _ScalarType) -> "Ristretto255Point":
        """
        Multiply the non-zero scalar *other* with the point.

        :param other: Scalar value, any type supported by :py:class:`Ristretto255Scalar`.
        :return: Product of *self* and *other*
        """
        return Ristretto255Point(
            nacl.bindings.crypto_scalarmult_ristretto255(
                Ristretto255Scalar._convert(other), self._value
            ),
            _assume_valid=True,
        )

    def __rmul__(self, other: _ScalarType) -> "Ristretto255Point":
        """
        Multiply the point with the non-zero scalar *other*.

        :param other: Scalar value, any type supported by :py:class:`Ristretto255Scalar`.
        :return: Product of *other and *self*
        """
        return self * other

    def __bool__(self) -> bool:
        """
        Check if this is *not* the zero / neutral / identity point.

        :return: False if zero point, True otherwise
        """
        return not nacl.bindings.sodium_is_zero(self._value)

    def __eq__(self, other: object) -> bool:
        """
        Compare this point to another point.

        :param other: Other point to compare to
        :return: True if same point, False otherwise or if not a :py:class:`Ristretto255Scalar`
        """
        if not isinstance(other, self.__class__):
            return False

        return nacl.bindings.sodium_memcmp(self._value, other._value)

    def __ne__(self, other: object) -> bool:
        """
        Compare this point to another point.

        :param other: Other point to compare to
        :return: False if same point, True otherwise or if not a :py:class:`Ristretto255Scalar`
        """
        return not (self == other)

    def __bytes__(self) -> bytes:
        """
        Get byte representation of point.

        :return: Little-endian byte representation of point
        """
        return self._value

    def __hash__(self) -> int:
        """
        Compute a hash value.

        :return: Hash value
        """
        return hash(self._value)

    def __repr__(self) -> str:
        """
        Get representation of point which, when evaluated, will yield an equal point.

        :return: Representation of point
        """
        return f"Ristretto255Point({bytes(self)!r})"

    def __str__(self) -> str:
        """
        Get human readable representation of point.

        :return: Little-endian hex representation of point
        """
        return f"Ristretto255Point({bytes(self).hex()})"


if nacl.bindings.has_crypto_core_ristretto25519:  # pragma: no branch
    # Neutral element
    Ristretto255Point.ZERO = Ristretto255Point(
        bytes(Ristretto255Point.SIZE), _assume_valid=True
    )
