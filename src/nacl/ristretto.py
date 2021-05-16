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

from __future__ import absolute_import, division, print_function

from fractions import Fraction

import nacl.bindings
from nacl import exceptions as exc
from nacl.utils import random


class Ristretto255Scalar(object):
    SIZE = nacl.bindings.crypto_core_ristretto255_SCALAR_BYTES
    NONREDUCED_SIZE = (
        nacl.bindings.crypto_core_ristretto255_NONREDUCED_SCALAR_BYTES
    )
    ORDER = nacl.bindings.crypto_core_ristretto255_GROUP_ORDER

    def __init__(self, value):
        if isinstance(value, Ristretto255Scalar):
            self._value = value._value
        elif isinstance(value, bytes):
            if len(value) != Ristretto255Scalar.SIZE:
                raise exc.ValueError
            self._value = value
        elif isinstance(value, int):
            self._value = (value % Ristretto255Scalar.ORDER).to_bytes(
                Ristretto255Scalar.SIZE, "little"
            )
        elif isinstance(value, Fraction):
            self._value = (
                Ristretto255Scalar(value.numerator)
                * Ristretto255Scalar(value.denominator).inverse
            )._value
        else:
            raise exc.TypeError

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

        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_add(
                self._value, Ristretto255Scalar(other)._value
            )
        )

    def __radd__(self, other):
        return self + other

    def __sub__(self, other):
        """
        Subtract to scalars.
        """
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_sub(
                self._value, Ristretto255Scalar(other)._value
            )
        )

    def __rsub__(self, other):
        return -(self - other)

    def __mul__(self, other):
        """
        Multiply two scalars.
        """
        return Ristretto255Scalar(
            nacl.bindings.crypto_core_ristretto255_scalar_mul(
                self._value, Ristretto255Scalar(other)._value
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


if nacl.bindings.has_crypto_core_ristretto25519:
    # Neutral additive element
    Ristretto255Scalar.ZERO = Ristretto255Scalar(0)

    # Neutral multiplicative element
    Ristretto255Scalar.ONE = Ristretto255Scalar(1)

    # Constant needed for inverting points
    Ristretto255Scalar.MINUS_ONE = Ristretto255Scalar(-1)
else:  # pragma: no cover

    Ristretto255Scalar.ZERO = Ristretto255Scalar(
        bytes(Ristretto255Scalar.SIZE)
    )
    Ristretto255Scalar.ONE = Ristretto255Scalar(bytes(Ristretto255Scalar.SIZE))
    Ristretto255Scalar.MINUS_ONE = Ristretto255Scalar(
        bytes(Ristretto255Scalar.SIZE)
    )


class Ristretto255Point(object):
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
        Multiply the scalar ``n`` with the Ed25519 base point.
        """
        return cls(
            nacl.bindings.crypto_scalarmult_ristretto255_base(
                bytes(Ristretto255Scalar(n))
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
            raise exc.TypeError("Operand must be another Ristretto255Point")

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
            raise exc.TypeError("Operand must be another Ristretto255Point")

        return Ristretto255Point(
            nacl.bindings.crypto_core_ristretto255_sub(
                self._value, other._value
            ),
            _assume_valid=True,
        )

    def __mul__(self, other):
        """
        Multiply the scalar ``n`` with the point.
        """
        return Ristretto255Point(
            nacl.bindings.crypto_scalarmult_ristretto255(
                bytes(Ristretto255Scalar(other)), self._value
            ),
            _assume_valid=True,
        )

    def __rmul__(self, other):
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


# Neutral element
Ristretto255Point.ZERO = Ristretto255Point(
    bytes(Ristretto255Point.SIZE), _assume_valid=True
)
