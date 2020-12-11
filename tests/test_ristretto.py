# Copyright 2020 Donald Stufft and individual contributors
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

import json
import os
from binascii import unhexlify
from fractions import Fraction
from functools import reduce
from hashlib import sha256, sha512
from operator import mul
from random import randrange

import pytest

from six import int2byte

import nacl.exceptions as exc
from nacl.ristretto import Ristretto255Point, Ristretto255Scalar


def _ristretto255_vectors():
    """
    Test vectors from https://ristretto.group/test_vectors/ristretto255.html
    """
    DATA = "ristretto255.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    vectors = json.load(open(path))

    return {
        "encodings_of_small_multiples": [
            (idx, unhexlify(enc))
            for idx, enc in enumerate(vectors["encodings_of_small_multiples"])
        ],
        "bad_encodings": [unhexlify(enc) for enc in vectors["bad_encodings"]],
        "label_hash_to_points": [
            (label, unhexlify(enc))
            for label, enc in zip(
                vectors["labels"], vectors["encoded_hash_to_points"]
            )
        ],
    }


class TestRistretto255Scalar(object):
    order = 7237005577332262213973186563042994240857116359379907606001950938285454250989
    order_bytes = unhexlify(
        "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
    )

    def test_init(self):

        dgst = sha256(b"hello").digest()
        s = Ristretto255Scalar(dgst)
        assert bytes(s) == dgst

        assert bytes(Ristretto255Scalar(0xE2)) == b"\xe2" + b"\x00" * 31
        assert bytes(Ristretto255Scalar(0xABCD)) == b"\xcd\xab" + b"\x00" * 30
        assert bytes(Ristretto255Scalar(self.order)) == b"\x00" * 32
        assert (
            bytes(Ristretto255Scalar(-0xED)) == b"\x00" + self.order_bytes[1:]
        )

        assert (
            bytes(Ristretto255Scalar(Fraction(5, 1))) == b"\x05" + b"\x00" * 31
        )
        # (pow(3, -1, order) * 5 % order).to_bytes(32, "little").hex()
        five_thirds = unhexlify(
            "a646a7c9082106c89c8952364a534a5c55555555555555555555555555555505"
        )
        assert bytes(Ristretto255Scalar(Fraction(5, 3))) == five_thirds

        with pytest.raises(exc.ValueError):
            Ristretto255Scalar(b"too short")

        with pytest.raises(exc.TypeError):
            Ristretto255Scalar(3.14)

    def test_random(self):
        s = Ristretto255Scalar.random()
        t = Ristretto255Scalar.random()

        # Two random scalars *might* be the same in theory. But in practice
        # it can only be a serious bug because of the huge group size.
        assert s != t

    def test_random_zero(self):
        s = Ristretto255Scalar.random_zero()
        t = Ristretto255Scalar.random_zero()

        # Two random scalars *might* be the same in theory. But in practice
        # it can only be a serious bug because of the huge group size.
        assert s != t

    def test_reduce(self):
        assert (
            bytes(Ristretto255Scalar.reduce(b"\xcd\xab" + b"\x00" * 62))
            == b"\xcd\xab" + b"\x00" * 30
        )
        dgst = sha512(b"hello").digest()

        # (int.from_bytes(sha512(b"hello").digest(), "little") % order).to_bytes(32, "little").hex()
        reduced_dgst = unhexlify(
            "b586c3423482ab97d876ce24cab8bd8ab84e22ac3a52a8dfbb330bbe92a3260f"
        )

        assert bytes(Ristretto255Scalar.reduce(dgst)) == reduced_dgst

    def test_inverse(self):
        assert Ristretto255Scalar(1).inverse == Ristretto255Scalar.ONE
        s = Ristretto255Scalar.random()
        assert s.inverse * s == Ristretto255Scalar.ONE

        t = Ristretto255Scalar(b"".join(int2byte(i) for i in range(32)))

        # pow(int.from_bytes(bytes(range(32)), "little"), -1, order).to_bytes(32, "little").hex()
        inv = unhexlify(
            "0cf17e6d77775ab76bd4f41cd2ef9ecc9ddd8242185bd685a60b49b5b3f16606"
        )

        assert bytes(t.inverse) == inv

    def test_complement(self):
        assert Ristretto255Scalar(1).complement == Ristretto255Scalar.ZERO
        assert Ristretto255Scalar(0).complement == Ristretto255Scalar.ONE

        s = Ristretto255Scalar.random()
        assert s.complement + s == Ristretto255Scalar.ONE

        t = Ristretto255Scalar(b"".join(int2byte(i) for i in range(32)))
        # ((1 - int.from_bytes(bytes(range(32)), "little")) % order).to_bytes(32, "little").hex()
        compl = unhexlify(
            "dba6e9b630c11ea9a430e53ab1e6af1af0eeedecebeae9e8e7e6e5e4e3e2e100"
        )

        assert bytes(t.complement) == compl

    def test_add(self):
        s = Ristretto255Scalar(123)
        t = Ristretto255Scalar(456)
        u = Ristretto255Scalar(579)

        assert s + t == u
        assert s + t == t + s
        assert s != t
        assert s + Ristretto255Scalar.ZERO == s
        assert s + 456 == u
        assert 456 + s == u
        assert u + (self.order - 456) == s

        a = Ristretto255Scalar.random()
        b = Ristretto255Scalar.random()
        c = Ristretto255Scalar.random()

        assert (a + b) + c == (c + a) + b

    def test_sub(self):
        s = Ristretto255Scalar(123)
        t = Ristretto255Scalar(456)
        u = Ristretto255Scalar(579)

        assert u - s == t
        assert u - t == s
        assert s - (self.order - 456) == u
        assert u - 456 == s
        assert 579 - t == s

        a = Ristretto255Scalar.random()
        b = Ristretto255Scalar.random()
        c = Ristretto255Scalar.random()

        assert (a - b) - c == a - (c + b)

    def test_mul(self):
        s = Ristretto255Scalar(123)
        t = Ristretto255Scalar(456)
        u = Ristretto255Scalar(123 * 456)

        assert s * t == t * s
        assert bytes(s * t) == b"\x18\xdb" + b"\x00" * 30
        assert 456 * s == u
        assert t * 123 == u

        assert ((s * -1) * t) * -1 == u

        v = Ristretto255Scalar(b"\x01" * 32)
        w = Ristretto255Scalar(b"\x02" * 32)
        # (int.from_bytes(b"\x01" * 32, "little") * int.from_bytes(b"\x02" * 32, "little") % order).to_bytes(32, "little").hex()
        x = unhexlify(
            "7d808bf1fafea25f3ee660ef3c1793985190ba1413f9b714edf967ce6b8bdd06"
        )
        assert bytes(v * w) == x

        a = Ristretto255Scalar.random()
        b = Ristretto255Scalar.random()
        c = Ristretto255Scalar.random()

        assert (a * b) * c == c * (b * a)
        assert a * Ristretto255Scalar.ZERO == Ristretto255Scalar.ZERO
        assert a * Ristretto255Scalar.ONE == a

    def test_neg(self):
        s = Ristretto255Scalar(123)
        t = Ristretto255Scalar(-123)

        assert -s == t
        assert s == -t
        assert -s * Ristretto255Scalar.MINUS_ONE == s

        a = Ristretto255Scalar.random()
        assert a + -a == Ristretto255Scalar.ZERO
        assert a - -a == 2 * a
        assert -Ristretto255Scalar.ZERO == Ristretto255Scalar.ZERO
        assert -Ristretto255Scalar.ONE == Ristretto255Scalar.MINUS_ONE

    def test_eq(self):
        s = Ristretto255Scalar(123)
        t = Ristretto255Scalar(123)
        u = Ristretto255Scalar(456)

        assert s == s
        assert s == t
        assert t != u

        assert s != "foobar"
        assert s != 123

        p = Ristretto255Scalar.random()
        q = Ristretto255Scalar.random()

        a = p * 17 + q
        b = p * 8 + q * 5 + p * 9 - 4 * q
        c = p * 17 + q * 2

        assert a == b
        assert a != c
        assert b != c

    def test_hash(self):
        p = Ristretto255Scalar.random()
        q = Ristretto255Scalar.random()

        h0 = hash(p * 17 + q)
        h1 = hash(p * 8 + q * 5 + p * 9 - 4 * q)

        assert h0 == h1

    def test_bytes(self):
        s = Ristretto255Scalar(123)
        assert type(bytes(s)) is bytes
        assert len(bytes(s)) == 32

    def test_int(self):
        s = Ristretto255Scalar(123)
        t = -s

        assert int(s) == 123
        assert int(t) == self.order - 123
        assert int(Ristretto255Scalar.ZERO) == 0
        assert int(Ristretto255Scalar.ONE) == 1
        assert int(Ristretto255Scalar.MINUS_ONE) == self.order - 1

    def test_bool(self):
        assert not Ristretto255Scalar.ZERO
        assert Ristretto255Scalar.ONE
        assert Ristretto255Scalar.MINUS_ONE
        assert Ristretto255Scalar.random()

        s = Ristretto255Scalar(123)
        t = Ristretto255Scalar(456)
        u = Ristretto255Scalar(579)

        assert s
        assert u - t
        assert not (u - t - s)

    def test_repr(self):
        s = Ristretto255Scalar(123)
        assert repr(s) == "Ristretto255Scalar(123)"


class TestRistretto255Point(object):
    _vectors = _ristretto255_vectors()

    @pytest.mark.parametrize(
        ("idx", "encoding"), _vectors["encodings_of_small_multiples"]
    )
    def test_small_multiples(self, idx, encoding):
        base = Ristretto255Point(
            unhexlify(
                "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
            )
        )
        point = Ristretto255Point.ZERO

        for i in range(idx):
            point += base

        assert bytes(point) == encoding

        if idx > 0:
            # skip idx == 0 because libsodium would raise an error.
            point = Ristretto255Point.base_mul(idx)
            assert bytes(point) == encoding

    @pytest.mark.parametrize(("encoding"), _vectors["bad_encodings"])
    def test_bad_encodings(self, encoding):
        with pytest.raises(exc.ValueError):
            Ristretto255Point(encoding)

    @pytest.mark.parametrize(
        ("label", "encoding"), _vectors["label_hash_to_points"]
    )
    def test_hash_to_point(self, label, encoding):
        point = Ristretto255Point.from_hash(
            sha512(label.encode("UTF-8")).digest()
        )
        assert bytes(point) == encoding

    def test_init(self):
        with pytest.raises(exc.TypeError):
            Ristretto255Point(b"too short")

        with pytest.raises(exc.TypeError):
            Ristretto255Point(3.14)

        # good code paths are tested elsewhere.

    def test_random(self):
        p = Ristretto255Point.random()
        q = Ristretto255Point.random()

        # Two random points *might* be the same in theory. But in practice
        # it can only be a serious bug because of the huge group size.
        assert p != q

    def test_neg(self):
        p = Ristretto255Point.random()
        q = -p
        assert p != q
        assert p + q == Ristretto255Point.ZERO
        assert p - q == p + p

    def test_add(self):
        p = Ristretto255Point.random()
        q = Ristretto255Point.random()
        r = Ristretto255Point.random()

        with pytest.raises(exc.TypeError):
            p + 123

        assert p + Ristretto255Point.ZERO == p
        assert Ristretto255Point.ZERO + p == p
        assert p + q == q + p
        assert (p + q) + r == p + (q + r)
        assert (p + q) + r == (r + p) + q

    def test_sub(self):
        p = Ristretto255Point.random()
        q = Ristretto255Point.random()
        r = Ristretto255Point.random()

        with pytest.raises(exc.TypeError):
            p - 123

        assert p - Ristretto255Point.ZERO == p
        assert Ristretto255Point.ZERO - p != p
        assert Ristretto255Point.ZERO - p == -p
        assert p - q != q - p
        assert (p - q) - r == p - (q + r)

    def test_mul(self):
        p = Ristretto255Point.random()
        q = Ristretto255Point.random()

        with pytest.raises(exc.TypeError):
            p * q

        with pytest.raises(exc.TypeError):
            p * u"test"

        assert p * 3 == 3 * p
        assert p + p + p == p * 3
        assert ((p * 2) * 3) * 5 == p * 30

        assert p * Ristretto255Scalar(7) == p * 8 - p
        assert p * Fraction(8, 1) == p * 8
        assert 27 * p * Fraction(-11, 27) == p * -11

    def test_bool(self):
        p = Ristretto255Point.random()

        assert not Ristretto255Point.ZERO
        assert bool(Ristretto255Point.base_mul(1))
        assert not (p - p)

    def test_eq(self):
        p = Ristretto255Point.random()
        q = Ristretto255Point.random()
        assert p != u"foobar"
        assert p == p

        a = p * 17 + q
        b = p * 8 + q * 5 + p * 9 - 4 * q
        c = p * 17 + q * 2

        assert a == b
        assert a != c
        assert b != c

    def test_bytes(self):
        base = Ristretto255Point.base_mul(1)
        enc0 = bytes(base)
        enc1 = unhexlify(
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        )
        assert enc0 == enc1

        p = Ristretto255Point.random()
        assert type(bytes(p)) is bytes
        assert len(bytes(p)) == 32

    def test_hash(self):
        p = Ristretto255Point.random()
        q = Ristretto255Point.random()

        h0 = hash(p * 17 + q)
        h1 = hash(p * 8 + q * 5 + p * 9 - 4 * q)

        assert h0 == h1

    def test_repr(self):
        base = Ristretto255Point.base_mul(1)
        assert (
            repr(base)
            == "Ristretto255Point('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76')"
        )

    def test_library_error(self):
        p = Ristretto255Point(
            self._vectors["bad_encodings"][6], _assume_valid=True
        )
        q = Ristretto255Point.random()

        with pytest.raises(exc.RuntimeError):
            p + q

        with pytest.raises(exc.RuntimeError):
            p - q

        with pytest.raises(exc.RuntimeError):
            p * 2


class TestElGamal(object):
    """
    ElGamal encryption.
    """

    def gen_key(self):
        x = Ristretto255Scalar.random()
        h = Ristretto255Point.base_mul(x)

        return x, h

    def encrypt(self, h, m):
        y = Ristretto255Scalar.random()
        s = h * y
        c0 = Ristretto255Point.base_mul(y)
        c1 = m + s

        return c0, c1

    def decrypt(self, c0, c1, x):
        s = c0 * x
        m = c1 - s

        return m

    def test_el_gamal(self):
        x, h = self.gen_key()
        orig_msg = b"The quick brown fox jumps over the lazy dog.".ljust(64)

        # happens to be a valid point.
        m0 = Ristretto255Point(orig_msg[:32])
        e0, f0 = self.encrypt(h, m0)

        # happens to be a valid point too. Blessed be the lazy dog!
        m1 = Ristretto255Point(orig_msg[32:])
        e1, f1 = self.encrypt(h, m1)

        d0 = self.decrypt(e0, f0, x)
        d1 = self.decrypt(e1, f1, x)
        decr_msg = bytes(d0) + bytes(d1)

        assert orig_msg == decr_msg


class TestShamir(object):
    """
    Shamir's Secret Sharing
    """

    class Polynomial:
        def __init__(self, coeffs, zero):
            self._coeffs = list(coeffs)
            self._zero = zero

        def __call__(self, i):
            return sum(
                (
                    coeff * Ristretto255Scalar(i ** j)
                    for j, coeff in enumerate(self._coeffs)
                ),
                self._zero,
            )

        def __getitem__(self, idx):
            return self._coeffs[idx]

    def share_secret(self, share_count, qualified_size):
        gen = Ristretto255Point.random()

        alpha = self.Polynomial(
            (Ristretto255Scalar.random() for __ in range(qualified_size)),
            Ristretto255Scalar.ZERO,
        )

        secret = gen * alpha[0]
        shares = [(i, gen * alpha(i)) for i in range(1, share_count + 1)]

        return secret, shares

    def reconstruct(self, shares):
        return sum(
            (
                share
                * reduce(
                    mul,
                    (
                        Fraction(idx1, idx1 - idx0)
                        for idx1, __ in shares
                        if idx0 != idx1
                    ),
                    Fraction(1),
                )
                for idx0, share in shares
            ),
            Ristretto255Point.ZERO,
        )

    def test_shamir(self):
        secret0, shares = self.share_secret(5, 3)

        # Delete any two shares
        del shares[randrange(len(shares))]
        del shares[randrange(len(shares))]

        secret1 = self.reconstruct(shares)

        assert secret0 == secret1
