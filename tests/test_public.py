# Copyright 2013 Donald Stufft and individual contributors
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

import pytest

from utils import assert_equal, assert_not_equal

from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import PrivateKey, PublicKey


class TestPublicKey:
    def test_equal_keys_are_equal(self):
        k1 = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
        k2 = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
        assert_equal(k1, k1)
        assert_equal(k1, k2)

    @pytest.mark.parametrize('k2', [
        b"\x00" * crypto_box_PUBLICKEYBYTES,
        PublicKey(b"\x01" * crypto_box_PUBLICKEYBYTES),
        PublicKey(b"\x00" * (crypto_box_PUBLICKEYBYTES - 1) + b"\x01"),
    ])
    def test_different_keys_are_not_equal(self, k2):
        k1 = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
        assert_not_equal(k1, k2)


class TestPrivateKey:
    def test_equal_keys_are_equal(self):
        k1 = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
        k2 = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
        assert_equal(k1, k1)
        assert_equal(k1, k2)

    @pytest.mark.parametrize('k2', [
        b"\x00" * crypto_box_SECRETKEYBYTES,
        PrivateKey(b"\x01" * crypto_box_SECRETKEYBYTES),
        PrivateKey(b"\x00" * (crypto_box_SECRETKEYBYTES - 1) + b"\x01"),
    ])
    def test_different_keys_are_not_equal(self, k2):
        k1 = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
        assert_not_equal(k1, k2)
