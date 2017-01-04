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

from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import PublicKey, PrivateKey

class TestPublicKey:
    def test_eq_returns_True_for_identical_keys(self):
        k1 = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
        k2 = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
        assert k1 == k2

    def test_eq_returns_False_for_wrong_type(self):
        k1 = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
        k2 = b"\x00" * crypto_box_PUBLICKEYBYTES
        assert k1 != k2

class TestPrivateKey:
    def test_eq_returns_True_for_identical_keys(self):
        k1 = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
        k2 = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
        assert k1 == k2

    def test_eq_returns_False_for_wrong_type(self):
        k1 = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
        k2 = b"\x00" * crypto_box_SECRETKEYBYTES
        assert k1 != k2
