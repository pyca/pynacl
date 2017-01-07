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

from __future__ import absolute_import, division, print_function

import pytest

import nacl.encoding
import nacl.pw_hash


@pytest.mark.parametrize(("size", "password", "salt", "expected"), [
    (
        32,
        b"The quick brown fox jumps over the lazy dog.",
        b"ef537f25c895bfa782526529a9b63d97",
        b"\x10e>\xc8A8\x11\xde\x07\xf1\x0f\x98EG\xe6}V]\xd4yN\xae\xd3P\x87yP\x1b\xc7+n*",
    ),
])
def test_kdf_scryptsalsa208sha256(size, password, salt, expected):
    assert nacl.pw_hash.kdf_scryptsalsa208sha256(size, password, salt) == expected


@pytest.mark.parametrize(("password", ), [
    (
        b"The quick brown fox jumps over the lazy dog.",
    ),
])
def test_scryptsalsa208sha256_random(password):
    assert nacl.pw_hash.scryptsalsa208sha256(password) != \
           nacl.pw_hash.scryptsalsa208sha256(password)


@pytest.mark.parametrize(("password", ), [
    (
        b"The quick brown fox jumps over the lazy dog.",
    ),
])
def test_scryptsalsa208sha256_verify(password):
    assert nacl.pw_hash.verify_scryptsalsa208sha256(
        nacl.pw_hash.scryptsalsa208sha256(password),
        password
    )


@pytest.mark.parametrize(("password", ), [
    (
        b"The quick brown fox jumps over the lazy dog.",
    ),
])
def test_scryptsalsa208sha256_verify_incorrect(password):
    assert not nacl.pw_hash.verify_scryptsalsa208sha256(
        nacl.pw_hash.scryptsalsa208sha256(password),
        password.replace(b'dog', b'cat')
    )
