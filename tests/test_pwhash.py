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

import nacl.bindings
import nacl.encoding
import nacl.exceptions as exc
import nacl.pwhash


@pytest.mark.parametrize(("size", "password", "salt",
                          "opslimit", "memlimit",
                          "expected"), [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b63d97",
            20000,
            (2 ** 20) * 100,
            (b"\x10e>\xc8A8\x11\xde\x07\xf1\x0f\x98"
             b"EG\xe6}V]\xd4yN\xae\xd3P\x87yP\x1b\xc7+n*")
        ),
    ],
)
def test_kdf_scryptsalsa208sha256(size, password, salt,
                                  opslimit, memlimit, expected):
    res = nacl.pwhash.kdf_scryptsalsa208sha256(size, password, salt,
                                               opslimit, memlimit)
    assert res == expected


@pytest.mark.parametrize(("password", ), [
    (
        b"The quick brown fox jumps over the lazy dog.",
    ),
])
def test_scryptsalsa208sha256_random(password):
    h1 = nacl.pwhash.scryptsalsa208sha256_str(password)
    h2 = nacl.pwhash.scryptsalsa208sha256_str(password)
    assert h1 != h2


@pytest.mark.parametrize(("password", ), [
    (
        b"The quick brown fox jumps over the lazy dog.",
    ),
])
def test_scryptsalsa208sha256_verify(password):
    assert nacl.pwhash.verify_scryptsalsa208sha256(
        nacl.pwhash.scryptsalsa208sha256_str(password),
        password
    )


@pytest.mark.parametrize(("password", ), [
    (
        b"The quick brown fox jumps over the lazy dog.",
    ),
])
def test_scryptsalsa208sha256_verify_incorrect(password):
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.verify_scryptsalsa208sha256(
            nacl.pwhash.scryptsalsa208sha256_str(password),
            password.replace(b'dog', b'cat')
        )


@pytest.mark.parametrize(("size", "password", "salt",
                          "opslimit", "memlimit"), [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9",
            20000,
            (2 ** 20) * 100
        ),
    ],
)
def test_wrong_salt_length(size, password, salt,
                           opslimit, memlimit):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.kdf_scryptsalsa208sha256(size, password, salt,
                                             opslimit, memlimit)


@pytest.mark.parametrize(("passwd_hash", "password"), [
        (
            b"Too short (and wrong) hash",
            b"a password",
        ),
    ],
)
def test_wrong_hash_length(passwd_hash, password):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.verify_scryptsalsa208sha256(passwd_hash,
                                                password)


@pytest.mark.parametrize(("size", "password", "salt",
                          "opslimit", "memlimit"), [
        (
            32,
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b6",
            20000,
            (2 ** 20) * 100
        ),
    ],
)
def test_kdf_wrong_salt_length(size, password, salt,
                               opslimit, memlimit):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.kdf_scryptsalsa208sha256(size, password, salt,
                                             opslimit, memlimit)


@pytest.mark.parametrize(("opslimit", "memlimit",
                          "n", "r", "p"), [
        (
            32768,
            2 * (2 ** 20),
            10,
            8,
            1
        ),
        (
            32768,
            8 * (2 ** 10),
            3,
            8,
            128
        ),
        (
            65536,
            (2 ** 20) * 2,
            11,
            8,
            1
        ),
        (
            262144,
            (2 ** 20) * 2,
            11,
            8,
            4
        ),
        (
            2 * (2 ** 20),
            2 * (2 ** 20),
            11,
            8,
            32
        ),
    ],
)
def test_variable_limits(opslimit, memlimit, n, r, p):
    rn, rr, rp = nacl.bindings.nacl_bindings_pick_scrypt_params(opslimit,
                                                                memlimit)
    assert rn == n
    assert rr == r
    assert rp == p


@pytest.mark.parametrize(("passwd_hash", "password"), [
        (
            b"Too short (and wrong) hash",
            b"another password",
        ),
    ],
)
def test_str_verify_wrong_hash_length(passwd_hash, password):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.verify_scryptsalsa208sha256(passwd_hash,
                                                password)
