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

import binascii
import json
import os
import random
import sys
import unicodedata as ud

import pytest

from six import unichr

import nacl.bindings
import nacl.encoding
import nacl.exceptions as exc
import nacl.pwhash


_all_unicode = u''.join(unichr(i) for i in range(sys.maxunicode))
PASSWD_CHARS = u''.join(c for c in _all_unicode
                        if (ud.category(c).startswith('L') or
                            ud.category(c).startswith('N') or
                            ud.category(c) == 'Zs'
                            )
                        )
# Select Letters, number representations and spacing characters


def argon2i_modular_crypt_ref():
    DATA = "modular_crypt_argon2i_hashes.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    jvectors = json.load(open(path))
    vectors = [(x["pwhash"], x["passwd"])
               for x in jvectors if x["mode"] == "crypt"]
    return vectors


def argon2i_raw_ref():
    DATA = "raw_argon2i_hashes.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    jvectors = json.load(open(path))
    vectors = [(x["dgst_len"], x["passwd"], x["salt"], x["iters"],
                x["maxmem"], x["pwhash"])
               for x in jvectors if x["mode"] == "raw"]
    return vectors


def random_utf8_password_gen(minlen=5, maxlen=20):
    rng = random.SystemRandom()

    def _genpsw(rng, lmin, lmax):
        ln = rng.randint(lmin, lmax)
        psw = u''.join(rng.choice(PASSWD_CHARS)
                       for c in range(ln)).encode('utf8')
        return psw
    while True:
        yield _genpsw(rng, minlen, maxlen)


def gen_argon2i_str_params(n,
                           min_ops=nacl.pwhash.ARGON2I_OPSLIMIT_INTERACTIVE,
                           max_ops=nacl.pwhash.ARGON2I_OPSLIMIT_MODERATE,
                           min_mem=nacl.pwhash.ARGON2I_MEMLIMIT_INTERACTIVE,
                           max_mem=nacl.pwhash.ARGON2I_MEMLIMIT_MODERATE):
    rng = random.SystemRandom()
    pwgen = random_utf8_password_gen()
    rn = [(next(pwgen),
           rng.randint(min_ops, max_ops),
           rng.randint(min_mem, max_mem))
          for c in range(n)]
    return rn


@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit", "expected"),
    [
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


@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit"),
    [
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


@pytest.mark.parametrize(
    ("passwd_hash", "password"),
    [
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


@pytest.mark.parametrize(
    ("size", "password", "salt", "opslimit", "memlimit"),
    [
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


@pytest.mark.parametrize(
    ("opslimit", "memlimit", "n", "r", "p"),
    [
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


@pytest.mark.parametrize(
    ("passwd_hash", "password"),
    [
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


@pytest.mark.parametrize(("password_hash", "password"),
                         argon2i_modular_crypt_ref())
def test_str_verify_argon2i_ref(password_hash, password):
    pw_hash = password_hash.encode('ascii')
    pw = password.encode('ascii')
    res = nacl.pwhash.verify_argon2i(pw_hash, pw)
    assert res is True


@pytest.mark.parametrize(("password_hash", "password"),
                         argon2i_modular_crypt_ref())
def test_str_verify_argon2i_ref_fail(password_hash, password):
    pw_hash = password_hash.encode('ascii')
    pw = ('a' + password).encode('ascii')
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.verify_argon2i(pw_hash, pw)


@pytest.mark.parametrize(("password", "ops", "mem"),
                         gen_argon2i_str_params(10,
                                                min_ops=4,
                                                max_ops=6,
                                                min_mem=1024 * 1024,
                                                max_mem=16 * 1024 * 1024))
def test_argon2i_str_and_verify(password, ops, mem):
    pw_hash = nacl.pwhash.argon2i_str(password, opslimit=ops, memlimit=mem)
    res = nacl.pwhash.verify_argon2i(pw_hash, password)
    assert res is True


@pytest.mark.parametrize(("password", "ops", "mem"),
                         gen_argon2i_str_params(10,
                                                min_ops=4,
                                                max_ops=6,
                                                min_mem=1024 * 1024,
                                                max_mem=16 * 1024 * 1024))
def test_argon2i_str_and_verify_fail(password, ops, mem):
    pw_hash = nacl.pwhash.argon2i_str(password, opslimit=ops, memlimit=mem)
    with pytest.raises(exc.InvalidkeyError):
        nacl.pwhash.verify_argon2i(pw_hash, b'A' + password)


@pytest.mark.parametrize(("dk_size", "password", "salt",
                          "iters", "mem_kb", "pwhash"),
                         argon2i_raw_ref())
def test_argon2i_kdf(dk_size, password, salt, iters, mem_kb, pwhash):
    dk = nacl.pwhash.kdf_argon2i(dk_size, password.encode('utf-8'),
                                 salt.encode('utf-8'), iters, 1024 * mem_kb)
    ref = binascii.unhexlify(pwhash)
    assert dk == ref


@pytest.mark.parametrize(
    ("dk_size", "password", "salt", "iters", "mem_kb"),
    [
        #  wrong salt length:
        (20, "aPassword", 3 * "salt", 3, 256),
        #  too short output:
        (15, "aPassword", 4 * "salt", 4, 256),
        #  too long output:
        (0xFFFFFFFF + 1, "aPassword", 4 * "salt", 4, 256),
        #  too low iteration count:
        (20, "aPassword", 4 * "salt", 1, 256),
        #  too high interation count:
        (20, "aPassword", 4 * "salt", 0xFFFFFFFF + 1, 256),
        #  too low memory usage:
        (20, "aPassword", 4 * "salt", 4, 2),
        #  too high memory usage:
        (20, "aPassword", 4 * "salt", 4, 0xFFFFFFFF + 1),
    ]
)
def test_argon2i_kdf_invalid_parms(dk_size, password, salt, iters, mem_kb):
    with pytest.raises(exc.ValueError):
        nacl.pwhash.kdf_argon2i(dk_size, password.encode('utf-8'),
                                salt.encode('utf-8'), iters, 1024 * mem_kb)
