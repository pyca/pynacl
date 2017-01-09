# Copyright 2016 Donald Stufft and individual contributors
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

import pytest

import nacl.encoding
import nacl.exceptions as exc
import nacl.hash
from nacl.utils import bytes_as_string

OVERLONG_PARAMS_VECTORS = [
    (b'key', 65*b'\xaa', 16*b'\xaa', 16*b'\x55', 64, b'will raise'),
    (b'salt', b'key', 17*b'\xaa', 16*b'\x55', 64, b'will raise'),
    (b'personal', b'key', 16*b'\xaa', 17*b'\x55', 64, b'will raise'),
    (b'digest_size', b'key', 16*b'\xaa', 16*b'\x55', 65, b'will raise'),
]


def _read_crypto_test_vectors(fname):
    vectors = []
    path = os.path.join(os.path.dirname(__file__), "data", fname)
    with open(path, "r") as fp:
        for line in fp:
            line = line.rstrip()
            if line[0] == '#':
                continue
            splt = [x for x in line.split('\t')]
            vectors.append(tuple(splt))
    return vectors


def generichash_vectors():
    # Format: <message> <tab> <key> <tab> <output length> <tab> <output>
    DATA = "crypto-test-vectors-blake2-nosalt-nopersonalization.txt"
    return _read_crypto_test_vectors(DATA)


def blake2_salt_pers_vectors():
    # Format: <message> <tab> <key> <tab> <salt> <tab>
    # <personalization> <tab> <output length> <tab> <output>
    DATA = "crypto-test-vectors-blake2-salt-personalization.txt"
    return _read_crypto_test_vectors(DATA)


def blake2_reference_vectors():
    DATA = "blake2-kat.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    jvectors = json.load(open(path))
    vectors = [(x["in"], x["key"], len(x["out"]) // 2,
                x["out"])
               for x in jvectors if x["hash"] == "blake2b"]
    return vectors


@pytest.mark.parametrize(["message", "key", "outlen", "output"],
                         generichash_vectors())
def test_generichash(message, key, outlen, output):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = nacl.hash.generichash(msg, digest_size=outlen, key=k)
    assert (bytes_as_string(out) == output)


@pytest.mark.parametrize(["message", "key", "salt", "person", "outlen",
                          "output"],
                         OVERLONG_PARAMS_VECTORS)
def test_overlong_blake2b_oneshot_params(message, key, salt, person,
                                         outlen, output):
    with pytest.raises(exc.ValueError):
        nacl.hash.blake2b(message, digest_size=outlen, key=key,
                          salt=salt, person=person)


@pytest.mark.parametrize(["message", "key", "outlen", "output"],
                         blake2_reference_vectors())
def test_generichash_blake2_ref(message, key, outlen, output):
    test_generichash(message, key, outlen, output)


@pytest.mark.parametrize(["message", "key", "salt", "person", "outlen",
                          "output"],
                         blake2_salt_pers_vectors())
def test_hash_blake2b(message, key, salt, person, outlen, output):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    slt = binascii.unhexlify(salt)
    pers = binascii.unhexlify(person)
    outlen = int(outlen)
    out = nacl.hash.blake2b(msg, digest_size=outlen, key=k,
                            salt=slt, person=pers)
    assert (bytes_as_string(out) == output)
