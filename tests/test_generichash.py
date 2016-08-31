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
import nacl.hash
import nacl.hashlib
from nacl.utils import bytes_as_string


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


@pytest.mark.parametrize(["message", "key", "outlen", "output"],
                         blake2_reference_vectors())
def test_generichash_blake2_ref(message, key, outlen, output):
    test_generichash(message, key, outlen, output)


@pytest.mark.parametrize(["message", "key", "salt", "personal", "outlen",
                          "output"],
                         blake2_salt_pers_vectors())
def test_hash_blake2b(message, key, salt, personal, outlen, output):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    slt = binascii.unhexlify(salt)
    pers = binascii.unhexlify(personal)
    outlen = int(outlen)
    out = nacl.hash.blake2b(msg, digest_size=outlen, key=k,
                            salt=slt, personal=pers)
    assert (bytes_as_string(out) == output)


@pytest.mark.parametrize(["message", "key", "outlen", "output"],
                         blake2_reference_vectors())
def test_hashlib_blake2_ref_vectors(message, key, outlen, output):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = binascii.unhexlify(output)
    h = nacl.hashlib.blake2b(msg, digest_size=outlen, key=k)
    dgst = h.digest()
    assert (out == dgst)


@pytest.mark.parametrize(["message", "key", "outlen", "output"],
                         blake2_reference_vectors())
def test_hashlib_blake2_iuf_ref_vectors(message, key, outlen, output):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = binascii.unhexlify(output)
    h = nacl.hashlib.generic(digest_size=outlen, key=k)
    for _pos in range(len(msg)):
        _end = _pos + 1
        h.update(bytes(msg[_pos:_end]))
    dgst = h.digest()
    hdgst = h.hexdigest()
    assert (hdgst == output)
    assert (out == dgst)


@pytest.mark.parametrize(["message", "key", "outlen", "output"],
                         blake2_reference_vectors())
def test_hashlib_blake2_iuf_cp_ref_vectors(message, key, outlen, output):
    msg = binascii.unhexlify(message)
    msglen = len(msg)
    if msglen < 2:
        pytest.skip("Message too short for splitting")
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = binascii.unhexlify(output)
    h = nacl.hashlib.generic(digest_size=outlen, key=k)
    for _pos in range(len(msg)):
        _end = _pos + 1
        h.update(bytes(msg[_pos:_end]))
        if _end == msglen // 2:
            h2 = h.copy()
    dgst = h.digest()
    d2 = h2.digest()
    assert (out == dgst)
    assert (d2 != dgst)
