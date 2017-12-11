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
import sys

from hypothesis import given, settings
from hypothesis.strategies import binary

import pytest

from utils import read_kv_test_vectors

import nacl.bindings as b
import nacl.exceptions as exc


def chacha20poly1305_agl_vectors():
    # NIST vectors derived format
    DATA = "chacha20-poly1305-agl_ref.txt"
    return read_kv_test_vectors(DATA, delimiter=b':', newrecord=b'AEAD')


def chacha20poly1305_ietf_vectors():
    # NIST vectors derived format
    DATA = "chacha20-poly1305-ietf_ref.txt"
    return read_kv_test_vectors(DATA, delimiter=b':', newrecord=b'AEAD')


def xchacha20poly1305_ietf_vectors():
    # NIST vectors derived format
    DATA = "xchacha20-poly1305-ietf_ref.txt"
    return read_kv_test_vectors(DATA, delimiter=b':', newrecord=b'AEAD')


@pytest.mark.parametrize("kv",
                         chacha20poly1305_agl_vectors())
def test_chacha20poly1305(kv):
    msg = binascii.unhexlify(kv['IN'])
    ad = binascii.unhexlify(kv['AD'])
    nonce = binascii.unhexlify(kv['NONCE'])
    k = binascii.unhexlify(kv['KEY'])
    _tag = kv.get('TAG', b'')
    exp = binascii.unhexlify(kv['CT']) + binascii.unhexlify(_tag)
    out = b.crypto_aead_chacha20poly1305_encrypt(msg, ad, nonce, k)
    assert (out == exp)


@pytest.mark.parametrize("kv",
                         chacha20poly1305_ietf_vectors())
def test_chacha20poly1305_ietf(kv):
    msg = binascii.unhexlify(kv['IN'])
    ad = binascii.unhexlify(kv['AD'])
    nonce = binascii.unhexlify(kv['NONCE'])
    k = binascii.unhexlify(kv['KEY'])
    exp = binascii.unhexlify(kv['CT']) + binascii.unhexlify(kv['TAG'])
    out = b.crypto_aead_chacha20poly1305_ietf_encrypt(msg, ad, nonce, k)
    assert (out == exp)


@pytest.mark.parametrize("kv",
                         xchacha20poly1305_ietf_vectors())
def test_xchacha20poly1305_ietf(kv):
    msg = binascii.unhexlify(kv['IN'])
    ad = binascii.unhexlify(kv['AD'])
    nonce = binascii.unhexlify(kv['NONCE'])
    k = binascii.unhexlify(kv['KEY'])
    exp = binascii.unhexlify(kv['CT']) + binascii.unhexlify(kv['TAG'])
    out = b.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, ad, nonce, k)
    assert (out == exp)


@given(binary(min_size=0, max_size=100),
       binary(min_size=0, max_size=50),
       binary(min_size=b.crypto_aead_chacha20poly1305_NPUBBYTES,
              max_size=b.crypto_aead_chacha20poly1305_NPUBBYTES),
       binary(min_size=b.crypto_aead_chacha20poly1305_KEYBYTES,
              max_size=b.crypto_aead_chacha20poly1305_KEYBYTES))
@settings(deadline=1500, max_examples=20)
def test_chacha20poly1305_roundtrip(message, aad, nonce, key):
    ct = b.crypto_aead_chacha20poly1305_encrypt(message,
                                                aad,
                                                nonce,
                                                key)

    pt = b.crypto_aead_chacha20poly1305_decrypt(ct,
                                                aad,
                                                nonce,
                                                key)

    assert pt == message
    with pytest.raises(exc.CryptoError):
        ct1 = bytearray(ct)
        ct1[0] = ct1[0] ^ 0xff
        b.crypto_aead_chacha20poly1305_decrypt(ct1,
                                               aad,
                                               nonce,
                                               key)


@given(binary(min_size=0, max_size=100),
       binary(min_size=0, max_size=50),
       binary(min_size=b.crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
              max_size=b.crypto_aead_chacha20poly1305_ietf_NPUBBYTES),
       binary(min_size=b.crypto_aead_chacha20poly1305_ietf_KEYBYTES,
              max_size=b.crypto_aead_chacha20poly1305_ietf_KEYBYTES))
@settings(deadline=1500, max_examples=20)
def test_chacha20poly1305_ietf_roundtrip(message, aad, nonce, key):
    ct = b.crypto_aead_chacha20poly1305_ietf_encrypt(message,
                                                     aad,
                                                     nonce,
                                                     key)

    pt = b.crypto_aead_chacha20poly1305_ietf_decrypt(ct,
                                                     aad,
                                                     nonce,
                                                     key)

    assert pt == message
    with pytest.raises(exc.CryptoError):
        ct1 = bytearray(ct)
        ct1[0] = ct1[0] ^ 0xff
        b.crypto_aead_chacha20poly1305_ietf_decrypt(ct1,
                                                    aad,
                                                    nonce,
                                                    key)


@given(binary(min_size=0, max_size=100),
       binary(min_size=0, max_size=50),
       binary(min_size=b.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
              max_size=b.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES),
       binary(min_size=b.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
              max_size=b.crypto_aead_xchacha20poly1305_ietf_KEYBYTES))
@settings(deadline=1500, max_examples=20)
def test_xchacha20poly1305_ietf_roundtrip(message, aad, nonce, key):
    ct = b.crypto_aead_xchacha20poly1305_ietf_encrypt(message,
                                                      aad,
                                                      nonce,
                                                      key)

    pt = b.crypto_aead_xchacha20poly1305_ietf_decrypt(ct,
                                                      aad,
                                                      nonce,
                                                      key)

    assert pt == message
    with pytest.raises(exc.CryptoError):
        ct1 = bytearray(ct)
        ct1[0] = ct1[0] ^ 0xff
        b.crypto_aead_xchacha20poly1305_ietf_decrypt(ct1,
                                                     aad,
                                                     nonce,
                                                     key)


def test_chacha20poly1305_wrong_params():
    nonce = b'\x00' * b.crypto_aead_chacha20poly1305_NPUBBYTES
    key = b'\x00' * b.crypto_aead_chacha20poly1305_KEYBYTES
    aad = None
    b.crypto_aead_chacha20poly1305_encrypt(b'',
                                           aad,
                                           nonce,
                                           key)
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_encrypt(b'',
                                               aad,
                                               nonce[:-1],
                                               key)

    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_encrypt(b'',
                                               aad,
                                               nonce,
                                               key[:-1])
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_encrypt(b'',
                                               aad,
                                               nonce.decode('utf-8'),
                                               key)
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_encrypt(b'',
                                               aad,
                                               nonce,
                                               key.decode('utf-8'))


@pytest.mark.skipif(sys.version_info < (3,),
                    reason="Python 2 doesn't distinguish str() from bytes()")
def test_chacha20poly1305_str_msg():
    nonce = b'\x00' * b.crypto_aead_chacha20poly1305_NPUBBYTES
    key = b'\x00' * b.crypto_aead_chacha20poly1305_KEYBYTES
    aad = None
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_encrypt('',
                                               aad,
                                               nonce,
                                               key)


def test_chacha20poly1305_ietf_wrong_params():
    nonce = b'\x00' * b.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    key = b'\x00' * b.crypto_aead_chacha20poly1305_ietf_KEYBYTES
    aad = None
    b.crypto_aead_chacha20poly1305_ietf_encrypt(b'',
                                                aad,
                                                nonce,
                                                key)
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_ietf_encrypt(b'',
                                                    aad,
                                                    nonce[:-1],
                                                    key)

    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_ietf_encrypt(b'',
                                                    aad,
                                                    nonce,
                                                    key[:-1])
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_ietf_encrypt(b'',
                                                    aad,
                                                    nonce.decode('utf-8'),
                                                    key)
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_ietf_encrypt(b'',
                                                    aad,
                                                    nonce,
                                                    key.decode('utf-8'))


@pytest.mark.skipif(sys.version_info < (3,),
                    reason="Python 2 doesn't distinguish str() from bytes()")
def test_chacha20poly1305_ietf_str_msg():
    nonce = b'\x00' * b.crypto_aead_chacha20poly1305_ietf_NPUBBYTES
    key = b'\x00' * b.crypto_aead_chacha20poly1305_ietf_KEYBYTES
    aad = None
    with pytest.raises(exc.TypeError):
        b.crypto_aead_chacha20poly1305_ietf_encrypt('',
                                                    aad,
                                                    nonce,
                                                    key)


def test_xchacha20poly1305_ietf_wrong_params():
    nonce = b'\x00' * b.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    key = b'\x00' * b.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    aad = None
    b.crypto_aead_xchacha20poly1305_ietf_encrypt(b'',
                                                 aad,
                                                 nonce,
                                                 key)
    with pytest.raises(exc.TypeError):
        b.crypto_aead_xchacha20poly1305_ietf_encrypt(b'',
                                                     aad,
                                                     nonce[:-1],
                                                     key)

    with pytest.raises(exc.TypeError):
        b.crypto_aead_xchacha20poly1305_ietf_encrypt(b'',
                                                     aad,
                                                     nonce,
                                                     key[:-1])
    with pytest.raises(exc.TypeError):
        b.crypto_aead_xchacha20poly1305_ietf_encrypt(b'',
                                                     aad,
                                                     nonce.decode('utf-8'),
                                                     key)
    with pytest.raises(exc.TypeError):
        b.crypto_aead_xchacha20poly1305_ietf_encrypt(b'',
                                                     aad,
                                                     nonce,
                                                     key.decode('utf-8'))


@pytest.mark.skipif(sys.version_info < (3,),
                    reason="Python 2 doesn't distinguish str() from bytes()")
def test_xchacha20poly1305_ietf_str_msg():
    nonce = b'\x00' * b.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    key = b'\x00' * b.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    aad = None
    with pytest.raises(exc.TypeError):
        b.crypto_aead_xchacha20poly1305_ietf_encrypt('',
                                                     aad,
                                                     nonce,
                                                     key)
