# Copyright 2018 Donald Stufft and individual contributors
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
from collections import namedtuple

from hypothesis import given, settings
from hypothesis.strategies import binary, sampled_from

import pytest

from utils import read_kv_test_vectors

import nacl.bindings as b
import nacl.exceptions as exc

@pytest.mark.parametrize(("seed1", "seed2"), [
    (
        None,
        None
    ),
    (
        b'12345678901234567890123456789012',
        b'12345678901234567890123456789012'
    ),
    (
        b'23456789012345678901234567890123',
        b'34567890123456789012345678901234'
    ),
    (
        b'23456789012345678901234567890123',
        b'34567890123456789012345678901234'
    ),
    (
        b'27238674',
        b'345678901234567890123456789012342837472384'
    )
])
def test_crypto_kx_keypair(seed1, seed2):
    if seed1 is None:
        public_key, secret_key = b.crypto_kx_keypair()
        public_key_2, secret_key_2 = b.crypto_kx_keypair()
        assert public_key != public_key_2
        assert secret_key != secret_key_2
    elif len(seed1) < b.crypto_kx_SEED_BYTES:
        with pytest.raises(exc.TypeError):
            b.crypto_kx_keypair(seed1)
        with pytest.raises(exc.TypeError):
            b.crypto_kx_keypair(seed2)
    elif seed1 == seed2:
        seeded = b.crypto_kx_keypair(seed1)
        seeded_same = b.crypto_kx_keypair(seed2)
        assert seeded == seeded_same
    else:
        seeded = b.crypto_kx_keypair(seed1)
        seeded_other = b.crypto_kx_keypair(seed2)
        assert seeded != seeded_other

@pytest.mark.parametrize('execution_number', range(100))
def test_crypto_kx_session_keys(execution_number):
    server_keys = b.crypto_kx_keypair()
    client_keys = b.crypto_kx_keypair()

    server_decryption_key, server_encryption_key = b.crypto_kx_server_session_keys(server_keys[0], server_keys[1], client_keys[0])
    client_decryption_key, client_encryption_key = b.crypto_kx_client_session_keys(client_keys[0], client_keys[1], server_keys[0])

    assert client_decryption_key == server_encryption_key
    assert server_decryption_key == client_encryption_key

def test_crypto_kx_session_keys_wrong_length():
    server_keys = b.crypto_kx_keypair()
    client_keys = b.crypto_kx_keypair()

    with pytest.raises(exc.TypeError):
        b.crypto_kx_server_session_keys(server_keys[0][:-1], server_keys[1], client_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_client_session_keys(client_keys[0][:-1], client_keys[1], server_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_server_session_keys(server_keys[0], server_keys[1][:-1], client_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_client_session_keys(client_keys[0], client_keys[1][:-1], server_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_server_session_keys(server_keys[0], server_keys[1], client_keys[0][:-1])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_client_session_keys(client_keys[0], client_keys[1], server_keys[0][:-1])
