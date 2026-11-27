# Copyright 2026 Donald Stufft and individual contributors
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

from binascii import hexlify, unhexlify

import pytest

from nacl import bindings as c


def tohex(b: bytes) -> str:
    return hexlify(b).decode("ascii")


def test_stream():
    key = b"\x00" * c.crypto_stream_KEYBYTES
    nonce = b"\x01" * c.crypto_stream_NONCEBYTES

    # The raw keystream equals crypto_stream_xor of an all-zero message
    stream = c.crypto_stream(64, nonce, key)
    assert len(stream) == 64
    assert stream == c.crypto_stream_xor(b"\x00" * 64, nonce, key)

    # Deterministic for a fixed key/nonce pair
    assert c.crypto_stream(64, nonce, key) == stream

    # Different nonce or length changes the output
    assert c.crypto_stream(32, nonce, key) == stream[:32]
    nonce2 = b"\x02" * c.crypto_stream_NONCEBYTES
    assert c.crypto_stream(64, nonce2, key) != stream

    # Length 0 yields empty bytes
    assert c.crypto_stream(0, nonce, key) == b""


def test_stream_wrong_length():
    key = b"\x00" * c.crypto_stream_KEYBYTES
    nonce = b"\x01" * c.crypto_stream_NONCEBYTES

    with pytest.raises(ValueError):
        c.crypto_stream(-1, nonce, key)
    with pytest.raises(ValueError):
        c.crypto_stream(8, nonce, b"")
    with pytest.raises(ValueError):
        c.crypto_stream(8, b"", key)
    with pytest.raises(ValueError):
        c.crypto_stream(c.crypto_stream_MESSAGEBYTES_MAX + 1, nonce, key)


def test_stream_wrong_type():
    # Type safety: mypy can spot these errors, but we want to make sure they're
    # caught at runtime too
    key = b"\x00" * c.crypto_stream_KEYBYTES
    nonce = b"\x01" * c.crypto_stream_NONCEBYTES

    with pytest.raises(TypeError):
        c.crypto_stream(8.0, nonce, key)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        c.crypto_stream(8, None, key)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        c.crypto_stream(8, nonce, None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        c.crypto_stream_xor(b"message", None, key)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        c.crypto_stream_xor(b"message", nonce, None)  # type: ignore[arg-type]


def test_stream_xor_known_answer():
    # Key/nonce values taken from libsodium (test/default/stream.c)
    key = unhexlify(
        b"1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
    )
    nonce = unhexlify(b"69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
    stream = c.crypto_stream_xor(b"\x00" * 32, nonce, key)
    assert len(stream) == 32
    assert tohex(stream) == (
        "eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880"
    )


def test_stream_xor_roundtrip():
    key = b"\x00" * c.crypto_stream_KEYBYTES
    nonce = b"\x01" * c.crypto_stream_NONCEBYTES
    message = b"message"
    ct = c.crypto_stream_xor(message, nonce, key)
    assert c.crypto_stream_xor(ct, nonce, key) == message
    # Same key/nonce, different message produces different output
    ct2 = c.crypto_stream_xor(b"message!", nonce, key)
    assert ct2 != ct
    # Changing the nonce changes the output
    nonce2 = b"\x02" * c.crypto_stream_NONCEBYTES
    ct3 = c.crypto_stream_xor(message, nonce2, key)
    assert ct3 != ct


def test_stream_xor_wrong_length():
    with pytest.raises(ValueError):
        c.crypto_stream_xor(b"", b"", b"")
    with pytest.raises(ValueError):
        c.crypto_stream_xor(b"", b"", b"\x00" * c.crypto_stream_KEYBYTES)
    with pytest.raises(ValueError):
        c.crypto_stream_xor(b"", b"\x00" * c.crypto_stream_NONCEBYTES, b"")


def test_stream_keygen():
    k1 = c.crypto_stream_keygen()
    k2 = c.crypto_stream_keygen()
    assert len(k1) == c.crypto_stream_KEYBYTES
    # Practically impossible that two are equal
    assert k1 != k2
