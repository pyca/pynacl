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

import nacl.encoding
import nacl.hash


@pytest.mark.parametrize(
    ("inp", "expected"),
    [
        (
            b"The quick brown fox jumps over the lazy dog.",
            b"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        ),
        (
            b"",
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ],
)
def test_sha256_hex(inp: bytes, expected: bytes):
    assert nacl.hash.sha256(inp) == expected


@pytest.mark.parametrize(
    ("inp", "expected"),
    [
        (
            b"The quick brown fox jumps over the lazy dog.",
            (
                b"\xefS\x7f%\xc8\x95\xbf\xa7\x82Re)\xa9\xb6=\x97\xaac\x15d\xd5\xd7"
                b"\x89\xc2\xb7eD\x8c\x865\xfbl"
            ),
        ),
        (
            b"",
            (
                b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d"
                b"\x9b\x93L\xa4\x95\x99\x1bxR\xb8U"
            ),
        ),
    ],
)
def test_sha256_binary(inp: bytes, expected: bytes):
    assert nacl.hash.sha256(inp, encoder=nacl.encoding.RawEncoder) == expected


@pytest.mark.parametrize(
    ("inp", "expected"),
    [
        (
            b"The quick brown fox jumps over the lazy dog.",
            (
                b"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c"
                b"7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed"
            ),
        ),
        (
            b"",
            (
                b"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d"
                b"0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            ),
        ),
    ],
)
def test_sha512_hex(inp: bytes, expected: bytes):
    assert nacl.hash.sha512(inp) == expected


@pytest.mark.parametrize(
    ("inp", "expected"),
    [
        (
            b"The quick brown fox jumps over the lazy dog.",
            (
                b"\x91\xea\x12E\xf2\rF\xae\x9a\x03z\x98\x9fT\xf1\xf7\x90\xf0\xa4v\a"
                b"\xee\xb8\xa1M\x12\x89\f\xeaw\xa1\xbb\xc6\xc7\xed\x9c\xf2\x05\xe6{"
                b"\x7f+\x8f\xd4\xc7\xdf\xd3\xa7\xa8a~E\xf3\xc4c\xd4\x81\xc7\xe5\x86"
                b"\xc3\x9a\xc1\xed"
            ),
        ),
        (
            b"",
            (
                b"\xcf\x83\xe15~\xef\xb8\xbd\xf1T(P\xd6m\x80\a\xd6 \xe4\x05\vW\x15"
                b"\xdc\x83\xf4\xa9!\xd3l\xe9\xceG\xd0\xd1<]\x85\xf2\xb0\xff\x83\x18"
                b"\xd2\x87~\xec/c\xb91\xbdGAz\x81\xa582z\xf9'\xda>"
            ),
        ),
    ],
)
def test_sha512_binary(inp: bytes, expected: bytes):
    assert nacl.hash.sha512(inp, encoder=nacl.encoding.RawEncoder) == expected
