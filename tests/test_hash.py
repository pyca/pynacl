import nacl
import pytest


@pytest.mark.parametrize(("inp", "expected"), [
    (
        b"The quick brown fox jumps over the lazy dog.",
        b"ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
    ),
    (
        b"",
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
])
def test_sha256_hex(inp, expected):
    assert nacl.hash.sha256(inp) == expected


@pytest.mark.parametrize(("inp", "expected"), [
    (
        b"The quick brown fox jumps over the lazy dog.",
        b"\xEFS\x7F%\xC8\x95\xBF\xA7\x82Re)\xA9\xB6=\x97\xAAc\x15d\xD5\xD7\x89\xC2\xB7eD\x8C\x865\xFBl",
    ),
    (
        b"",
        b"\xe3\xb0\xc4B\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99o\xb9$'\xaeA\xe4d\x9b\x93L\xa4\x95\x99\x1bxR\xb8U",
    )
])
def test_sha256_binary(inp, expected):
    assert nacl.hash.sha256(inp, encoding="raw") == expected


@pytest.mark.parametrize(("inp", "expected"), [
    (
        b"The quick brown fox jumps over the lazy dog.",
        b"91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bbc6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
    ),
    (
        b"",
        b"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    )
])
def test_sha512_hex(inp, expected):
    assert nacl.hash.sha512(inp) == expected


@pytest.mark.parametrize(("inp", "expected"), [
    (
        b"The quick brown fox jumps over the lazy dog.",
        b"\x91\xEA\x12E\xF2\rF\xAE\x9A\x03z\x98\x9FT\xF1\xF7\x90\xF0\xA4v\a\xEE\xB8\xA1M\x12\x89\f\xEAw\xA1\xBB\xC6\xC7\xED\x9C\xF2\x05\xE6{\x7F+\x8F\xD4\xC7\xDF\xD3\xA7\xA8a~E\xF3\xC4c\xD4\x81\xC7\xE5\x86\xC3\x9A\xC1\xED",
    ),
    (
        b"",
        b"\xCF\x83\xE15~\xEF\xB8\xBD\xF1T(P\xD6m\x80\a\xD6 \xE4\x05\vW\x15\xDC\x83\xF4\xA9!\xD3l\xE9\xCEG\xD0\xD1<]\x85\xF2\xB0\xFF\x83\x18\xD2\x87~\xEC/c\xB91\xBDGAz\x81\xA582z\xF9'\xDA>",
    )
])
def test_sha512_binary(inp, expected):
    assert nacl.hash.sha512(inp, encoding="raw") == expected
