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

from binascii import hexlify, unhexlify
from nacl import c
import hashlib


def tohex(b):
    return hexlify(b).decode("ascii")


def test_hash():
    msg = b"message"
    h1 = c.crypto_hash(msg)
    assert len(h1) == c.crypto_hash_BYTES
    assert tohex(h1) == ("f8daf57a3347cc4d6b9d575b31fe6077"
                         "e2cb487f60a96233c08cb479dbf31538"
                         "cc915ec6d48bdbaa96ddc1a16db4f4f9"
                         "6f37276cfcb3510b8246241770d5952c")
    assert tohex(h1) == hashlib.sha512(msg).hexdigest()

    h2 = c.crypto_hash_sha512(msg)
    assert len(h2) == c.crypto_hash_sha512_BYTES
    assert tohex(h2) == tohex(h1)

    h3 = c.crypto_hash_sha256(msg)
    assert len(h3) == c.crypto_hash_sha256_BYTES
    assert tohex(h3) == ("ab530a13e45914982b79f9b7e3fba994"
                         "cfd1f3fb22f71cea1afbf02b460c6d1d")
    assert tohex(h3) == hashlib.sha256(msg).hexdigest()


def test_secretbox():
    key = b"\x00" * c.crypto_secretbox_KEYBYTES
    msg = b"message"
    nonce = b"\x01" * c.crypto_secretbox_NONCEBYTES
    ct = c.crypto_secretbox(msg, nonce, key)
    assert len(ct) == len(msg) + c.crypto_secretbox_BOXZEROBYTES
    assert tohex(ct) == "3ae84dfb89728737bd6e2c8cacbaf8af3d34cc1666533a"
    msg2 = c.crypto_secretbox_open(ct, nonce, key)
    assert msg2 == msg


def test_box():
    A_pubkey, A_secretkey = c.crypto_box_keypair()
    assert len(A_secretkey) == c.crypto_box_SECRETKEYBYTES
    assert len(A_pubkey) == c.crypto_box_PUBLICKEYBYTES
    B_pubkey, B_secretkey = c.crypto_box_keypair()

    k1 = c.crypto_box_beforenm(B_pubkey, A_secretkey)
    assert len(k1) == c.crypto_box_BEFORENMBYTES
    k2 = c.crypto_box_beforenm(A_pubkey, B_secretkey)
    assert tohex(k1) == tohex(k2)

    message = b"message"
    nonce = b"\x01" * c.crypto_box_NONCEBYTES
    ct1 = c.crypto_box_afternm(message, nonce, k1)
    assert len(ct1) == len(message) + c.crypto_box_BOXZEROBYTES

    ct2 = c.crypto_box(message, nonce, B_pubkey, A_secretkey)
    assert tohex(ct2) == tohex(ct1)

    m1 = c.crypto_box_open(ct1, nonce, A_pubkey, B_secretkey)
    assert m1 == message

    m2 = c.crypto_box_open_afternm(ct1, nonce, k1)
    assert m2 == message


def test_sign():
    seed = b"\x00" * c.crypto_sign_SEEDBYTES
    pubkey, secretkey = c.crypto_sign_seed_keypair(seed)
    assert len(pubkey) == c.crypto_sign_PUBLICKEYBYTES
    assert len(secretkey) == c.crypto_sign_SECRETKEYBYTES

    pubkey, secretkey = c.crypto_sign_keypair()
    assert len(pubkey) == c.crypto_sign_PUBLICKEYBYTES
    assert len(secretkey) == c.crypto_sign_SECRETKEYBYTES

    msg = b"message"
    sigmsg = c.crypto_sign(msg, secretkey)
    assert len(sigmsg) == len(msg) + c.crypto_sign_BYTES

    msg2 = c.crypto_sign_open(sigmsg, pubkey)
    assert msg2 == msg


def secret_scalar():
    pubkey, secretkey = c.crypto_box_keypair()
    assert len(secretkey) == c.crypto_box_SECRETKEYBYTES
    assert c.crypto_box_SECRETKEYBYTES == c.crypto_scalarmult_BYTES
    return secretkey, pubkey


def test_scalarmult():
    x, xpub = secret_scalar()
    assert len(x) == 32
    y, ypub = secret_scalar()
    # the Curve25519 base point (generator)
    base = unhexlify(b"09" + b"00"*31)

    bx1 = c.crypto_scalarmult_base(x)
    bx2 = c.crypto_scalarmult(x, base)
    assert tohex(bx1) == tohex(bx2)
    assert tohex(bx1) == tohex(xpub)

    xby = c.crypto_scalarmult(x, c.crypto_scalarmult_base(y))
    ybx = c.crypto_scalarmult(y, c.crypto_scalarmult_base(x))
    assert tohex(xby) == tohex(ybx)

    z = unhexlify(b"10"*32)
    bz1 = c.crypto_scalarmult_base(z)
    assert tohex(bz1) == ("781faab908430150daccdd6f9d6c5086"
                          "e34f73a93ebbaa271765e5036edfc519")
    bz2 = c.crypto_scalarmult(z, base)
    assert tohex(bz1) == tohex(bz2)
