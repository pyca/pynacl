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

from binascii import hexlify
from nacl import c
import hashlib

def test_hash():
    msg = "message"
    h1 = c.crypto_hash(msg)
    assert len(h1) == c.crypto_hash_BYTES
    assert hexlify(h1) == "f8daf57a3347cc4d6b9d575b31fe6077e2cb487f60a96233c08cb479dbf31538cc915ec6d48bdbaa96ddc1a16db4f4f96f37276cfcb3510b8246241770d5952c"
    assert hexlify(h1) == hashlib.sha512(msg).hexdigest()

    h2 = c.crypto_hash_sha512(msg)
    assert len(h2) == c.crypto_hash_sha512_BYTES
    assert hexlify(h2) == hexlify(h1)

    h3 = c.crypto_hash_sha256(msg)
    assert len(h3) == c.crypto_hash_sha256_BYTES
    assert hexlify(h3) == "ab530a13e45914982b79f9b7e3fba994cfd1f3fb22f71cea1afbf02b460c6d1d"
    assert hexlify(h3) == hashlib.sha256(msg).hexdigest()


def test_secretbox():
    key = "\x00" * c.crypto_secretbox_KEYBYTES
    msg = "message"
    nonce = "\x01" * c.crypto_secretbox_NONCEBYTES
    # TODO: NaCl is secretbox(msg,nonce,key)
    ct = c.crypto_secretbox(key, msg, nonce)
    assert len(ct) == len(msg) + c.crypto_secretbox_BOXZEROBYTES
    assert hexlify(ct) == "3ae84dfb89728737bd6e2c8cacbaf8af3d34cc1666533a"
    # TODO: NaCl is secretbox_open(ct,nonce,key)
    msg2 = c.crypto_secretbox_open(key, ct, nonce)
    assert msg2 == msg

def test_box():
    # TODO: NaCl C++ is pk=box_keypair(sk), C is box_keypair(pk,sk)
    A_secretkey, A_pubkey = c.crypto_box_keypair()
    assert len(A_secretkey) == c.crypto_box_SECRETKEYBYTES
    assert len(A_pubkey) == c.crypto_box_PUBLICKEYBYTES
    B_secretkey, B_pubkey = c.crypto_box_keypair()

    # TODO: NaCl is beforenm(k,pk,sk)
    k1 = c.crypto_box_beforenm(A_secretkey, B_pubkey)
    assert len(k1) == c.crypto_box_BEFORENMBYTES
    k2 = c.crypto_box_beforenm(B_secretkey, A_pubkey)
    assert hexlify(k1) == hexlify(k2)

    message = "message"
    nonce = "\x01" * c.crypto_box_NONCEBYTES
    # TODO: NaCl is box_afternm(ct, msg, nonce, k)
    ct1 = c.crypto_box_afternm(k1, message, nonce)
    assert len(ct1) == len(message) + c.crypto_box_BOXZEROBYTES

    # TODO: NaCl is box(ct, msg, nonce, pubkey, secretkey)
    ct2 = c.crypto_box(A_secretkey, B_pubkey, message, nonce)
    assert hexlify(ct2) == hexlify(ct1)

    # TODO: NaCl is open(msg, ct, nonce, pk, sk)
    m1 = c.crypto_box_open(B_secretkey, A_pubkey, ct1, nonce)
    assert m1 == message

    # TODO: NaCl is open_afternm(msg, ct, nonce, k)
    m2 = c.crypto_box_open_afternm(k1, ct1, nonce)
    assert m2 == message


def test_sign():
    # TODO: NaCl C++ is pk=keypair(sk), C is keypair(pk,sk)
    seed = "\x00" * c.crypto_sign_SEEDBYTES
    secretkey, pubkey = c.crypto_sign_seed_keypair(seed)
    assert len(pubkey) == c.crypto_sign_PUBLICKEYBYTES
    assert len(secretkey) == c.crypto_sign_SECRETKEYBYTES

    secretkey, pubkey = c.crypto_sign_keypair()
    assert len(pubkey) == c.crypto_sign_PUBLICKEYBYTES
    assert len(secretkey) == c.crypto_sign_SECRETKEYBYTES

    # TODO: NaCl is sm=sign(msg, sk)
    msg = "message"
    sigmsg = c.crypto_sign(secretkey, msg)
    assert len(sigmsg) == len(msg) + c.crypto_sign_BYTES

    # TODO: NaCl is msg=open(sm, pk)
    msg2 = c.crypto_sign_open(pubkey, sigmsg)
    assert msg2 == msg

def secret_scalar():
    # TODO: NaCl is box_keypair(pk,sk)
    secretkey, pubkey = c.crypto_box_keypair()
    assert len(secretkey) == c.crypto_box_SECRETKEYBYTES
    assert c.crypto_box_SECRETKEYBYTES == c.crypto_scalarmult_BYTES
    return secretkey, pubkey

def test_scalarmult():
    x, xpub = secret_scalar()
    assert len(x) == 32
    y, ypub = secret_scalar()

    bx = c.crypto_scalarmult_base(x)
    assert hexlify(bx) == hexlify(xpub)
