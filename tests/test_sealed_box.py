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

import pytest

from utils import read_crypto_test_vectors

from nacl.encoding import HexEncoder
from nacl.public import PrivateKey, PublicKey, SealedBox


def sealbox_vectors():
    # Fmt: <recipient sk><tab><recipient pk><tab><plaintext><tab><ciphertext>
    # [<tab> ...]
    DATA = "sealed_box_ref.txt"
    return read_crypto_test_vectors(DATA, maxels=4)


def test_generate_private_key():
    PrivateKey.generate()


def test_sealed_box_creation():
    pub = PublicKey(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    priv = PrivateKey(
        b"5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    SealedBox(priv)
    SealedBox(pub)


@pytest.mark.parametrize(
    (
        "privalice", "pubalice", "plaintext", "_encrypted"
    ),
    sealbox_vectors()
)
def test_sealed_box_encryption(privalice, pubalice, plaintext, _encrypted):
    pubalice = PublicKey(pubalice, encoder=HexEncoder)
    privalice = PrivateKey(privalice, encoder=HexEncoder)

    box = SealedBox(pubalice)
    encrypted = box.encrypt(
        binascii.unhexlify(plaintext),
        encoder=HexEncoder,
    )

    assert encrypted != _encrypted
    # since SealedBox.encrypt uses an ephemeral sender's keypair

    box2 = SealedBox(privalice)
    decrypted = box2.decrypt(
        encrypted,
        encoder=HexEncoder,
    )
    assert binascii.hexlify(decrypted) == plaintext
    assert bytes(box) == bytes(box2)


@pytest.mark.parametrize(
    (
        "privalice", "pubalice", "plaintext", "encrypted"
    ),
    sealbox_vectors()
)
def test_sealed_box_decryption(privalice, pubalice, plaintext, encrypted):
    pubalice = PublicKey(pubalice, encoder=HexEncoder)
    privalice = PrivateKey(privalice, encoder=HexEncoder)

    box = SealedBox(privalice)
    decrypted = box.decrypt(
        encrypted,
        encoder=HexEncoder,
    )
    assert binascii.hexlify(decrypted) == plaintext


def check_type_error(expected, f, *args):
    with pytest.raises(TypeError) as e:
        f(*args)
    assert expected in str(e)


def test_wrong_types():
    priv = PrivateKey.generate()

    check_type_error(("SealedBox must be created from a PublicKey"
                      " or a PrivateKey"),
                     SealedBox, priv.encode())
    check_type_error(("SealedBox must be created from a PublicKey"
                      " or a PrivateKey"),
                     SealedBox, priv.public_key.encode())
    with pytest.raises(TypeError):
        SealedBox(priv, priv.public_key)


@pytest.mark.parametrize(
    (
        "_privalice", "pubalice", "_plaintext", "encrypted"
    ),
    sealbox_vectors()
)
def test_sealed_box_public_key_cannot_decrypt(_privalice, pubalice,
                                              _plaintext, encrypted):
    pubalice = PublicKey(pubalice, encoder=HexEncoder)
    box = SealedBox(pubalice)
    with pytest.raises(TypeError):
        box.decrypt(
            encrypted,
            encoder=HexEncoder,
        )
