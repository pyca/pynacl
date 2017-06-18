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

from nacl.encoding import HexEncoder
from nacl.public import PrivateKey, PublicKey, SealedBox


VECTORS = [
    # privalice, pubalice, plaintext, encrypted
    (
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        b"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        (b"be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5e"
         b"cbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8"
         b"250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4"
         b"8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"),
        (b"199c808806a62c1be56951023ad3396b0ce0ef2c5b9ca688ac96d2d06ca43f65d31"
         b"4400cc9bbefb23dd26f824c9cb553f81e8c894ea9a553f4d777c77b66d5a6925da3"
         b"f5961c5f7147172db5597ac14210066ee3ee13e6230a9a9610e9cddbf24094f54fb"
         b"bf6694c08a436cec39ff5a373656d9584f4df9dd8c817e2e597540628d0ee21a652"
         b"4a3fcf3eabdc0968390bd260a47366ead7f71cc2e774d411d96f3497c7e10291937"
         b"bc16dc46a111686b85a8c86"),
    ),
]


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
    VECTORS,
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
    VECTORS,
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
    VECTORS,
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
