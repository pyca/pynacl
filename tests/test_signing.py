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
from __future__ import division

import binascii
import codecs
import os

import pytest

import nacl.signing
import nacl.encoding
import nacl.exceptions


def ed25519_known_answers():
    # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
    answers = []

    path = os.path.join(os.path.dirname(__file__), "data", "ed25519")
    with codecs.open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            x = line.split(":")
            answers.append({
                "seed": x[0][0:64].encode("ascii"),
                "public_key": x[1].encode("ascii"),
                "message": x[2].encode("ascii"),
                "signed": x[3].encode("ascii"),
                "signature": binascii.hexlify(
                    binascii.unhexlify(x[3].encode("ascii"))[:64],
                ),
            })

    return answers


class TestSigningKey:

    def test_initialize_with_generate(self):
        nacl.signing.SigningKey.generate()

    @pytest.mark.parametrize("seed", [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ])
    def test_initialization_with_seed(self, seed):
        nacl.signing.SigningKey(seed, encoder=nacl.encoding.HexEncoder)

    @pytest.mark.parametrize(
        ("seed", "message", "signature", "expected"),
        [
            (x["seed"], x["message"], x["signature"], x["signed"])
            for x in ed25519_known_answers()
        ],
    )
    def test_message_signing(self, seed, message, signature, expected):
        signing_key = nacl.signing.SigningKey(
            seed,
            encoder=nacl.encoding.HexEncoder,
        )
        signed = signing_key.sign(
            binascii.unhexlify(message),
            encoder=nacl.encoding.HexEncoder,
        )

        assert signed == expected
        assert signed.message == message
        assert signed.signature == signature


class TestVerifyKey:

    @pytest.mark.parametrize(
        ("public_key", "signed", "message", "signature"),
        [
            (x["public_key"], x["signed"], x["message"], x["signature"])
            for x in ed25519_known_answers()
        ]
    )
    def test_valid_signed_message(
            self, public_key, signed, message, signature):
        key = nacl.signing.VerifyKey(
            public_key,
            encoder=nacl.encoding.HexEncoder,
        )

        assert binascii.hexlify(
            key.verify(signed, encoder=nacl.encoding.HexEncoder),
        ) == message
        assert binascii.hexlify(
            key.verify(message, signature, encoder=nacl.encoding.HexEncoder),
        ) == message

    def test_invalid_signed_message(self):
        skey = nacl.signing.SigningKey.generate()
        smessage = skey.sign(b"A Test Message!")
        signature, message = smessage.signature, b"A Forged Test Message!"

        # Small sanity check
        assert skey.verify_key.verify(smessage)

        with pytest.raises(nacl.exceptions.BadSignatureError):
            skey.verify_key.verify(message, signature)

        with pytest.raises(nacl.exceptions.BadSignatureError):
            forged = nacl.signing.SignedMessage(signature + message)
            skey.verify_key.verify(forged)
