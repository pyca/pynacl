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
import codecs
import os

import pytest

from nacl.c import crypto_sign_PUBLICKEYBYTES, crypto_sign_SEEDBYTES
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage, SigningKey, VerifyKey


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
        SigningKey.generate()

    def test_wrong_length(self):
        with pytest.raises(ValueError):
            SigningKey(b"")

    def test_bytes(self):
        k = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
        assert bytes(k) == b"\x00" * crypto_sign_SEEDBYTES

    @pytest.mark.parametrize("seed", [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ])
    def test_initialization_with_seed(self, seed):
        SigningKey(seed, encoder=HexEncoder)

    @pytest.mark.parametrize(
        ("seed", "message", "signature", "expected"),
        [
            (x["seed"], x["message"], x["signature"], x["signed"])
            for x in ed25519_known_answers()
        ],
    )
    def test_message_signing(self, seed, message, signature, expected):
        signing_key = SigningKey(
            seed,
            encoder=HexEncoder,
        )
        signed = signing_key.sign(
            binascii.unhexlify(message),
            encoder=HexEncoder,
        )

        assert signed == expected
        assert signed.message == message
        assert signed.signature == signature


class TestVerifyKey:
    def test_wrong_length(self):
        with pytest.raises(ValueError):
            VerifyKey(b"")

    def test_bytes(self):
        k = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        assert bytes(k) == b"\x00" * crypto_sign_PUBLICKEYBYTES

    @pytest.mark.parametrize(
        ("public_key", "signed", "message", "signature"),
        [
            (x["public_key"], x["signed"], x["message"], x["signature"])
            for x in ed25519_known_answers()
        ]
    )
    def test_valid_signed_message(
            self, public_key, signed, message, signature):
        key = VerifyKey(
            public_key,
            encoder=HexEncoder,
        )

        assert binascii.hexlify(
            key.verify(signed, encoder=HexEncoder),
        ) == message
        assert binascii.hexlify(
            key.verify(message, signature, encoder=HexEncoder),
        ) == message

    def test_invalid_signed_message(self):
        skey = SigningKey.generate()
        smessage = skey.sign(b"A Test Message!")
        signature, message = smessage.signature, b"A Forged Test Message!"

        # Small sanity check
        assert skey.verify_key.verify(smessage)

        with pytest.raises(BadSignatureError):
            skey.verify_key.verify(message, signature)

        with pytest.raises(BadSignatureError):
            forged = SignedMessage(signature + message)
            skey.verify_key.verify(forged)
