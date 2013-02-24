from __future__ import division

import binascii
import os

import pytest

import nacl
import nacl.nacl


def ed25519_known_answers():
    # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
    answers = []

    path = os.path.join(os.path.dirname(__file__), "data", "ed25519")
    with open(path, "r") as fp:
        for line in fp:
            x = line.split(":")
            answers.append({
                "seed": x[0][0:64],
                "public_key": x[1],
                "message": x[2],
                "signed": x[3],
                "signature": binascii.hexlify(binascii.unhexlify(x[3])[:64]),
            })

    return answers


class TestSigningKey:

    def test_initialize_with_generate(self):
        nacl.signing.SigningKey.generate()

    @pytest.mark.parametrize("seed", [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ])
    def test_initialization_with_seed(self, seed):
        nacl.signing.SigningKey(binascii.unhexlify(seed))

    @pytest.mark.parametrize(("seed", "message", "signature", "expected"),
            [(x["seed"], x["message"], x["signature"], x["signed"])
                for x in ed25519_known_answers()]
        )
    def test_message_signing(self, seed, message, signature, expected):
        signing_key = nacl.signing.SigningKey(binascii.unhexlify(seed))
        signed = signing_key.sign(binascii.unhexlify(message))

        assert binascii.hexlify(signed) == expected
        assert binascii.hexlify(signed.message) == message
        assert binascii.hexlify(signed.signature) == signature


class TestVerifyKey:

    @pytest.mark.parametrize(("public_key", "signed", "message", "signature"),
        [(x["public_key"], x["signed"], x["message"], x["signature"]) for x in ed25519_known_answers()]
    )
    def test_valid_signed_message(self, public_key, signed, message, signature):
        key = nacl.signing.VerifyKey(binascii.unhexlify(public_key))
        signedb = binascii.unhexlify(signed)
        messageb = binascii.unhexlify(message)
        signatureb = binascii.unhexlify(signature)

        assert binascii.hexlify(key.verify(signedb)) == message
        assert binascii.hexlify(key.verify(messageb, signatureb)) == message

    def test_invalid_signed_message(self):
        skey = nacl.signing.SigningKey.generate()
        smessage = skey.sign("A Test Message!")
        signature, message = smessage.signature, "A Forged Test Message!"

        # Small sanity check
        assert skey.verify_key.verify(smessage)

        with pytest.raises(nacl.signing.BadSignatureError):
            skey.verify_key.verify(message, signature)

        with pytest.raises(nacl.signing.BadSignatureError):
            forged = nacl.signing.SignedMessage(signature + message)
            skey.verify_key.verify(forged)
