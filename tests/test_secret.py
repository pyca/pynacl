import binascii
import pytest

from nacl.encoding import HexEncoder
from nacl.secret import SecretBox


VECTORS = [
    # Key, Nonce, Plaintext, Ciphertext
    (
        b"1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389",
        b"69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
        b"be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705",
        b"f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5",
    ),
]


def test_secret_box_creation():
    SecretBox(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )


@pytest.mark.parametrize(("key", "nonce", "plaintext", "ciphertext"), VECTORS)
def test_secret_box_encryption(key, nonce, plaintext, ciphertext):
    box = SecretBox(key, encoder=HexEncoder)

    plaintext = binascii.unhexlify(plaintext)
    nonce = binascii.unhexlify(nonce)

    assert box.encrypt(plaintext, nonce, encoder=HexEncoder) == ciphertext


@pytest.mark.parametrize(("key", "nonce", "plaintext", "ciphertext"), VECTORS)
def test_secret_box_decryption(key, nonce, plaintext, ciphertext):
    box = SecretBox(key, encoder=HexEncoder)

    nonce = binascii.unhexlify(nonce)
    decrypted = binascii.hexlify(
                    box.decrypt(ciphertext, nonce, encoder=HexEncoder))

    assert decrypted == plaintext
