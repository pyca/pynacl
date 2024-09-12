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


import binascii

import pytest

from nacl.encoding import HexEncoder
from nacl.exceptions import CryptoError
from nacl.public import AeadClient, AeadServer, PrivateKx, PublicKx
from nacl.utils import random

from .test_bindings import _kx_from_seed_vectors
from .utils import check_type_error

VECTORS = [
    # privalice, pubalice, privbob, pubbob, nonce, plaintext,
    # ciphertext_c, ciphertext_s
    (
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        b"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        b"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        b"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        b"69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37",
        (
            b"be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5e"
            b"cbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8"
            b"250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb4"
            b"8f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705"
        ),
        (
            b"353a672c2752c5b3f0ebbfd9f22ead181e3cd51e46f64cd1d48f6ddeb85c0f3eb1c"
            b"d339a9da09078d1cef5c723ae37f83027aae107e182507a43573b491655afc0376e"
            b"dcbf8a75d586b9691b32f9c5966f136b35135ca274247696ad0294a1e4afe229b72"
            b"47419150189627d13b265b9bc16dbd40a1d4a2633ae97aeb240ce57eb1727515d09"
            b"96bdabc2205c03e547feceb276"
        ),
        (
            b"8f9bb2a56563446b050324a9c4c7089920d68ff0097e1e679b9a8a2f0c7aa2f5620"
            b"afcf7b7c487883f819eb3aec5a119a045c7ab0240dbe992b9c5706ead15ca289294"
            b"9fc1ec97f1221802d85d47eb05ebd5d9871eed00eeef7ee2aae41536f029ce8aaaf"
            b"1664a1244236e3602abc96ceb59247f6c2ac41a993c939ffa6db04418d4e7ee065c"
            b"f13d95069231c3d949ed6c2c45"
        ),
    ),
]


def test_generate_private_key():
    PrivateKx.generate()


def test_generate_private_key_from_random_seed():
    PrivateKx.from_seed(random(PrivateKx.SEED_SIZE))


@pytest.mark.parametrize(
    ("seed", "public_key", "secret_key"), _kx_from_seed_vectors()
)
def test_generate_private_key_from_seed(
    seed: bytes, public_key: bytes, secret_key: bytes
):
    prvt = PrivateKx.from_seed(seed, encoder=HexEncoder)
    sk = binascii.unhexlify(secret_key)
    pk = binascii.unhexlify(public_key)
    assert bytes(prvt) == sk
    assert bytes(prvt.public_key) == pk


def test_aeadkx_creation():
    pub = PublicKx(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    priv = PrivateKx(
        b"5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    AeadClient(priv, pub)
    AeadServer(priv, pub)


def test_aeadkx_decode():
    pub = PublicKx(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    priv = PrivateKx(
        b"5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )

    c1 = AeadClient(priv, pub)
    c2 = AeadClient.decode(c1.encode())
    assert c1._tx_key == c2._tx_key
    assert c1._rx_key == c2._rx_key

    s1 = AeadServer(priv, pub)
    s2 = AeadServer.decode(s1.encode())
    assert s1._tx_key == s2._tx_key
    assert s1._rx_key == s2._rx_key


def test_aeadkx_bytes():
    pub = PublicKx(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    priv = PrivateKx(
        b"5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )

    c = AeadClient(priv, pub)
    assert bytes(c) == c.encode()

    s = AeadServer(priv, pub)
    assert bytes(s) == s.encode()


@pytest.mark.parametrize(
    (
        "privalice",
        "pubalice",
        "privbob",
        "pubbob",
        "nonce",
        "plaintext",
        "ciphertext_c",
        "ciphertext_s",
    ),
    VECTORS,
)
def test_aeadkx_encryption(
    privalice: bytes,
    pubalice: bytes,
    privbob: bytes,
    pubbob: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext_c: bytes,
    ciphertext_s: bytes,
):
    pubalice_decoded = PublicKx(pubalice, encoder=HexEncoder)
    privbob_decoded = PrivateKx(privbob, encoder=HexEncoder)
    pubbob_decoded = PublicKx(pubbob, encoder=HexEncoder)
    privalice_decoded = PrivateKx(privalice, encoder=HexEncoder)

    c = AeadClient(privbob_decoded, pubalice_decoded)
    s = AeadServer(privalice_decoded, pubbob_decoded)

    encrypted_c = c.encrypt(
        binascii.unhexlify(plaintext),
        b"",
        binascii.unhexlify(nonce),
        encoder=HexEncoder,
    )

    encrypted_s = s.encrypt(
        binascii.unhexlify(plaintext),
        b"",
        binascii.unhexlify(nonce),
        encoder=HexEncoder,
    )

    expected_c = binascii.hexlify(
        binascii.unhexlify(nonce) + binascii.unhexlify(ciphertext_c),
    )

    expected_s = binascii.hexlify(
        binascii.unhexlify(nonce) + binascii.unhexlify(ciphertext_s),
    )

    assert encrypted_c == expected_c
    assert encrypted_s == expected_s
    assert encrypted_c.nonce == encrypted_s.nonce == nonce
    assert encrypted_c.ciphertext == ciphertext_c
    assert encrypted_s.ciphertext == ciphertext_s


@pytest.mark.parametrize(
    (
        "privalice",
        "pubalice",
        "privbob",
        "pubbob",
        "nonce",
        "plaintext",
        "ciphertext_c",
        "ciphertext_s",
    ),
    VECTORS,
)
def test_aeadkx_decryption(
    privalice: bytes,
    pubalice: bytes,
    privbob: bytes,
    pubbob: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext_c: bytes,
    ciphertext_s: bytes,
):
    pubalice_decoded = PublicKx(pubalice, encoder=HexEncoder)
    privbob_decoded = PrivateKx(privbob, encoder=HexEncoder)
    pubbob_decoded = PublicKx(pubbob, encoder=HexEncoder)
    privalice_decoded = PrivateKx(privalice, encoder=HexEncoder)

    c = AeadClient(privbob_decoded, pubalice_decoded)
    s = AeadServer(privalice_decoded, pubbob_decoded)

    nonce = binascii.unhexlify(nonce)
    decrypted_c1 = binascii.hexlify(
        c.decrypt(ciphertext_s, b"", nonce, encoder=HexEncoder),
    )

    decrypted_c2 = binascii.hexlify(
        c.decrypt_beforetx(ciphertext_c, b"", nonce, encoder=HexEncoder),
    )

    decrypted_s1 = binascii.hexlify(
        s.decrypt(ciphertext_c, b"", nonce, encoder=HexEncoder),
    )

    decrypted_s2 = binascii.hexlify(
        s.decrypt_beforetx(ciphertext_s, b"", nonce, encoder=HexEncoder),
    )

    assert (
        decrypted_c1
        == decrypted_c2
        == decrypted_s1
        == decrypted_s2
        == plaintext
    )


@pytest.mark.parametrize(
    (
        "privalice",
        "pubalice",
        "privbob",
        "pubbob",
        "nonce",
        "plaintext",
        "ciphertext_c",
        "ciphertext_s",
    ),
    VECTORS,
)
def test_aeadkx_decryption_combined(
    privalice: bytes,
    pubalice: bytes,
    privbob: bytes,
    pubbob: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext_c: bytes,
    ciphertext_s: bytes,
):
    pubalice_decoded = PublicKx(pubalice, encoder=HexEncoder)
    privbob_decoded = PrivateKx(privbob, encoder=HexEncoder)
    pubbob_decoded = PublicKx(pubbob, encoder=HexEncoder)
    privalice_decoded = PrivateKx(privalice, encoder=HexEncoder)

    c = AeadClient(privbob_decoded, pubalice_decoded)
    s = AeadServer(privalice_decoded, pubbob_decoded)

    combined_c = binascii.hexlify(
        binascii.unhexlify(nonce) + binascii.unhexlify(ciphertext_c),
    )
    combined_s = binascii.hexlify(
        binascii.unhexlify(nonce) + binascii.unhexlify(ciphertext_s),
    )

    decrypted_c1 = binascii.hexlify(c.decrypt(combined_s, encoder=HexEncoder))
    decrypted_s1 = binascii.hexlify(s.decrypt(combined_c, encoder=HexEncoder))
    decrypted_c2 = binascii.hexlify(
        c.decrypt_beforetx(combined_c, encoder=HexEncoder)
    )
    decrypted_s2 = binascii.hexlify(
        s.decrypt_beforetx(combined_s, encoder=HexEncoder)
    )

    assert (
        decrypted_c1
        == decrypted_c2
        == decrypted_s1
        == decrypted_s2
        == plaintext
    )


@pytest.mark.parametrize(
    (
        "privalice",
        "pubalice",
        "privbob",
        "pubbob",
        "nonce",
        "plaintext",
        "ciphertext_c",
        "ciphertext_s",
    ),
    VECTORS,
)
def test_aeadkx_optional_nonce(
    privalice: bytes,
    pubalice: bytes,
    privbob: bytes,
    pubbob: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext_c: bytes,
    ciphertext_s: bytes,
):
    pubalice_decoded = PublicKx(pubalice, encoder=HexEncoder)
    privbob_decoded = PrivateKx(privbob, encoder=HexEncoder)
    pubbob_decoded = PublicKx(pubbob, encoder=HexEncoder)
    privalice_decoded = PrivateKx(privalice, encoder=HexEncoder)

    c = AeadClient(privbob_decoded, pubalice_decoded)
    s = AeadServer(privalice_decoded, pubbob_decoded)

    encrypted = c.encrypt(binascii.unhexlify(plaintext), encoder=HexEncoder)

    decrypted = binascii.hexlify(s.decrypt(encrypted, encoder=HexEncoder))

    assert decrypted == plaintext


@pytest.mark.parametrize(
    (
        "privalice",
        "pubalice",
        "privbob",
        "pubbob",
        "nonce",
        "plaintext",
        "ciphertext_c",
        "ciphertext_s",
    ),
    VECTORS,
)
def test_aeadkx_encryption_generates_different_nonces(
    privalice: bytes,
    pubalice: bytes,
    privbob: bytes,
    pubbob: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext_c: bytes,
    ciphertext_s: bytes,
):
    pubalice_decoded = PublicKx(pubalice, encoder=HexEncoder)
    privbob_decoded = PrivateKx(privbob, encoder=HexEncoder)

    c = AeadClient(privbob_decoded, pubalice_decoded)

    nonce_0 = c.encrypt(
        binascii.unhexlify(plaintext), encoder=HexEncoder
    ).nonce

    nonce_1 = c.encrypt(
        binascii.unhexlify(plaintext), encoder=HexEncoder
    ).nonce

    assert nonce_0 != nonce_1


@pytest.mark.parametrize(
    (
        "privalice",
        "pubalice",
        "privbob",
        "pubbob",
        "nonce",
        "plaintext",
        "ciphertext_c",
        "ciphertext_s",
    ),
    VECTORS,
)
def test_box_failed_decryption(
    privalice: bytes,
    pubalice: bytes,
    privbob: bytes,
    pubbob: bytes,
    nonce: bytes,
    plaintext: bytes,
    ciphertext_c: bytes,
    ciphertext_s: bytes,
):
    privbob_decoded = PrivateKx(privbob, encoder=HexEncoder)
    pubbob_decoded = PublicKx(pubbob, encoder=HexEncoder)

    # this cannot decrypt the ciphertext! the ciphertext must be decrypted by
    # (privalice, pubbob) or (privbob, pubalice)
    c = AeadClient(privbob_decoded, pubbob_decoded)

    with pytest.raises(CryptoError):
        c.decrypt_beforetx(
            ciphertext_c, b"", binascii.unhexlify(nonce), encoder=HexEncoder
        )


def test_aeadkx_wrong_length():
    with pytest.raises(ValueError):
        PublicKx(b"")

    with pytest.raises(TypeError):
        PrivateKx(b"")

    pub = PublicKx(
        b"ec2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )
    priv = PrivateKx(
        b"5c2bee2d5be613ca82e377c96a0bf2220d823ce980cdff6279473edc52862798",
        encoder=HexEncoder,
    )

    c = AeadClient(priv, pub)

    with pytest.raises(ValueError):
        c.encrypt(b"", b"", b"")

    with pytest.raises(ValueError):
        c.decrypt(b"", b"", b"")


def test_wrong_types():
    priv = PrivateKx.generate()

    check_type_error(
        ("PrivateKx must be created from a 32 bytes long raw secret key"),
        PrivateKx,
        12,
    )
    check_type_error(
        ("PrivateKx must be created from a 32 bytes long raw secret key"),
        PrivateKx,
        priv,
    )
    check_type_error(
        ("PrivateKx must be created from a 32 bytes long raw secret key"),
        PrivateKx,
        priv.public_key,
    )

    check_type_error("PublicKx must be created from 32 bytes", PublicKx, 13)
    check_type_error("PublicKx must be created from 32 bytes", PublicKx, priv)
    check_type_error(
        "PublicKx must be created from 32 bytes", PublicKx, priv.public_key
    )

    check_type_error(
        "AeadClient must be created from a PrivateKx and a PublicKx",
        AeadClient,
        priv,
        "not a public key",
    )
    check_type_error(
        "AeadClient must be created from a PrivateKx and a PublicKx",
        AeadClient,
        priv.encode(),
        priv.public_key.encode(),
    )
    check_type_error(
        "AeadClient must be created from a PrivateKx and a PublicKx",
        AeadClient,
        priv,
        priv.public_key.encode(),
    )
    check_type_error(
        "AeadClient must be created from a PrivateKx and a PublicKx",
        AeadClient,
        priv.encode(),
        priv.public_key,
    )
    check_type_error(
        "AeadServer must be created from a PrivateKx and a PublicKx",
        AeadServer,
        priv,
        "not a public key",
    )
    check_type_error(
        "AeadServer must be created from a PrivateKx and a PublicKx",
        AeadServer,
        priv.encode(),
        priv.public_key.encode(),
    )
    check_type_error(
        "AeadServer must be created from a PrivateKx and a PublicKx",
        AeadServer,
        priv,
        priv.public_key.encode(),
    )
    check_type_error(
        "AeadServer must be created from a PrivateKx and a PublicKx",
        AeadServer,
        priv.encode(),
        priv.public_key,
    )

    check_type_error("seed must be a 32 bytes long", PrivateKx.from_seed, b"1")
