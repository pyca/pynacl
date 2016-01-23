
from __future__ import absolute_import, division, print_function

import binascii

import pytest

from nacl.encoding import HexEncoder
from nacl.aead import AES256GCM

VECTORS = [
    # Key, Nonce, Plaintext, Ciphertext, Tag
    (
        b"12336fc5dc0be1768adc758b1490960f0367cfcf25b7114ce47a728a9ac7f54b",
        b"a2058ca9a835e0ef289f6fee",
        (b"41627374726163742053796e746178204e6f746174696f6e204f6e65202841534e2"
         b"e312920697320776964656c792075736564207468726f7567686f75742074686520"
         b"49455446205365637572697479204172656120616e6420686173206265656e20666"
         b"f72206d616e792079656172732e2020536f6d652073706563696669636174696f6e"),
        (b"3dc33f50048d9b96754adebf98c4e4635294bf5a114db7de58579fc760ce40daf6b"
         b"3acf58f1e1a2b520a4f2af08e13ed53fd7bf5dc9a4032830005d72d14ca957e2564"
         b"be10b33fd8319957f25c7b38d8a31421c5382ff1689825308f52e394c89d1e390e2"
         b"1afc177f06a3a2d7d50bf3f13381be399be8b1e39a72ef1781544fc4b1fec661089"),
        b"a8eadf66994c88974da68be21d821630"
    ),
]

@pytest.mark.parametrize(("key", "nonce", "plaintext", "ciphertext", "tag"), VECTORS)
def test_aes256gcm_encryption(key, nonce, plaintext, ciphertext, tag):
    box = AES256GCM(key, encoder=HexEncoder)
    encryptedtext, encryptedtag = box.encrypt_and_mac(
        binascii.unhexlify(plaintext),
        binascii.unhexlify(nonce),
        encoder=HexEncoder,
    )

    assert encryptedtext == ciphertext
    assert encryptedtag == tag

@pytest.mark.parametrize(("key", "nonce", "plaintext", "ciphertext", "tag"), VECTORS)
def test_aes256gcm_decryption(key, nonce, plaintext, ciphertext, tag):
    box = AES256GCM(key, encoder=HexEncoder)
    
    nonce = binascii.unhexlify(nonce)
    decrypted = binascii.hexlify(
        box.decrypt_and_verify(ciphertext, tag, nonce, encoder=HexEncoder)
    )

    assert decrypted == plaintext
