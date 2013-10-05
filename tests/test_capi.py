"""
Tests for the C++ style API.
"""

from nacl import nacl
import os

message = b'the rain in spain stays mainly on the plain'

def test_sign(message=message):
    kp = nacl.crypto_sign_keypair()
    sm = nacl.crypto_sign(message, kp.sk)
    try:
        assert nacl.crypto_sign_open(sm + b'foo', kp.pk) == message
        raise Exception("Expected ValueError")
    except ValueError:
        pass

def test_box(message=message):
    nonce = b'\0' * nacl.crypto_box_NONCEBYTES
    sender = nacl.crypto_box_keypair()
    receiver = nacl.crypto_box_keypair()

    for i in range(10):
        c = nacl.crypto_box(message, nonce, sender.sk, receiver.pk)

    for i in range(10):
        m = nacl.crypto_box_open(c, nonce, sender.pk, receiver.sk)

    assert m == message

def test_secretbox(message=message):
    key = os.urandom(nacl.crypto_secretbox_KEYBYTES)
    nonce = b'\0' * nacl.crypto_secretbox_NONCEBYTES

    c = nacl.crypto_secretbox(message, nonce, key)
    m = nacl.crypto_secretbox_open(c, nonce, key)

    assert m == message

    try:
        m = nacl.crypto_secretbox_open(c + b' ', nonce, key)
        raise Exception("Expected ValueError")
    except ValueError:
        pass

    try:
        m = nacl.crypto_secretbox_open(c, b'\1' * nacl.crypto_secretbox_NONCEBYTES, key)
        raise Exception("Expected ValueError")
    except ValueError:
        pass

    try:
        m = nacl.crypto_secretbox_open(c, nonce, b'\1' * nacl.crypto_secretbox_KEYBYTES)
        raise Exception("Expected ValueError")
    except ValueError:
        pass

if __name__ == "__main__":
    for i in range(100): # tends to catch segfaults
        test_sign()
        test_box()
        test_secretbox()
