import nacl.random


def test_random_bytes_produces():
    assert len(nacl.random.random(16)) == 16


def test_random_bytes_produces_different_bytes():
    assert nacl.random.random(16) != nacl.random.random(16)
