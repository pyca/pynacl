import nacl


def test_random_bytes_produces():
    assert len(nacl.random(16)) == 16


def test_random_bytes_produces_different_bytes():
    assert nacl.random(16) != nacl.random(16)
