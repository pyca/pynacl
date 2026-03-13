from nacl._sodium import ffi, lib

POLY1305_BYTES = 16  # length of MAC/tag in bytes

def crypto_onetimeauth(message: bytes, key: bytes) -> bytes:
    """
    Generate Poly1305 MAC over message with key.

    :param message: data to authenticate
    :param key: 32-bytes Poly1305 key
    :return: 16-bytes MAC (tag)
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    mac = ffi.new(f"unsigned char[{POLY1305_BYTES}]")
    rc = lib.crypto_onetimeauth(mac, message, len(message), key)
    if rc != 0:
        raise RuntimeError(f"crypto_onetimeauth failed with code {rc}")
    return ffi.buffer(mac, POLY1305_BYTES)[:]

def crypto_onetimeauth_verify(mac: bytes, message: bytes, key: bytes) -> bool:
    """
    Verify if mac is valid for message and key.

    :param mac: 16-bytes MAC/tag to check
    :param message: data
    :param key: 32-bytes key
    :return: True on valid MAC, else False
    """
    if len(mac) != POLY1305_BYTES:
        raise ValueError("MAC must be 16 bytes")
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    rc = lib.crypto_onetimeauth_verify(mac, message, len(message), key)
    return rc == 0
