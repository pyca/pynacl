from nacl._sodium import ffi, lib


crypto_onetimeauth_BYTES = lib.crypto_onetimeauth_bytes()
crypto_onetimeauth_KEYBYTES = lib.crypto_onetimeauth_keybytes()


def crypto_onetimeauth(message: bytes, key: bytes) -> bytes:
    """
    Generate Poly1305 MAC over message with key.

    :param message: data to authenticate
    :param key: 32-bytes Poly1305 key
    :return: 16-bytes MAC (tag)
    """
    if len(key) != crypto_onetimeauth_KEYBYTES:
        raise ValueError(f"Key must be {crypto_onetimeauth_KEYBYTES} bytes")

    mac = ffi.new(f"unsigned char[{crypto_onetimeauth_BYTES}]")
    lib.crypto_onetimeauth(mac, message, len(message), key)
    return ffi.buffer(mac, crypto_onetimeauth_BYTES)[:]


def crypto_onetimeauth_verify(mac: bytes, message: bytes, key: bytes) -> bool:
    """
    Verify if mac is valid for message and key.

    :param mac: 16-bytes MAC/tag to check
    :param message: data
    :param key: 32-bytes key
    :return: True on valid MAC, else False
    """
    if len(mac) != crypto_onetimeauth_BYTES:
        raise ValueError(f"MAC must be {crypto_onetimeauth_BYTES} bytes")
    if len(key) != crypto_onetimeauth_KEYBYTES:
        raise ValueError(f"Key must be {crypto_onetimeauth_KEYBYTES} bytes")

    rc = lib.crypto_onetimeauth_verify(mac, message, len(message), key)
    return rc == 0
