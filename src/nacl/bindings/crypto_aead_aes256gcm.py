
from __future__ import absolute_import, division, print_function

from nacl._sodium import ffi, lib
from nacl.exceptions import CryptoError

crypto_aead_aes256gcm_KEYBYTES = lib.crypto_aead_aes256gcm_keybytes()
crypto_aead_aes256gcm_NPUBBYTES = lib.crypto_aead_aes256gcm_npubbytes()
crypto_aead_aes256gcm_ABYTES = lib.crypto_aead_aes256gcm_abytes()


def crypto_aead_aes256gcm_encrypt(message, nonce, key):
    """
    Encrypts the message ``message`` with secret ``key`` and 
    the nonce ``nonce`` and computes an authentication tag 

    : param message: bytes
    : param nonce: bytes
    : param key: bytes
    : rtype: bytes 
    """

    if len(key) != crypto_aead_aes256gcm_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
        raise ValueError("Invalid nonce")

    ciphertext = ffi.new("unsigned char[]", len(message) + crypto_aead_aes256gcm_ABYTES)
    cipherlen = ffi.new("unsigned long long *");
    
    lib.crypto_aead_aes256gcm_encrypt(ciphertext, cipherlen, message, len(message), ffi.NULL, 0, ffi.NULL, nonce, key)

    ciphertext = ffi.buffer(ciphertext, len(message) + crypto_aead_aes256gcm_ABYTES)
    return ciphertext[0:len(message)], ciphertext[len(message):]

def crypto_aead_aes256gcm_decrypt(cipher, tag, nonce ,key):
    if len(key) != crypto_aead_aes256gcm_KEYBYTES:
        raise ValueError("Invalid key")

    if len(nonce) != crypto_aead_aes256gcm_NPUBBYTES:
        raise ValueError("Invalid nonce")
    
    plaintext = ffi.new("unsigned char[]", len(cipher))
    decrypted_len = ffi.new("unsigned long long *")

    ciphertext = cipher + tag 

    if (lib.crypto_aead_aes256gcm_decrypt(plaintext, decrypted_len, ffi.NULL, ciphertext, len(ciphertext), ffi.NULL, 0, nonce, key) != 0):
        raise CryptoError("Decryption failed. Ciphertext failed verification")

    plaintext = ffi.buffer(plaintext, len(cipher))
    return plaintext    
