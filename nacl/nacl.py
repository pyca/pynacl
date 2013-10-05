"""
CFFI interface to NaCl and libsodium library
"""
from __future__ import absolute_import
from __future__ import division

import functools

from cffi import FFI
from collections import namedtuple


__all__ = ["ffi", "lib"]


ffi = FFI()
ffi.cdef(
    # Secret Key Encryption
    """
        static const int crypto_secretbox_KEYBYTES;
        static const int crypto_secretbox_NONCEBYTES;
        static const int crypto_secretbox_ZEROBYTES;
        static const int crypto_secretbox_BOXZEROBYTES;

        int crypto_secretbox(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_secretbox_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
    """

    # Public Key Encryption - Signatures
    """
        static const int crypto_sign_PUBLICKEYBYTES;
        static const int crypto_sign_SECRETKEYBYTES;
        static const int crypto_sign_BYTES;

        int crypto_sign_seed_keypair(unsigned char *pk, unsigned char *sk, unsigned char *seed);
        int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);
        int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);
    """

    # Public Key Encryption
    """
        static const int crypto_box_PUBLICKEYBYTES;
        static const int crypto_box_SECRETKEYBYTES;
        static const int crypto_box_BEFORENMBYTES;
        static const int crypto_box_NONCEBYTES;
        static const int crypto_box_ZEROBYTES;
        static const int crypto_box_BOXZEROBYTES;

        int crypto_box_keypair(unsigned char *pk, unsigned char *sk);
        int crypto_box_afternm(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);
        int crypto_box_open_afternm(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *k);
        int crypto_box_beforenm(unsigned char *k, const unsigned char *pk, const unsigned char *sk);
        int crypto_box(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk);
        int crypto_box_open(unsigned char *m, const unsigned char *c, unsigned long long clen, const unsigned char *n, const unsigned char *pk, const unsigned char *sk);
    """

    # Hashing
    """
        static const int crypto_hash_BYTES;
        static const int crypto_hash_sha256_BYTES;
        static const int crypto_hash_sha512_BYTES;

        int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
    """

    # Secure Random
    """
        void randombytes(unsigned char * const buf, const unsigned long long buf_len);
    """

    # Low Level - Scalar Multiplication
    """
        int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
    """
)


llib = ffi.verify("#include <sodium.h>", libraries=["sodium"])

class Box(object): pass
lib = Box()

def _copy():
    globals_update = {}
    for attr in dir(llib):
        if attr[0].isalpha():
            setattr(lib, attr, getattr(llib, attr))
        if attr[-1].isupper():
            globals_update[attr] = getattr(llib, attr)
    globals().update(globals_update)
_copy()

# This works around a bug in PyPy where CFFI exposed functions do not have a
#   __name__ attribute. See https://bugs.pypy.org/issue1452
def wraps(wrapped):
    def inner(func):
        if hasattr(wrapped, "__name__"):
            return functools.wraps(wrapped)(func)
        else:
            return func
    return inner


# A lot of the functions in nacl return 0 for success and a negative integer
#   for failure. This is inconvenient in Python as 0 is a falsey value while
#   negative integers are truthy. This wrapper has them return True/False as
#   you'd expect in Python
def wrap_nacl_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        return ret == 0
    return wrapper

lib.crypto_secretbox = wrap_nacl_function(llib.crypto_secretbox)
lib.crypto_secretbox_open = wrap_nacl_function(llib.crypto_secretbox_open)

lib.crypto_sign_seed_keypair = wrap_nacl_function(llib.crypto_sign_seed_keypair)
lib.crypto_sign = wrap_nacl_function(llib.crypto_sign)
lib.crypto_sign_open = wrap_nacl_function(llib.crypto_sign_open)

lib.crypto_box_keypair = wrap_nacl_function(llib.crypto_box_keypair)
lib.crypto_box_afternm = wrap_nacl_function(llib.crypto_box_afternm)
lib.crypto_box_open_afternm = wrap_nacl_function(llib.crypto_box_open_afternm)
lib.crypto_box_beforenm = wrap_nacl_function(llib.crypto_box_beforenm)

lib.crypto_hash = wrap_nacl_function(llib.crypto_hash)
lib.crypto_hash_sha256 = wrap_nacl_function(llib.crypto_hash_sha256)
lib.crypto_hash_sha512 = wrap_nacl_function(llib.crypto_hash_sha512)

lib.crypto_scalarmult_curve25519_base = wrap_nacl_function(llib.crypto_scalarmult_curve25519_base)

import os

#
# crypto_sign API
#

Keypair = namedtuple('Keypair', ('pk', 'sk'))  # public key, secret key

def crypto_sign_keypair(seed=None):
    """
    Generate a new keypair.
    seed: Random seed for key. os.urandom() if None.
    """
    
    if seed == None:
        seed = os.urandom(llib.crypto_sign_SECRETKEYBYTES)
    pk = ffi.new("unsigned char[]", llib.crypto_sign_PUBLICKEYBYTES)
    sk = ffi.new("unsigned char[]", llib.crypto_sign_SECRETKEYBYTES)
    s = ffi.new("unsigned char[]", llib.crypto_sign_SECRETKEYBYTES)
    ffi.buffer(s)[:] = seed
    rc = llib.crypto_sign_seed_keypair(pk, sk, s)
    assert rc == 0
    return Keypair(ffi.buffer(pk)[:], ffi.buffer(sk)[:])

def crypto_sign(m, sk):
    """
    Sign a message m using the sender's secret key sk.
    Return signed message.    
    """
    
    assert isinstance(m, bytes)
    assert isinstance(sk, bytes)

    c_smlen = ffi.new("unsigned long long[]", 1)
    c_m = ffi.new("unsigned char[]", len(m))
    c_sk = ffi.new("unsigned char[]", llib.crypto_sign_SECRETKEYBYTES)
    c_sm = ffi.new("unsigned char[]", llib.crypto_sign_BYTES + len(m))

    ffi.buffer(c_m)[:] = m
    ffi.buffer(c_sk)[:] = sk
    rc = llib.crypto_sign(c_sm, c_smlen, c_m, len(m), c_sk)
    assert rc == 0
    return ffi.buffer(c_sm)[:c_smlen[0]]

def crypto_sign_open(sm, pk):
    """
    Verify signed message sm using the signers's public key pk.
    Return message.
    """
    
    assert isinstance(sm, bytes)
    assert isinstance(pk, bytes)

    c_sm = ffi.new("unsigned char[]", len(sm))
    c_mlen = ffi.new("unsigned long long[]", 1)
    c_m = ffi.new("unsigned char[]", len(sm))
    c_pk = ffi.new("unsigned char[]", len(pk))

    ffi.buffer(c_sm)[:] = sm
    ffi.buffer(c_pk)[:] = pk

    rc = llib.crypto_sign_open(c_m, c_mlen, c_sm, len(sm), c_pk)
    if rc == -1:
        raise ValueError("signature fails verification")

    return ffi.buffer(c_m)[:c_mlen[0]]

#
# crypto_box API
#

def crypto_box_keypair():
    """
    Generate a new keypair.
    """
    
    pk = ffi.new("unsigned char[]", llib.crypto_box_PUBLICKEYBYTES)
    sk = ffi.new("unsigned char[]", llib.crypto_box_SECRETKEYBYTES)

    rc = llib.crypto_box_keypair(pk, sk)
    assert rc == 0

    return Keypair(ffi.buffer(pk)[:], ffi.buffer(sk)[:])

def crypto_box(m, n, sk, pk):
    """
    Encrypt and authenticate message m using a nonce n, the sender's secret
    key sk, and the receiver's public key pk.
    Return the resulting ciphertext.
    """

    assert isinstance(m, bytes)
    assert isinstance(n, bytes)
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    # The padded ciphertext is the same length as the padded message, but
    # only the first crypto_box_BOXZEROBYTES of the ciphertext are '\0'.
    c_c = ffi.new("unsigned char[]", llib.crypto_box_ZEROBYTES + len(m))
    c_m = ffi.new("unsigned char[]", llib.crypto_box_ZEROBYTES + len(m))
    c_n = ffi.new("unsigned char[]", llib.crypto_box_NONCEBYTES)
    c_pk = ffi.new("unsigned char[]", llib.crypto_box_PUBLICKEYBYTES)
    c_sk = ffi.new("unsigned char[]", llib.crypto_box_SECRETKEYBYTES)

    ffi.buffer(c_m)[llib.crypto_box_ZEROBYTES:] = m
    ffi.buffer(c_n)[:] = n
    ffi.buffer(c_pk)[:] = pk
    ffi.buffer(c_sk)[:] = sk

    rc = llib.crypto_box(c_c, c_m, len(c_m), c_n, c_pk, c_sk)
    assert rc == 0

    c_buffer = ffi.buffer(c_c)
    assert c_buffer[:llib.crypto_box_BOXZEROBYTES] == b'\0' * llib.crypto_box_BOXZEROBYTES
    return c_buffer[llib.crypto_box_BOXZEROBYTES:]

def crypto_box_open(c, n, pk, sk):
    """
    Verify and decrypto a ciphertext c using a nonce n, the sender's public 
    key pk, and the receiver's secret key sk.
    Return the message.
    """

    assert isinstance(c, bytes)
    assert isinstance(n, bytes)
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)

    c_m = ffi.new("unsigned char[]", llib.crypto_box_BOXZEROBYTES + len(c))
    c_c = ffi.new("unsigned char[]", llib.crypto_box_BOXZEROBYTES + len(c))
    c_n = ffi.new("unsigned char[]", llib.crypto_box_NONCEBYTES)
    c_pk = ffi.new("unsigned char[]", llib.crypto_box_PUBLICKEYBYTES)
    c_sk = ffi.new("unsigned char[]", llib.crypto_box_SECRETKEYBYTES)

    ffi.buffer(c_c)[llib.crypto_box_BOXZEROBYTES:] = c
    ffi.buffer(c_n)[:] = n
    ffi.buffer(c_pk)[:] = pk
    ffi.buffer(c_sk)[:] = sk

    rc = llib.crypto_box_open(c_m, c_c, len(c_c), c_n, c_pk, c_sk)
    if rc == -1:
        raise ValueError("ciphertext fails verification")

    m_buffer = ffi.buffer(c_m)
    assert m_buffer[:llib.crypto_box_ZEROBYTES] == b'\0' * llib.crypto_box_ZEROBYTES
    return m_buffer[llib.crypto_box_ZEROBYTES:]

#
# crypto_secretbox API
#

def crypto_secretbox(m, n, k):
    """
    Encrypt message m with nonce n and key k.
    """
    
    assert isinstance(m, bytes)
    assert isinstance(n, bytes)
    assert isinstance(k, bytes)
    
    c_c = ffi.new("unsigned char[]", llib.crypto_secretbox_ZEROBYTES + len(m))
    c_m = ffi.new("unsigned char[]", llib.crypto_secretbox_ZEROBYTES + len(m))
    c_n = ffi.new("unsigned char[]", llib.crypto_secretbox_NONCEBYTES)
    c_k = ffi.new("unsigned char[]", llib.crypto_secretbox_KEYBYTES)
    
    ffi.buffer(c_m)[llib.crypto_secretbox_ZEROBYTES:] = m
    ffi.buffer(c_n)[:] = n
    ffi.buffer(c_k)[:] = k
    
    rc = llib.crypto_secretbox(c_c, c_m, len(c_m), c_n, c_k)
    assert rc == 0
    
    c_buffer = ffi.buffer(c_c)
    assert c_buffer[:llib.crypto_secretbox_BOXZEROBYTES] == '\0' * llib.crypto_secretbox_BOXZEROBYTES
    return c_buffer[llib.crypto_secretbox_BOXZEROBYTES:]

def crypto_secretbox_open(c, n, k):
    """
    Verify and decrypt ciphertext c encrypted with nonce n and key k.
    """
    
    assert isinstance(c, bytes)
    assert isinstance(n, bytes)
    assert isinstance(k, bytes)
    
    c_m = ffi.new("unsigned char[]", llib.crypto_secretbox_BOXZEROBYTES + len(c))
    c_c = ffi.new("unsigned char[]", llib.crypto_secretbox_BOXZEROBYTES + len(c))
    c_n = ffi.new("unsigned char[]", llib.crypto_secretbox_NONCEBYTES)
    c_k = ffi.new("unsigned char[]", llib.crypto_secretbox_KEYBYTES)
    
    ffi.buffer(c_c)[llib.crypto_secretbox_BOXZEROBYTES:] = c
    ffi.buffer(c_n)[:] = n
    ffi.buffer(c_k)[:] = k
    
    rc = llib.crypto_secretbox_open(c_m, c_c, len(c_c), c_n, c_k)
    if rc == -1:
        raise ValueError("ciphertext fails verification")
    
    m_buffer = ffi.buffer(c_m)
    assert m_buffer[:llib.crypto_secretbox_ZEROBYTES] == '\0' * llib.crypto_secretbox_ZEROBYTES
    return m_buffer[llib.crypto_secretbox_ZEROBYTES:]
