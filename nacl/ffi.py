"""
CFFI interface to libsodium the library
"""
from cffi import FFI

ffi = FFI()

ffi.cdef(
    # Low Level Hashing functions
    """
        static const int crypto_hash_BYTES;
        static const int crypto_hash_sha256_BYTES;
        static const int crypto_hash_sha512_BYTES;

        int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);
        int crypto_hash_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
    """
)

lib = ffi.verify("#include <sodium.h>", libraries=["sodium"])
