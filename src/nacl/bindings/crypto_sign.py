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

from __future__ import absolute_import, division, print_function

from nacl import exceptions as exc
from nacl._sodium import ffi, lib
from nacl.exceptions import ensure


crypto_sign_BYTES = lib.crypto_sign_bytes()
# crypto_sign_SEEDBYTES = lib.crypto_sign_seedbytes()
crypto_sign_SEEDBYTES = lib.crypto_sign_secretkeybytes() // 2
crypto_sign_PUBLICKEYBYTES = lib.crypto_sign_publickeybytes()
crypto_sign_SECRETKEYBYTES = lib.crypto_sign_secretkeybytes()

crypto_sign_curve25519_BYTES = lib.crypto_box_secretkeybytes()


def crypto_sign_keypair():
    """
    Returns a randomly generated public key and secret key.

    :rtype: (bytes(public_key), bytes(secret_key))
    """
    pk = ffi.new("unsigned char[]", crypto_sign_PUBLICKEYBYTES)
    sk = ffi.new("unsigned char[]", crypto_sign_SECRETKEYBYTES)

    rc = lib.crypto_sign_keypair(pk, sk)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return (
        ffi.buffer(pk, crypto_sign_PUBLICKEYBYTES)[:],
        ffi.buffer(sk, crypto_sign_SECRETKEYBYTES)[:],
    )


def crypto_sign_seed_keypair(seed):
    """
    Computes and returns the public key and secret key using the seed ``seed``.

    :param seed: bytes
    :rtype: (bytes(public_key), bytes(secret_key))
    """
    if len(seed) != crypto_sign_SEEDBYTES:
        raise exc.ValueError("Invalid seed")

    pk = ffi.new("unsigned char[]", crypto_sign_PUBLICKEYBYTES)
    sk = ffi.new("unsigned char[]", crypto_sign_SECRETKEYBYTES)

    rc = lib.crypto_sign_seed_keypair(pk, sk, seed)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return (
        ffi.buffer(pk, crypto_sign_PUBLICKEYBYTES)[:],
        ffi.buffer(sk, crypto_sign_SECRETKEYBYTES)[:],
    )


def crypto_sign(message, sk):
    """
    Signs the message ``message`` using the secret key ``sk`` and returns the
    signed message.

    :param message: bytes
    :param sk: bytes
    :rtype: bytes
    """
    signed = ffi.new("unsigned char[]", len(message) + crypto_sign_BYTES)
    signed_len = ffi.new("unsigned long long *")

    rc = lib.crypto_sign(signed, signed_len, message, len(message), sk)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(signed, signed_len[0])[:]


def crypto_sign_open(signed, pk):
    """
    Verifies the signature of the signed message ``signed`` using the public
    key ``pk`` and returns the unsigned message.

    :param signed: bytes
    :param pk: bytes
    :rtype: bytes
    """
    message = ffi.new("unsigned char[]", len(signed))
    message_len = ffi.new("unsigned long long *")

    if lib.crypto_sign_open(
            message, message_len, signed, len(signed), pk) != 0:
        raise exc.BadSignatureError("Signature was forged or corrupt")

    return ffi.buffer(message, message_len[0])[:]


def crypto_sign_ed25519_pk_to_curve25519(public_key_bytes):
    """
    Converts a public Ed25519 key (encoded as bytes ``public_key_bytes``) to
    a public Curve25519 key as bytes.

    Raises a ValueError if ``public_key_bytes`` is not of length
    ``crypto_sign_PUBLICKEYBYTES``

    :param public_key_bytes: bytes
    :rtype: bytes
    """
    if len(public_key_bytes) != crypto_sign_PUBLICKEYBYTES:
        raise exc.ValueError("Invalid curve public key")

    curve_public_key_len = crypto_sign_curve25519_BYTES
    curve_public_key = ffi.new("unsigned char[]", curve_public_key_len)

    rc = lib.crypto_sign_ed25519_pk_to_curve25519(curve_public_key,
                                                  public_key_bytes)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(curve_public_key, curve_public_key_len)[:]


def crypto_sign_ed25519_sk_to_curve25519(secret_key_bytes):
    """
    Converts a secret Ed25519 key (encoded as bytes ``secret_key_bytes``) to
    a secret Curve25519 key as bytes.

    Raises a ValueError if ``secret_key_bytes``is not of length
    ``crypto_sign_SECRETKEYBYTES``

    :param public_key_bytes: bytes
    :rtype: bytes
    """
    if len(secret_key_bytes) != crypto_sign_SECRETKEYBYTES:
        raise exc.ValueError("Invalid curve public key")

    curve_secret_key_len = crypto_sign_curve25519_BYTES
    curve_secret_key = ffi.new("unsigned char[]", curve_secret_key_len)

    rc = lib.crypto_sign_ed25519_sk_to_curve25519(curve_secret_key,
                                                  secret_key_bytes)
    ensure(rc == 0,
           'Unexpected library error',
           raising=exc.RuntimeError)

    return ffi.buffer(curve_secret_key, curve_secret_key_len)[:]
