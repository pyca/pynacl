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

from nacl.bindings.crypto_box import (
    crypto_box, crypto_box_BEFORENMBYTES, crypto_box_BOXZEROBYTES,
    crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES,
    crypto_box_SECRETKEYBYTES, crypto_box_ZEROBYTES, crypto_box_afternm,
    crypto_box_beforenm, crypto_box_keypair, crypto_box_open,
    crypto_box_open_afternm,
)
from nacl.bindings.crypto_hash import (
    crypto_hash, crypto_hash_BYTES, crypto_hash_sha256,
    crypto_hash_sha256_BYTES, crypto_hash_sha512, crypto_hash_sha512_BYTES,
)
from nacl.bindings.crypto_scalarmult import (
    crypto_scalarmult, crypto_scalarmult_BYTES, crypto_scalarmult_SCALARBYTES,
    crypto_scalarmult_base
)
from nacl.bindings.crypto_secretbox import (
    crypto_secretbox, crypto_secretbox_BOXZEROBYTES, crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES, crypto_secretbox_ZEROBYTES,
    crypto_secretbox_open
)
from nacl.bindings.crypto_sign import (
    crypto_sign, crypto_sign_BYTES, crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES, crypto_sign_SEEDBYTES,
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_keypair, crypto_sign_open, crypto_sign_seed_keypair
)
from nacl.bindings.randombytes import randombytes
from nacl.bindings.sodium_core import sodium_init


__all__ = [
    "crypto_box_SECRETKEYBYTES",
    "crypto_box_PUBLICKEYBYTES",
    "crypto_box_NONCEBYTES",
    "crypto_box_ZEROBYTES",
    "crypto_box_BOXZEROBYTES",
    "crypto_box_BEFORENMBYTES",
    "crypto_box_keypair",
    "crypto_box",
    "crypto_box_open",
    "crypto_box_beforenm",
    "crypto_box_afternm",
    "crypto_box_open_afternm",

    "crypto_hash_BYTES",
    "crypto_hash_sha256_BYTES",
    "crypto_hash_sha512_BYTES",
    "crypto_hash",
    "crypto_hash_sha256",
    "crypto_hash_sha512",

    "crypto_scalarmult_BYTES",
    "crypto_scalarmult_SCALARBYTES",
    "crypto_scalarmult",
    "crypto_scalarmult_base",

    "crypto_secretbox_KEYBYTES",
    "crypto_secretbox_NONCEBYTES",
    "crypto_secretbox_ZEROBYTES",
    "crypto_secretbox_BOXZEROBYTES",
    "crypto_secretbox",
    "crypto_secretbox_open",

    "crypto_sign_BYTES",
    "crypto_sign_SEEDBYTES",
    "crypto_sign_PUBLICKEYBYTES",
    "crypto_sign_SECRETKEYBYTES",
    "crypto_sign_keypair",
    "crypto_sign_seed_keypair",
    "crypto_sign",
    "crypto_sign_open",
    "crypto_sign_ed25519_pk_to_curve25519",
    "crypto_sign_ed25519_sk_to_curve25519",

    "randombytes",

    "sodium_init",
]

# Initialize Sodium
sodium_init()
