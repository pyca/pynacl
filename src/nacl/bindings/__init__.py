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
from nacl.bindings.crypto_generichash import (
    crypto_generichash_BYTES, crypto_generichash_BYTES_MAX,
    crypto_generichash_BYTES_MIN, crypto_generichash_KEYBYTES,
    crypto_generichash_KEYBYTES_MAX, crypto_generichash_KEYBYTES_MIN,
    crypto_generichash_PERSONALBYTES, crypto_generichash_SALTBYTES,
    crypto_generichash_STATEBYTES,
    generichash_blake2b_final as crypto_generichash_blake2b_final,
    generichash_blake2b_init as crypto_generichash_blake2b_init,
    generichash_blake2b_salt_personal as
    crypto_generichash_blake2b_salt_personal,
    generichash_blake2b_state_copy as crypto_generichash_blake2b_state_copy,
    generichash_blake2b_update as crypto_generichash_blake2b_update
)
from nacl.bindings.crypto_hash import (
    crypto_hash, crypto_hash_BYTES, crypto_hash_sha256,
    crypto_hash_sha256_BYTES, crypto_hash_sha512, crypto_hash_sha512_BYTES,
)
from nacl.bindings.crypto_pwhash import (
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE,
    crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE,
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
    crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
    crypto_pwhash_scryptsalsa208sha256_SALTBYTES,
    crypto_pwhash_scryptsalsa208sha256_STRBYTES,
    crypto_pwhash_scryptsalsa208sha256_ll,
    crypto_pwhash_scryptsalsa208sha256_str,
    crypto_pwhash_scryptsalsa208sha256_str_verify,
    nacl_bindings_pick_scrypt_params,
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
from nacl.bindings.crypto_shorthash import (
    BYTES as crypto_shorthash_siphash24_BYTES,
    KEYBYTES as crypto_shorthash_siphash24_KEYBYTES,
    crypto_shorthash_siphash24
)
from nacl.bindings.crypto_sign import (
    crypto_sign, crypto_sign_BYTES, crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES, crypto_sign_SEEDBYTES,
    crypto_sign_ed25519_pk_to_curve25519, crypto_sign_ed25519_sk_to_curve25519,
    crypto_sign_keypair, crypto_sign_open, crypto_sign_seed_keypair
)
from nacl.bindings.randombytes import randombytes
from nacl.bindings.sodium_core import sodium_init
from nacl.bindings.utils import sodium_memcmp


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

    "crypto_generichash_BYTES",
    "crypto_generichash_BYTES_MIN",
    "crypto_generichash_BYTES_MAX",
    "crypto_generichash_KEYBYTES",
    "crypto_generichash_KEYBYTES_MIN",
    "crypto_generichash_KEYBYTES_MAX",
    "crypto_generichash_SALTBYTES",
    "crypto_generichash_PERSONALBYTES",
    "crypto_generichash_STATEBYTES",
    "crypto_generichash_blake2b_salt_personal",
    "crypto_generichash_blake2b_init",
    "crypto_generichash_blake2b_update",
    "crypto_generichash_blake2b_final",
    "crypto_generichash_blake2b_state_copy",

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

    "crypto_shorthash_siphash24_BYTES",
    "crypto_shorthash_siphash24_KEYBYTES",
    "crypto_shorthash_siphash24",

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

    "crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE",
    "crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE",
    "crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE",
    "crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE",
    "crypto_pwhash_scryptsalsa208sha256_SALTBYTES",
    "crypto_pwhash_scryptsalsa208sha256_STRBYTES",
    "crypto_pwhash_scryptsalsa208sha256_ll",
    "crypto_pwhash_scryptsalsa208sha256_str",
    "crypto_pwhash_scryptsalsa208sha256_str_verify",
    "nacl_bindings_pick_scrypt_params",

    "randombytes",

    "sodium_init",

    "sodium_memcmp",
]

# Initialize Sodium
sodium_init()
