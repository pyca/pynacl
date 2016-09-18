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
from __future__ import absolute_import
from __future__ import division

import nacl.bindings
import nacl.encoding

SALT_SIZE = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
PWHASH_SIZE = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1
_SC_OPS_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
_SC_MEM_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
_SC_OPS_SENSITIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
_SC_MEM_SENSITIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE


def kdf_scryptsalsa208sha256(size, password, salt,
                             opslimit=_SC_OPS_SENSITIVE,
                             memlimit=_SC_MEM_SENSITIVE,
                             encoder=nacl.encoding.RawEncoder):
    """
    Makes a key defined from ``password`` and ``salt`` that is
    ``size`` bytes long

    :param size: int
    :param password: bytes
    :param salt: bytes
    :param opslimit: int
    :param memlimit: int
    :rtype: bytes
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(
            "The salt must be exactly %s, not %s bytes long" % (
                SALT_SIZE,
                len(salt)
            )
        )

    return encoder.encode(
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256(size, password, salt,
                                                         opslimit, memlimit)
    )


def scryptsalsa208sha256(password,
                         opslimit=_SC_OPS_INTERACTIVE,
                         memlimit=_SC_MEM_INTERACTIVE):
    """
    Hashes a password with a random salt, returns an ascii string
    that has all the needed info to check against a future password

    The default settings for opslimit and memlimit are those deemed
    correct for the interactive user login case.

    :param password: bytes
    :param opslimit: int
    :param memlimit: int
    :rtype: byte string
    """

    return nacl.bindings.crypto_pwhash_scryptsalsa208sha256_str(password,
                                                                opslimit,
                                                                memlimit)


def verify_scryptsalsa208sha256(password_hash, password):
    """
    Takes the output of scryptsalsa208sha256 and compares it against
    a user provided password to see if they are the same

    :param password_hash: bytes
    :param password: bytes
    :rtype: boolean
    """

    if len(password_hash) != PWHASH_SIZE:
        raise ValueError(
            "The pw_hash must be exactly %s bytes long" %
            nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
        )

    return nacl.bindings.crypto_pwhash_scryptsalsa208sha256_str_verify(
        password_hash, password
    )
