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
import nacl.exceptions as exc

from nacl.utils import ensure

SALTBYTES = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_SALTBYTES
PWHASH_SIZE = nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1
OPSLIMIT_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
MEMLIMIT_INTERACTIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
OPSLIMIT_SENSITIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
MEMLIMIT_SENSITIVE = \
    nacl.bindings.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE


def kdf_scryptsalsa208sha256(size, password, salt,
                             opslimit=OPSLIMIT_SENSITIVE,
                             memlimit=MEMLIMIT_SENSITIVE,
                             encoder=nacl.encoding.RawEncoder):
    """
    Makes a key defined from ``password`` and ``salt`` that is
    ``size`` bytes long

    the enclosing module provides the constants

        - :py:const:`.OPSLIMIT_INTERACTIVE`
        - :py:const:`.MEMLIMIT_INTERACTIVE`
        - :py:const:`.OPSLIMIT_SENSITIVE`
        - :py:const:`.MEMLIMIT_SENSITIVE`

    as a guidance for correct settings respectively for the
    interactive login and the long term key protecting sensitive data
    use cases.

    :param int size: int
    :param bytes password: bytes
    :param bytes salt: bytes
    :param int opslimit:
    :param int memlimit:
    :rtype: bytes
    """
    ensure(len(salt) == SALTBYTES,
           "The salt must be exactly %s, not %s bytes long" % (
                SALTBYTES,
                len(salt)
            ),
           raising=exc.ValueError
           )

    return encoder.encode(
        nacl.bindings.crypto_pwhash_scryptsalsa208sha256(size, password, salt,
                                                         opslimit, memlimit)
    )


def scryptsalsa208sha256(password,
                         opslimit=OPSLIMIT_INTERACTIVE,
                         memlimit=MEMLIMIT_INTERACTIVE):
    """
    Hashes a password with a random salt, returning an ascii string
    that has all the needed info to check against a future password

    The default settings for opslimit and memlimit are those deemed
    correct for the interactive user login case.

    :param bytes password:
    :param int opslimit:
    :param int memlimit:
    :rtype: bytes
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

    ensure(len(password_hash) == PWHASH_SIZE,
           "The pw_hash must be exactly %s bytes long" %
           nacl.bindings.crypto_pwhash_scryptsalsa208sha256_STRBYTES,
           raising=exc.ValueError)

    return nacl.bindings.crypto_pwhash_scryptsalsa208sha256_str_verify(
        password_hash, password
    )
