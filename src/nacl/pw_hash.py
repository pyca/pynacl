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

import nacl.c
import nacl.encoding

SALT_SIZE = nacl.c.crypto_pwhash_scryptxsalsa208sha256_SALTBYTES
PWHASH_SIZE = nacl.c.crypto_pwhash_scryptxsalsa208sha256_STRBYTES

def kdf_cryptxsalsa208sha256(size, password, salt, encoder=nacl.encoding.RawEncoder):
    """
    Makes a key defined from ``password`` and ``salt`` that is ``size`` bytes long

    :param size: int
    :param password: bytes
    :param salt: bytes
    :rtype: bytes
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(
                "The salt must be exactly %s bytes long" % 
                nacl.c.crypto_pwhash_scryptxsalsa208sha256_SALTBYTES, 
        )

    return encoder.encode(nacl.c.crypto_pwhash_scryptxsalsa208sha256(size, password, salt))


def cryptxsalsa208sha256(password):
    """
    Hashes a password with a random salt, returns an ascii string
    that has all the needed info to check against a future password

    :param password: bytes
    :rtype: byte string
    """

    return nacl.c.crypto_pwhash_cryptxsalsa208sha256S_str(message)


def verify_cryptxsalsa208sha256( password_hash, password ):
    """
    Takes the output of cryptxsalsa208sha25 and compares it against
    a user provided password to see if they are the same

    :param password_hash: bytes
    :param password: bytes
    :rtype: boolean
    """
    
    if len(password_hash) != PWHASH_SIZE:
        raise ValueError(
                "The pw_hash must be exactly %s bytes long" % 
                nacl.c.crypto_pwhash_scryptxsalsa208sha256_STRBYTES, 
        ) 

    return nacl.c.crypto_pwhash_cryptxsalsa208sha256S_str_verify(password_hash, password)

