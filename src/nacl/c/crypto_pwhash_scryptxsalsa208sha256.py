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

from nacl._lib import lib
from nacl.exceptions import CryptoError

__all__ = ["crypto_pwhash_scryptxsalsa208sha256", "crypto_pwhash_scryptxsalsa208sha256_str", "crypto_pwhash_scryptxsalsa208sha256_str_verify"]


crypto_pwhash_scryptxsalsa208sha256_SALTBYTES = lib.crypto_pwhash_scryptxsalsa208sha256_saltbytes()
crypto_pwhash_scryptxsalsa208sha256_STRBYTES = lib.crypto_pwhash_scryptxsalsa208sha256_strbytes()

def crypto_pwhash_scryptxsalsa208sha256( outlen, passwd, salt, opslimit = 10000, memlimit = (2**11)*100 ):
    """
    returns uses the ``passwd`` and ``salt`` to produce derive a key of ``outlen`` bytes
    can be tuned by picking different ``opslimit`` and ``memlimit``
    
    :param outlen: int
    :param passwd: bytes
    :param salt: bytes
    :rtype: bytes
    """

    if len(salt) != crypto_pwhash_scryptxsalsa208sha256_SALTBYTES:
        raise ValueError("Invalid salt")

    buf = lib.ffi.new("unsigned char[]", outlen)

    ret = lib.crypto_pwhasd_scryptxsalsasha256(buf, outlen, passwd, len(passwd), salt, opslimit, memlimit )

    if ret != 0:
        raise CryptoError( "Key derivation fails!" )

    return lib.ffi.buffer(buf, outlen)[:]

def crypto_pwhash_scryptxsalsa208sha256_str( passwd, opslimit=5000, memlimit=(2**11)*50):
    """
    returns uses the ``passwd`` and ``salt`` and hashes them, producing a 
    ASCII string of crypto_pwhash_scryptxsalsa208sha256_STRBYTES in length, 
    including the null terminator. The returned string includes the salt
    and the tuning parameters, ``opslimit`` and ``memlimit``, and can be 
    written directly to disk as a password hash
    
    :param passwd: bytes
    :param opslimit: int
    :param memlimit: int
    :rtype: bytestring
    """
    buf = lib.ffi.new("unsigned char[]", crypto_pwhash_scryptxsalsa208sha256_STRBYTES)

    ret = lib.crypto_pwhash_scryptxsalsa208sha256_str(buf, passwd, len(passwd), opslimit, memlimit )

    if( ret != 0 ):
        raise CryptoError( "Failed to hash password" )

    return lib.ffi.string( buf )

def crypto_pwhash_scryptxsalsa208sha256_str_verify( passwd_hash, passwd ):
    """
    Verifies the ``passwd`` against the ``passwd_hash`` that was generated.
    Returns True or False depending on the success
    
    :param passwd_hash: bytes
    :param passwd: bytes
    :rtype: boolean
    """

    if len(passwd_hash) != crypto_pwhash_scryptxsalsa208sha256_STRBYTES:
        raise ValueError("Invalid password hash")

    if lib.crypto_pwhash_scryptxsalsa208sha256_str_verify(passwd_hash, passwd, len(passwd) ) == 0:
        return True
    else:
        return False
