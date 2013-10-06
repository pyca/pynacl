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

from . import nacl
from . import six


class EncryptedMessage(six.binary_type):
    """
    A bytes subclass that holds a messaged that has been encrypted by a
    :class:`SecretBox`.
    """

    @classmethod
    def _from_parts(cls, nonce, ciphertext, combined):
        obj = cls(combined)
        obj._nonce = nonce
        obj._ciphertext = ciphertext
        return obj

    @property
    def nonce(self):
        """
        The nonce used during the encryption of the :class:`EncryptedMessage`.
        """
        return self._nonce

    @property
    def ciphertext(self):
        """
        The ciphertext contained within the :class:`EncryptedMessage`.
        """
        return self._ciphertext


def random(size=32):
    data = nacl.ffi.new("unsigned char[]", size)
    nacl.lib.randombytes(data, size)
    return nacl.ffi.buffer(data, size)[:]
