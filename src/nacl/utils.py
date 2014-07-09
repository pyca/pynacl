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

import six

import nacl.c


class EncryptedMessage(six.binary_type):

    @classmethod
    def _from_parts(cls, nonce, ciphertext, combined):
        obj = cls(combined)
        obj._nonce = nonce
        obj._ciphertext = ciphertext
        return obj

    @property
    def nonce(self):
        return self._nonce

    @property
    def ciphertext(self):
        return self._ciphertext


class StringFixer(object):

    def __str__(self):
        if six.PY3:
            return self.__unicode__()
        else:
            return self.__bytes__()


def random(size=32):
    return nacl.c.randombytes(size)
