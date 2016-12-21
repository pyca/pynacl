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

import six

import nacl.bindings


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


class StringFixer(object):

    def __str__(self):
        if six.PY3:
            return self.__unicode__()
        else:
            return self.__bytes__()


def random(size=32):
    return nacl.bindings.randombytes(size)


def check_condition(cond, *args, **kwds):
    """
    Return if a condition is true, otherwise raise a caller-configurable
    :py:class:`Exception`
    :param bool cond: the condition to be chacked
    :param sequence args: the arguments to be passed to the exception's
                          consructor
    The only accepted named parameter is `raising` used to configure the
    exception to be raised if `cond` is not `True`
    """
    _CHK_UNEXP = 'check_condition() got an unexpected keyword argument {0}'

    raising = kwds.pop('raising', AssertionError)
    if kwds:
        raise TypeError(_CHK_UNEXP.format(repr(kwds.popitem[0])))

    if cond is True:
        return
    raise raising(*args)
