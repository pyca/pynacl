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

import pytest
import six

import nacl.utils
from nacl import exceptions as exc


class CustomError(exc.CryptoError):
    pass


class StringFixerChild(nacl.utils.StringFixer):
    def __unicode__(self):
        return u'test'

    def __bytes__(self):
        return b'test'


def test_string_fixer():
    sfc = StringFixerChild()
    assert str(sfc) == u'test' if six.PY3 else b'test'


def test_bytes_as_string():
    string = nacl.utils.bytes_as_string(b'test')
    assert string == u'test' if six.PY3 else b'test'


def test_random_bytes_produces():
    assert len(nacl.utils.random(16)) == 16


def test_random_bytes_produces_different_bytes():
    assert nacl.utils.random(16) != nacl.utils.random(16)


def test_util_ensure_with_true_condition():
    nacl.utils.ensure(1 == 1, 'one equals one')


def test_util_ensure_with_false_condition():
    with pytest.raises(AssertionError):
        nacl.utils.ensure(1 == 0, 'one is not zero',
                          raising=exc.AssertionError)


def test_util_ensure_with_unwanted_kwarg():
    with pytest.raises(TypeError):
        nacl.utils.ensure(1 == 1, unexpected='unexpected')


def test_util_ensure_custom_exception():
    with pytest.raises(CustomError):
        nacl.utils.ensure(1 == 0, 'Raising a CustomError', raising=CustomError)
