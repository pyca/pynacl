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

import nacl.utils


def test_random_bytes_produces():
    assert len(nacl.utils.random(16)) == 16


def test_random_bytes_produces_different_bytes():
    assert nacl.utils.random(16) != nacl.utils.random(16)


def test_util_check_true_condition():
    nacl.utils.check_condition(1 == 1, AssertionError, 'one equals one')


def test_util_check_false_condition():
    with pytest.raises(AssertionError):
        nacl.utils.check_condition(1 == 0, AssertionError, 'one is not zero')


def test_util_check_unwanted_kwarg():
    with pytest.raises(TypeError):
        nacl.utils.check_condition(1 == 1, unexpected='unexpected')
