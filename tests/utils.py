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

import os


def assert_equal(x, y):
    assert x == y
    assert not (x != y)


def assert_not_equal(x, y):
    assert x != y
    assert not (x == y)


def read_crypto_test_vectors(fname, maxels=0):
    vectors = []
    path = os.path.join(os.path.dirname(__file__), "data", fname)
    with open(path, "rb") as fp:
        for line in fp:
            line = line.rstrip()
            if line and line[0] != b'#'[0]:
                splt = [x for x in line.split(b'\t')]
                if maxels:
                    splt = splt[:maxels]
                vectors.append(tuple(splt))
    return vectors
