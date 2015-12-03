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

import glob
import os.path

from cffi import FFI


__all__ = ["ffi"]


HEADERS = glob.glob(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "*.h")
)


# Build our FFI instance
ffi = FFI()


# Add all of our header files, but sort first for consistency of the
# hash that CFFI generates and uses in the .so filename (the order of
# glob() results cannot be relied on)
for header in sorted(HEADERS):
    with open(header, "r") as hfile:
        ffi.cdef(hfile.read())


# Set our source so that we can actually build our bindings to sodium.
ffi.set_source("_sodium", "#include <sodium.h>", libraries=["sodium"])
