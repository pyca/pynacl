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
import sys

from cffi import FFI


__all__ = ["ffi"]


HEADERS = glob.glob(
    os.path.join(os.path.abspath(os.path.dirname(__file__)), "*.h")
)


# Build our FFI instance
ffi = FFI()

for header in HEADERS:
    with open(header, "r") as hfile:
        ffi.cdef(hfile.read())

# we need to easily control a few values for Windows builds
source = []
if os.getenv("PYNACL_SODIUM_STATIC") is not None:
    source.append("#define SODIUM_STATIC")

source.append("#include <sodium.h>")

if sys.platform == "windows":
    libraries = ["libsodium"]
else:
    libraries = ["sodium"]

# Set our source so that we can actually build our bindings to sodium.
ffi.set_source("_sodium", "\n".join(source), libraries=libraries)
