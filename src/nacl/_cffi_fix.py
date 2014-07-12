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

import imp
import os.path
import sys

import cffi.vengine_cpy
import cffi.vengine_gen


def _get_so_suffixes():
    suffixes = []
    for suffix, mode, type in imp.get_suffixes():
        if type == imp.C_EXTENSION:
            suffixes.append(suffix)

    if not suffixes:
        # bah, no C_EXTENSION available.  Occurs on pypy without cpyext
        if sys.platform == 'win32':
            suffixes = [".pyd"]
        else:
            suffixes = [".so"]

    return suffixes


def vengine_cpy_find_module(self, module_name, path, so_suffix):
    # We will ignore so_suffix and get it ourselves
    so_suffixes = _get_so_suffixes()

    try:
        f, filename, descr = imp.find_module(module_name, path)
    except ImportError:
        return None
    if f is not None:
        f.close()

    # Note that after a setuptools installation, there are both .py
    # and .so files with the same basename.  The code here relies on
    # imp.find_module() locating the .so in priority.
    if descr[0] not in so_suffixes:
        return None
    return filename


def vengine_gen_find_module(self, module_name, path, so_suffixes):
    # We will ignore so_suffix and get it ourselves
    so_suffixes = _get_so_suffixes()

    for so_suffix in so_suffixes:
        basename = module_name + so_suffix
        if path is None:
            path = sys.path
        for dirname in path:
            filename = os.path.join(dirname, basename)
            if os.path.isfile(filename):
                return filename


cffi.vengine_cpy.VCPythonEngine.find_module = vengine_cpy_find_module
cffi.vengine_gen.VGenericEngine.find_module = vengine_gen_find_module
