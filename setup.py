#!/usr/bin/env python
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

import functools
import glob
import os
import os.path
import subprocess
import sys

from distutils.command.build_clib import build_clib as _build_clib
from distutils.command.build_ext import build_ext as _build_ext

from setuptools import Distribution, setup

from distutils.command.build import build
from setuptools.command.install import install


SODIUM_MAJOR = 4
SODIUM_MINOR = 5

CFFI_DEPENDENCY = "cffi>=0.8"


def here(*paths):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), *paths))

sodium = functools.partial(here, "src/libsodium/src/libsodium")


sys.path.insert(0, here("src"))


import nacl


def which(name, flags=os.X_OK):  # Taken from twisted
    result = []
    exts = filter(None, os.environ.get('PATHEXT', '').split(os.pathsep))
    path = os.environ.get('PATH', None)
    if path is None:
        return []
    for p in os.environ.get('PATH', '').split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, flags):
            result.append(p)
        for e in exts:
            pext = p + e
            if os.access(pext, flags):
                result.append(pext)
    return result


def get_ext_modules():
    import nacl._lib
    return [nacl._lib.ffi.verifier.get_extension()]


class CFFIBuild(build):
    """
    This class exists, instead of just providing ``ext_modules=[...]`` directly
    in ``setup()`` because importing cryptography requires we have several
    packages installed first.

    By doing the imports here we ensure that packages listed in
    ``setup_requires`` are already installed.
    """

    def finalize_options(self):
        self.distribution.ext_modules = get_ext_modules()
        build.finalize_options(self)


class CFFIInstall(install):
    """
    As a consequence of CFFIBuild and it's late addition of ext_modules, we
    need the equivalent for the ``install`` command to install into platlib
    install-dir rather than purelib.
    """

    def finalize_options(self):
        self.distribution.ext_modules = get_ext_modules()
        install.finalize_options(self)

def keywords_with_side_effects(argv):
    """
    Get a dictionary with setup keywords that (can) have side effects.

    :param argv: A list of strings with command line arguments.
    :returns: A dictionary with keyword arguments for the ``setup()`` function.

    This setup.py script uses the setuptools 'setup_requires' feature because
    this is required by the cffi package to compile extension modules. The
    purpose of ``keywords_with_side_effects()`` is to avoid triggering the cffi
    build process as a result of setup.py invocations that don't need the cffi
    module to be built (setup.py serves the dual purpose of exposing package
    metadata).

    All of the options listed by ``python setup.py --help`` that print
    information should be recognized here. The commands ``clean``,
    ``egg_info``, ``register``, ``sdist`` and ``upload`` are also recognized.
    Any combination of these options and commands is also supported.

    This function was originally based on the `setup.py script`_ of SciPy (see
    also the discussion in `pip issue #25`_).

    .. _pip issue #25: https://github.com/pypa/pip/issues/25
    .. _setup.py script: https://github.com/scipy/scipy/blob/master/setup.py
    """
    no_setup_requires_arguments = (
        '-h', '--help',
        '-n', '--dry-run',
        '-q', '--quiet',
        '-v', '--verbose',
        '-V', '--version',
        '--author',
        '--author-email',
        '--classifiers',
        '--contact',
        '--contact-email',
        '--description',
        '--egg-base',
        '--fullname',
        '--help-commands',
        '--keywords',
        '--licence',
        '--license',
        '--long-description',
        '--maintainer',
        '--maintainer-email',
        '--name',
        '--no-user-cfg',
        '--obsoletes',
        '--platforms',
        '--provides',
        '--requires',
        '--url',
        'clean',
        'egg_info',
        'register',
        'sdist',
        'upload',
    )

    def is_short_option(argument):
        """Check whether a command line argument is a short option."""
        return len(argument) >= 2 and argument[0] == '-' and argument[1] != '-'

    def expand_short_options(argument):
        """Expand combined short options into canonical short options."""
        return ('-' + char for char in argument[1:])

    def argument_without_setup_requirements(argv, i):
        """Check whether a command line argument needs setup requirements."""
        if argv[i] in no_setup_requires_arguments:
            # Simple case: An argument which is either an option or a command
            # which doesn't need setup requirements.
            return True
        elif (is_short_option(argv[i]) and
              all(option in no_setup_requires_arguments
                  for option in expand_short_options(argv[i]))):
            # Not so simple case: Combined short options none of which need
            # setup requirements.
            return True
        elif argv[i - 1:i] == ['--egg-base']:
            # Tricky case: --egg-info takes an argument which should not make
            # us use setup_requires (defeating the purpose of this code).
            return True
        else:
            return False
    if all(argument_without_setup_requirements(argv, i)
           for i in range(1, len(argv))):
        return {
            "cmdclass": {
                "build": DummyCFFIBuild,
                "install": DummyCFFIInstall,
                "build_clib": build_clib,
                "build_ext": build_ext,
            }
        }
    else:
        return {
            "setup_requires": [CFFI_DEPENDENCY],
            "cmdclass": {
                "build": CFFIBuild,
                "install": CFFIInstall,
                "build_clib": build_clib,
                "build_ext": build_ext,
            }
        }

setup_requires_error = ("Requested setup command that needs 'setup_requires' "
                        "while command line arguments implied a side effect "
                        "free command or option.")

class DummyCFFIBuild(build):
    """
    This class makes it very obvious when ``keywords_with_side_effects()`` has
    incorrectly interpreted the command line arguments to ``setup.py build`` as
    one of the 'side effect free' commands or options.
    """

    def run(self):
        raise RuntimeError(setup_requires_error)


class DummyCFFIInstall(install):
    """
    This class makes it very obvious when ``keywords_with_side_effects()`` has
    incorrectly interpreted the command line arguments to ``setup.py install``
    as one of the 'side effect free' commands or options.
    """

    def run(self):
        raise RuntimeError(setup_requires_error)


def use_system():
    install_type = os.environ.get("SODIUM_INSTALL")

    if install_type == "system":
        # If we are forcing system installs, don't compile the bundled one
        return True
    elif install_type == "bundled":
        # If we are forcing bundled installs, compile it
        return False

    # Detect if we have libsodium available
    import cffi

    ffi = cffi.FFI()
    ffi.cdef("""
        int sodium_library_version_major();
        int sodium_library_version_minor();
    """)

    try:
        system = ffi.dlopen("libsodium")
    except OSError:
        # We couldn't locate libsodium so we'll use the bundled one
        return False

    if system.sodium_library_version_major() != SODIUM_MAJOR:
        return False

    if system.sodium_library_version_minor() < SODIUM_MINOR:
        return False

    # If we got this far then the system library should be good enough
    return True


class Distribution(Distribution):

    def has_c_libraries(self):
        return not use_system()


class build_clib(_build_clib):

    def get_source_files(self):
        files = glob.glob(here("src/libsodium/*"))
        files += glob.glob(here("src/libsodium/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*/*/*"))
        files += glob.glob(here("src/libsodium/*/*/*/*/*/*"))

        return files

    def build_libraries(self, libraries):
        raise Exception("build_libraries")

    def check_library_list(self, libraries):
        raise Exception("check_library_list")

    def get_library_names(self):
        return ["sodium"]

    def run(self):
        if use_system():
            return

        build_temp = os.path.abspath(self.build_temp)

        # Ensure our temporary build directory exists
        try:
            os.makedirs(build_temp)
        except IOError:
            pass

        # Ensure all of our executanle files have their permission set
        for filename in [
                "src/libsodium/autogen.sh",
                "src/libsodium/compile",
                "src/libsodium/config.guess",
                "src/libsodium/config.sub",
                "src/libsodium/configure",
                "src/libsodium/depcomp",
                "src/libsodium/install-sh",
                "src/libsodium/missing",
                "src/libsodium/msvc-scripts/process.bat",
                "src/libsodium/test/default/wintest.bat",
                "src/libsodium/test-driver"]:
            os.chmod(here(filename), 0o755)

        # Locate our configure script
        configure = here("src/libsodium/configure")

        # Run ./configure
        subprocess.check_call(
            [
                configure, "--disable-shared", "--enable-static",
                "--disable-debug", "--disable-dependency-tracking",
                "--with-pic", "--prefix", os.path.abspath(self.build_clib),
            ],
            cwd=build_temp,
        )

        # Build the library
        subprocess.check_call(["make"], cwd=build_temp)

        # Check the build library
        subprocess.check_call(["make", "check"], cwd=build_temp)

        # Install the built library
        subprocess.check_call(["make", "install"], cwd=build_temp)


class build_ext(_build_ext):

    def run(self):
        if self.distribution.has_c_libraries():
            build_clib = self.get_finalized_command("build_clib")
            self.include_dirs.append(
                os.path.join(build_clib.build_clib, "include"),
            )
            self.library_dirs.append(
                os.path.join(build_clib.build_clib, "lib"),
            )

        return _build_ext.run(self)


setup(
    name=nacl.__title__,
    version=nacl.__version__,

    description=nacl.__summary__,
    long_description=open("README.rst").read(),
    url=nacl.__uri__,
    license=nacl.__license__,

    author=nacl.__author__,
    author_email=nacl.__email__,

    install_requires=[
        CFFI_DEPENDENCY,
        "six",
    ],
    extras_require={
        "tests": ["pytest"],
    },
    tests_require=["pytest"],

    package_dir={"": "src"},
    packages=[
        "nacl",
        "nacl._lib",
        "nacl.c",
    ],
    package_data={"nacl._lib": ["*.h"]},

    ext_package="nacl._lib",

    distclass=Distribution,
    zip_safe=False,

    classifiers=[
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
    ],
    **keywords_with_side_effects(sys.argv)
)
