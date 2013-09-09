#!/usr/bin/env python
import os, sys, subprocess, shutil

from setuptools import setup
from setuptools.command.test import test as TestCommand

import nacl

class ShellError(Exception):
    pass

def shell(args, cwd=None):
    print "shell(%s)" % " ".join(args)
    p = subprocess.Popen(args, cwd=cwd)
    p.communicate()
    if p.returncode != 0:
        raise ShellError("rc=%d" % p.returncode)

# as soon as we import nacl.nacl, CFFI will try to compile the glue code. We
# must make sure libsodium.so is in place first.

libsodium_builddir = os.path.abspath("build-libsodium")
libsodium_outdir = os.path.abspath("nacl/libsodium")

if not os.path.isdir(libsodium_outdir):
    print "building libsodium before the python code"
    if os.path.exists(libsodium_builddir):
        shutil.rmtree(libsodium_builddir)
    os.makedirs(libsodium_builddir)
    b2 = os.path.join(libsodium_builddir, "libsodium-0.4.2")
    shell(["tar", "xf", "../libsodium-0.4.2.tar.gz"], libsodium_builddir)
    assert os.path.isdir(b2)
    shell(["./configure", "--prefix", libsodium_builddir], b2)
    shell(["make"], b2)
    shell(["make", "install"], b2)
    out = "nacl/libsodium"
    if not os.path.isdir(out):
        os.mkdir(out)
    shutil.copytree(os.path.join(libsodium_builddir, "include"),
                    os.path.join(out, "include"))
    shutil.copytree(os.path.join(libsodium_builddir, "lib"),
                    os.path.join(out, "lib"))

try:
    import nacl.nacl
except ImportError:
    # installing - there is no cffi yet
    pass


class PyTest(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errno = pytest.main(self.test_args)
        sys.exit(errno)


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
        "cffi",
    ],
    extras_require={
        "tests": ["pytest"],
    },
    tests_require=["pytest"],

    packages=[
        "nacl",
        "nacl.invoke",
    ],

    package_data={
        "nacl": ["libsodium/lib/*",
                 "libsodium/include/*.h",
                 "libsodium/include/sodium/*.h",
                 ]},

    zip_safe=False,
    cmdclass={"test": PyTest},

    classifiers=[
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
    ]
)
