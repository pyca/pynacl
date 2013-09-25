#!/usr/bin/env python
import sys
import os.path
import shlex
import shutil
import subprocess
import tarfile
import tempfile

from distutils.command.build_clib import build_clib as _build_clib

from setuptools import setup
from setuptools.command.test import test as TestCommand

import nacl


SODIUM_VERSION = "0.4.3"


def here(*paths):
    return os.path.abspath(os.path.join(os.path.dirname(__file__), *paths))


try:
    import nacl.nacl
except ImportError:
    # installing - there is no cffi yet
    ext_modules = []
else:
    # building bdist - cffi is here!
    ext_modules = [nacl.nacl.ffi.verifier.get_extension()]
    ext_modules[0].include_dirs.append(here("build/sodium/src/libsodium/include"))


class build_clib(_build_clib):

    def run(self):
        # Unpack the Libsodium Tarball
        sourcefile = tarfile.open(
            here("libsodium-%s.tar.gz" % SODIUM_VERSION),
        )

        tmpdir = tempfile.mkdtemp()
        try:
            sourcefile.extractall(tmpdir)

            # Copy our installed directory into the build location
            shutil.rmtree(here("build/sodium"))
            shutil.copytree(
                os.path.join(tmpdir, "libsodium-%s" % SODIUM_VERSION),
                here("build/sodium")
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            sourcefile.close()

        # Run ./configure
        subprocess.check_call(
            "./configure --disable-debug --disable-dependency-tracking",
            cwd=here("build/sodium"),
            shell=True,
        )

        # Parse the Makefile to determine what macros to define
        with open(here("build/sodium/Makefile")) as makefile:
            for line in makefile:
                if line.startswith("DEFS"):
                    defines = [
                        tuple(shlex.split(i)[0][2:].split("=", 1))
                        for i in shlex.split(line)
                        if i.startswith("-D")
                    ]

        # Configure libsodium using the Makefile defines
        libraries = []
        for libname, build_info in self.libraries:
            if libname == "sodium":
                # Store the define macros inside the build info
                macros = dict(build_info.get("macros", []))
                macros.update(dict(defines))
                build_info["macros"] = list(macros.items())

                sources = build_info["sources"]

                # Dynamically modify the implementation based on if we have
                #   TIMODE or not
                if "HAVE_TI_MODE" in macros:
                    sources.extend([
                        "crypto_scalarmult/curve25519/donna_c64/base_curve25519_donna_c64.c",
                        "crypto_scalarmult/curve25519/donna_c64/smult_curve25519_donna_c64.c",
                    ])
                else:
                    sources.extend([
                        "crypto_scalarmult/curve25519/ref/base_curve25519_ref.c",
                        "crypto_scalarmult/curve25519/ref/smult_curve25519_ref.c",
                    ])

                # Dynamically modify the implementation based on if we have
                #   AMD64 ASM or not.
                if "HAVE_AMD64_ASM" in macros:
                    sources.extend([
                        "crypto_stream/salsa20/amd64_xmm6/stream_salsa20_amd64_xmm6.S",
                    ])

                    self._include_asm = True
                else:
                    sources.extend([
                        "crypto_stream/salsa20/ref/stream_salsa20_ref.c",
                        "crypto_stream/salsa20/ref/xor_salsa20_ref.c",
                    ])

                    self._include_asm = False

                # Expand out all of the sources to their full path
                sources = [
                    here("build/sodium/src/libsodium", s) for s in sources
                ]

                build_info["sources"] = sources

            libraries.append((libname, build_info))

        self.libraries = libraries

        # Call our normal run
        return _build_clib.run(self)

    def build_libraries(self, libraries):
        # This is a convenient place to modify the compiler so that we can add
        #   the .S extension
        if self._include_asm and not ".S" in self.compiler.src_extensions:
            self.compiler.src_extensions.append(".S")

        return _build_clib.build_libraries(self, libraries)


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

    ext_package="nacl",
    ext_modules=ext_modules,

    libraries=[
        ("sodium", {
            "include_dirs": [
                here("build/sodium/src/libsodium/include/sodium"),
            ],
            "sources": [
                "crypto_auth/crypto_auth.c",
                "crypto_auth/hmacsha256/auth_hmacsha256_api.c",
                "crypto_auth/hmacsha256/ref/hmac_hmacsha256.c",
                "crypto_auth/hmacsha256/ref/verify_hmacsha256.c",
                "crypto_auth/hmacsha512256/auth_hmacsha512256_api.c",
                "crypto_auth/hmacsha512256/ref/hmac_hmacsha512256.c",
                "crypto_auth/hmacsha512256/ref/verify_hmacsha512256.c",
                "crypto_box/crypto_box.c",
                "crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c",
                "crypto_box/curve25519xsalsa20poly1305/ref/after_curve25519xsalsa20poly1305.c",
                "crypto_box/curve25519xsalsa20poly1305/ref/before_curve25519xsalsa20poly1305.c",
                "crypto_box/curve25519xsalsa20poly1305/ref/box_curve25519xsalsa20poly1305.c",
                "crypto_box/curve25519xsalsa20poly1305/ref/keypair_curve25519xsalsa20poly1305.c",
                "crypto_core/hsalsa20/ref2/core_hsalsa20.c",
                "crypto_core/hsalsa20/core_hsalsa20_api.c",
                "crypto_core/salsa20/ref/core_salsa20.c",
                "crypto_core/salsa20/core_salsa20_api.c",
                "crypto_core/salsa2012/ref/core_salsa2012.c",
                "crypto_core/salsa2012/core_salsa2012_api.c",
                "crypto_core/salsa208/ref/core_salsa208.c",
                "crypto_core/salsa208/core_salsa208_api.c",
                "crypto_generichash/crypto_generichash.c",
                "crypto_generichash/blake2/generichash_blake2_api.c",
                "crypto_generichash/blake2/ref/blake2b-ref.c",
                "crypto_generichash/blake2/ref/generichash_blake2b.c",
                "crypto_hash/crypto_hash.c",
                "crypto_hash/sha256/hash_sha256_api.c",
                "crypto_hash/sha256/ref/hash_sha256.c",
                "crypto_hash/sha512/hash_sha512_api.c",
                "crypto_hash/sha512/ref/hash_sha512.c",
                "crypto_hashblocks/sha256/ref/blocks_sha256.c",
                "crypto_hashblocks/sha256/hashblocks_sha256_api.c",
                "crypto_hashblocks/sha512/ref/blocks_sha512.c",
                "crypto_hashblocks/sha512/hashblocks_sha512_api.c",
                "crypto_onetimeauth/crypto_onetimeauth.c",
                "crypto_onetimeauth/poly1305/onetimeauth_poly1305.c",
                "crypto_onetimeauth/poly1305/onetimeauth_poly1305_api.c",
                "crypto_onetimeauth/poly1305/onetimeauth_poly1305_try.c",
                "crypto_onetimeauth/poly1305/53/auth_poly1305_53.c",
                "crypto_onetimeauth/poly1305/53/verify_poly1305_53.c",
                "crypto_onetimeauth/poly1305/donna/auth_poly1305_donna.c",
                "crypto_onetimeauth/poly1305/donna/verify_poly1305_donna.c",
                "crypto_scalarmult/crypto_scalarmult.c",
                "crypto_secretbox/crypto_secretbox.c",
                "crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c",
                "crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c",
                "crypto_shorthash/crypto_shorthash.c",
                "crypto_shorthash/siphash24/shorthash_siphash24_api.c",
                "crypto_shorthash/siphash24/ref/shorthash_siphash24.c",
                "crypto_sign/crypto_sign.c",
                "crypto_sign/ed25519/sign_ed25519_api.c",
                "crypto_sign/ed25519/ref10/fe_0.c",
                "crypto_sign/ed25519/ref10/fe_1.c",
                "crypto_sign/ed25519/ref10/fe_add.c",
                "crypto_sign/ed25519/ref10/fe_cmov.c",
                "crypto_sign/ed25519/ref10/fe_copy.c",
                "crypto_sign/ed25519/ref10/fe_frombytes.c",
                "crypto_sign/ed25519/ref10/fe_invert.c",
                "crypto_sign/ed25519/ref10/fe_isnegative.c",
                "crypto_sign/ed25519/ref10/fe_isnonzero.c",
                "crypto_sign/ed25519/ref10/fe_mul.c",
                "crypto_sign/ed25519/ref10/fe_neg.c",
                "crypto_sign/ed25519/ref10/fe_pow22523.c",
                "crypto_sign/ed25519/ref10/fe_sq.c",
                "crypto_sign/ed25519/ref10/fe_sq2.c",
                "crypto_sign/ed25519/ref10/fe_sub.c",
                "crypto_sign/ed25519/ref10/fe_tobytes.c",
                "crypto_sign/ed25519/ref10/ge_add.c",
                "crypto_sign/ed25519/ref10/ge_double_scalarmult.c",
                "crypto_sign/ed25519/ref10/ge_frombytes.c",
                "crypto_sign/ed25519/ref10/ge_madd.c",
                "crypto_sign/ed25519/ref10/ge_msub.c",
                "crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c",
                "crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c",
                "crypto_sign/ed25519/ref10/ge_p2_0.c",
                "crypto_sign/ed25519/ref10/ge_p2_dbl.c",
                "crypto_sign/ed25519/ref10/ge_p3_0.c",
                "crypto_sign/ed25519/ref10/ge_p3_dbl.c",
                "crypto_sign/ed25519/ref10/ge_p3_to_cached.c",
                "crypto_sign/ed25519/ref10/ge_p3_to_p2.c",
                "crypto_sign/ed25519/ref10/ge_p3_tobytes.c",
                "crypto_sign/ed25519/ref10/ge_precomp_0.c",
                "crypto_sign/ed25519/ref10/ge_scalarmult_base.c",
                "crypto_sign/ed25519/ref10/ge_sub.c",
                "crypto_sign/ed25519/ref10/ge_tobytes.c",
                "crypto_sign/ed25519/ref10/keypair.c",
                "crypto_sign/ed25519/ref10/open.c",
                "crypto_sign/ed25519/ref10/sc_muladd.c",
                "crypto_sign/ed25519/ref10/sc_reduce.c",
                "crypto_sign/ed25519/ref10/sign.c",
                "crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c",
                "crypto_sign/edwards25519sha512batch/ref/fe25519_edwards25519sha512batch.c",
                "crypto_sign/edwards25519sha512batch/ref/ge25519_edwards25519sha512batch.c",
                "crypto_sign/edwards25519sha512batch/ref/sc25519_edwards25519sha512batch.c",
                "crypto_sign/edwards25519sha512batch/ref/sign_edwards25519sha512batch.c",
                "crypto_stream/crypto_stream.c",
                "crypto_stream/aes128ctr/portable/afternm_aes128ctr.c",
                "crypto_stream/aes128ctr/stream_aes128ctr_api.c",
                "crypto_stream/aes128ctr/portable/beforenm_aes128ctr.c",
                "crypto_stream/aes128ctr/portable/common_aes128ctr.c",
                "crypto_stream/aes128ctr/portable/consts_aes128ctr.c",
                "crypto_stream/aes128ctr/portable/int128_aes128ctr.c",
                "crypto_stream/aes128ctr/portable/stream_aes128ctr.c",
                "crypto_stream/aes128ctr/portable/xor_afternm_aes128ctr.c",
                "crypto_stream/aes256estream/hongjun/aes256-ctr.c",
                "crypto_stream/aes256estream/stream_aes256estream_api.c",
                "crypto_stream/salsa2012/stream_salsa2012_api.c",
                "crypto_stream/salsa2012/ref/stream_salsa2012.c",
                "crypto_stream/salsa2012/ref/xor_salsa2012.c",
                "crypto_stream/salsa208/stream_salsa208_api.c",
                "crypto_stream/salsa208/ref/stream_salsa208.c",
                "crypto_stream/salsa208/ref/xor_salsa208.c",
                "crypto_stream/xsalsa20/stream_xsalsa20_api.c",
                "crypto_stream/xsalsa20/ref/stream_xsalsa20.c",
                "crypto_stream/xsalsa20/ref/xor_xsalsa20.c",
                "crypto_verify/16/verify_16_api.c",
                "crypto_verify/16/ref/verify_16.c",
                "crypto_verify/32/verify_32_api.c",
                "crypto_verify/32/ref/verify_32.c",
                "randombytes/randombytes.c",
                "randombytes/salsa20/randombytes_salsa20_random.c",
                "randombytes/sysrandom/randombytes_sysrandom.c",
                "sodium/compat.c",
                "sodium/core.c",
                "sodium/utils.c",
                "sodium/version.c",
            ],
        }),
    ],

    zip_safe=False,
    cmdclass={
        "build_clib": build_clib,
        "test": PyTest,
    },

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
