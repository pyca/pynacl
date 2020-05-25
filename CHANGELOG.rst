Changelog
=========

1.4.0 (2020-05-25)
------------------

* Update ``libsodium`` to 1.0.18.
* **BACKWARDS INCOMPATIBLE:** We no longer distribute 32-bit ``manylinux1``
  wheels. Continuing to produce them was a maintenance burden.
* Added support for Python 3.8, and removed support for Python 3.4.
* Add low level bindings for extracting the seed and the public key
  from crypto_sign_ed25519 secret key
* Add low level bindings for deterministic random generation.
* Add ``wheel`` and ``setuptools`` setup_requirements in ``setup.py`` (#485)
* Fix checks on very slow builders (#481, #495)
* Add low-level bindings to ed25519 arithmetic functions
* Update low-level blake2b state implementation
* Fix wrong short-input behavior of SealedBox.decrypt() (#517)
* Raise CryptPrefixError exception instead of InvalidkeyError when trying
  to check a password against a verifier stored in a unknown format (#519)
* Add support for minimal builds of libsodium. Trying to call functions
  not available in a minimal build will raise an UnavailableError
  exception. To compile a minimal build of the bundled libsodium, set
  the SODIUM_INSTALL_MINIMAL environment variable to any non-empty
  string (e.g. ``SODIUM_INSTALL_MINIMAL=1``) for setup.

1.3.0 2018-09-26
----------------

* Added support for Python 3.7.
* Update ``libsodium`` to 1.0.16.
* Run and test all code examples in PyNaCl docs through sphinx's
  doctest builder.
* Add low-level bindings for chacha20-poly1305 AEAD constructions.
* Add low-level bindings for the chacha20-poly1305 secretstream constructions.
* Add low-level bindings for ed25519ph pre-hashed signing construction.
* Add low-level bindings for constant-time increment and addition
  on fixed-precision big integers represented as little-endian
  byte sequences.
* Add low-level bindings for the ISO/IEC 7816-4 compatible padding API.
* Add low-level bindings for libsodium's crypto_kx... key exchange
  construction.
* Set hypothesis deadline to None in tests/test_pwhash.py to avoid
  incorrect test failures on slower processor architectures.  GitHub
  issue #370

1.2.1 - 2017-12-04
------------------

* Update hypothesis minimum allowed version.
* Infrastructure: add proper configuration for readthedocs builder
  runtime environment.

1.2.0 - 2017-11-01
------------------

* Update ``libsodium`` to 1.0.15.
* Infrastructure: add jenkins support for automatic build of
  ``manylinux1`` binary wheels
* Added support for ``SealedBox`` construction.
* Added support for ``argon2i`` and ``argon2id`` password hashing constructs
  and restructured high-level password hashing implementation to expose
  the same interface for all hashers.
* Added support for 128 bit ``siphashx24`` variant of ``siphash24``.
* Added support for ``from_seed`` APIs for X25519 keypair generation.
* Dropped support for Python 3.3.

1.1.2 - 2017-03-31
------------------

* reorder link time library search path when using bundled
  libsodium

1.1.1 - 2017-03-15
------------------

* Fixed a circular import bug in ``nacl.utils``.

1.1.0 - 2017-03-14
------------------

* Dropped support for Python 2.6.
* Added ``shared_key()`` method on ``Box``.
* You can now pass ``None`` to ``nonce`` when encrypting with ``Box`` or
  ``SecretBox`` and it will automatically generate a random nonce.
* Added support for ``siphash24``.
* Added support for ``blake2b``.
* Added support for ``scrypt``.
* Update ``libsodium`` to 1.0.11.
* Default to the bundled ``libsodium`` when compiling.
* All raised exceptions are defined mixing-in
  ``nacl.exceptions.CryptoError``

1.0.1 - 2016-01-24
------------------

* Fix an issue with absolute paths that prevented the creation of wheels.

1.0 - 2016-01-23
----------------

* PyNaCl has been ported to use the new APIs available in cffi 1.0+.
  Due to this change we no longer support PyPy releases older than 2.6.
* Python 3.2 support has been dropped.
* Functions to convert between Ed25519 and Curve25519 keys have been added.

0.3.0 - 2015-03-04
------------------

* The low-level API (`nacl.c.*`) has been changed to match the
  upstream NaCl C/C++ conventions (as well as those of other NaCl bindings).
  The order of arguments and return values has changed significantly. To
  avoid silent failures, `nacl.c` has been removed, and replaced with
  `nacl.bindings` (with the new argument ordering). If you have code which
  calls these functions (e.g. `nacl.c.crypto_box_keypair()`), you must review
  the new docstrings and update your code/imports to match the new
  conventions.
