Changelog
=========

1.2.0 (UNRELEASED)
------------------

* Update ``libsodium`` to 1.0.12.
* Infrastructure: add jenkins support for automatic build of
  ``manylinux1`` binary wheels
* Added support for ``SealedBox`` construction.
* Added support for ``argon2i`` password hashing construct
* Added support for 128 bit ``siphashx24`` variant of ``siphash24``.
* Added support for ``from_seed`` APIs for X25519 keypair generation.

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
