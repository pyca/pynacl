Reference vectors
=================

In addition to the policy of keeping any code path in PyNaCl covered by
unit tests, the output from cryptographic primitives and constructions
must be verified as being conformant to the reference implementations
or standards.

Imported reference vectors
--------------------------

Wherever possible it is the PyNaCl project's policy to use existing
reference vectors for primitives or constructions. These vectors should
ideally be in their original format, but it is acceptable to make minimal
changes to ease parsing at our discretion.


Box construction
^^^^^^^^^^^^^^^^

The reference vector for testing the :py:class:`nacl.public.Box`
implementation come from libsodium's ``test/default/box.c`` and
``test/default/box2.c`` and the corresponding expected outputs
in ``test/default/box.exp`` and ``test/default/box2.exp``

SecretBox construction
^^^^^^^^^^^^^^^^^^^^^^

The reference vector for testing the :py:class:`nacl.secret.SecretBox`
implementation come from libsodium's ``test/default/secretbox.c``
and the corresponding expected outputs in ``test/default/secretbox.exp``

chacha20poly1305
^^^^^^^^^^^^^^^^

The reference vectors for both the legacy draft-agl-tls-chacha20poly1305
and the IETF ratified rfc7539 chacha20poly1305 constructions are taken
from libressl version 2.5.5 tests/aeadtests.txt, excluding the shortened
authentication tag vectors, since libsodium only supports full sized tags.

xchacha20poly1305
^^^^^^^^^^^^^^^^^

The reference vector for the xchacha20poly1305 construction is taken
from the first test in libsodium's test/default/aead_xchacha20poly1305.c,
which defines the parameters, and the corresponding expected output from
aead_xchacha20poly1305.exp.

siphash24 and siphashx24
^^^^^^^^^^^^^^^^^^^^^^^^

The reference vectors for both the original and the 128 bit variants of
the siphash-2-4 construction are taken from the reference code sources.
In particular, the original expected results come from siphash's vectors.h,
while the key and the input messages have been generated following
the respective definitions in siphash's test.c.

Custom generated reference vectors
----------------------------------

In cases where there are no standardized test vectors, or the available ones
are not applicable to libsodium's implementation, test vectors are custom
generated.


.. toctree::
    :glob:

    *_vectors
    bundled_library_build
