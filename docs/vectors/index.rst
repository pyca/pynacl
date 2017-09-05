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


Custom generated reference vectors
----------------------------------

In cases where there are no standardized test vectors, or the available ones
are not applicable to libsodium's implementation, test vectors are custom
generated.


.. toctree::
    :glob:

    *_vectors
    bundled_library_build
