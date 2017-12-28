Hashing
=======

.. currentmodule:: nacl.hash

Cryptographic secure hash functions are irreversible transforms
of input data to a fixed length `digest`.

The standard properties of a cryptographic hash make these functions useful
both for standalone usage as data integrity checkers, as well as ``black-box``
building blocks of other kind of algorithms and data structures.

All of the hash functions exposed in :py:mod:`nacl.hash` can be used
as data integrity checkers.

Integrity check examples
------------------------

Message's creator perspective (:py:func:`~nacl.hash.sha256`,
                               :py:func:`~nacl.hash.sha512`,
                               :py:func:`~nacl.hash.blake2b`)

.. testcode::

    import nacl.encoding
    import nacl.hash

    HASHER = nacl.hash.sha256
    # could be nacl.hash.sha512 or nacl.hash.blake2b instead

    # define a 1024 bytes log message
    msg = 16*b'256 BytesMessage'
    digest = HASHER(msg, encoder=nacl.encoding.HexEncoder)

    # now send msg and digest to the user
    print(nacl.encoding.HexEncoder.encode(msg))
    print(digest)

.. testoutput::

    b'3235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d6573736167653235362042797465734d657373616765'
    b'12b413c70c148d79bb57a1542156c5f35e24ad77c38e8c0e776d055e827cdd45'



Message's user perspective (:py:func:`~nacl.hash.sha256`,
                            :py:func:`~nacl.hash.sha512`,
                            :py:func:`~nacl.hash.blake2b`)

.. testcode::

    from nacl.bindings.utils import sodium_memcmp
    import nacl.encoding
    import nacl.hash

    HASHER = nacl.hash.sha256
    # could be nacl.hash.sha512 or nacl.hash.blake2b instead

    # we received a 1024 bytes long message and it hex encoded digest
    received_msg = nacl.encoding.HexEncoder.decode(
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    b'3235362042797465734d6573736167653235362042797465734d657373616765'
    )

    dgst = b'12b413c70c148d79bb57a1542156c5f35e24ad77c38e8c0e776d055e827cdd45'

    shortened = received_msg[:-1]
    modified = b'modified' + received_msg[:-8]

    orig_dgs = HASHER(received_msg, encoder=nacl.encoding.HexEncoder)
    shrt_dgs = HASHER(shortened, encoder=nacl.encoding.HexEncoder)
    mdfd_dgs = HASHER(modified, encoder=nacl.encoding.HexEncoder)

    def eq_chk(dgs0, dgs1):
        if sodium_memcmp(dgs0, dgs1):
            return 'equals'
        return 'is different from'

    MSG = 'Digest of {0} message {1} original digest'

    for chk in (('original', orig_dgs),
                ('truncated', shrt_dgs),
                ('modified', mdfd_dgs)):

        print(MSG.format(chk[0], eq_chk(dgst, chk[1])))

.. testoutput::

    Digest of original message equals original digest
    Digest of truncated message is different from original digest
    Digest of modified message is different from original digest


Additional hashing usages for :class:`~nacl.hash.blake2b`
---------------------------------------------------------

As already hinted above, traditional cryptographic hash functions can be used
as building blocks for other uses, typically combining a secret-key with
the message via some construct like the ``HMAC`` one.

The :class:`~nacl.hash.blake2b` hash function can be used directly both
for message authentication and key derivation, replacing the ``HMAC`` construct
and the ``HKDF`` one by setting the additional parameters ``key``, ``salt``
and ``person``.

Please note that **key stretching procedures** like ``HKDF`` or
the one outlined in `Key derivation`_ are **not** suited to derive
a *cryptographically-strong* key from a *low-entropy input* like a plain-text
password or to compute a strong *long-term stored* hash used as password
verifier. See the :ref:`password-hashing` section for some more informations
and usage examples of the password hashing constructs provided in
:py:mod:`~nacl.pwhash`.

Message authentication
----------------------

To authenticate a message, using a secret key, the blake2b function
must be called as in the following example.

Message authentication example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. testcode::

    import nacl.encoding
    import nacl.utils
    from nacl.hash import blake2b

    msg = 16*b'256 BytesMessage'
    msg2 = 16*b'256 bytesMessage'

    auth_key = nacl.utils.random(size=64)
    # the simplest way to get a cryptographic quality auth_key
    # is to generate it with a cryptographic quality
    # random number generator

    auth1_key = nacl.utils.random(size=64)
    # generate a different key, just to show the mac is changed
    # both with changing messages and with changing keys

    mac0 = blake2b(msg, key=auth_key, encoder=nacl.encoding.HexEncoder)
    mac1 = blake2b(msg, key=auth1_key, encoder=nacl.encoding.HexEncoder)
    mac2 = blake2b(msg2, key=auth_key, encoder=nacl.encoding.HexEncoder)

    for i, mac in enumerate((mac0, mac1, mac2)):
        print('Mac{0} is: {1}.'.format(i, mac))

.. testoutput::

    Mac0 is: b'...'.
    Mac1 is: b'...'.
    Mac2 is: b'...'.


Key derivation
--------------

The blake2b algorithm can replace a key derivation function by
following the lines of:

Key derivation example
~~~~~~~~~~~~~~~~~~~~~~

.. testcode::

    import nacl.encoding
    import nacl.utils
    from nacl.hash import blake2b

    master_key = nacl.utils.random(64)

    derivation_salt = nacl.utils.random(16)

    personalization = b'<DK usage>'

    derived = blake2b(b'', key=master_key, salt=derivation_salt,
                      person=personalization,
                      encoder=nacl.encoding.RawEncoder)

By repeating the key derivation procedure before encrypting our messages,
and sending the derivation_salt along with the encrypted message, we can
expect to never reuse a key, drastically reducing the risks which ensue from
such a reuse.
