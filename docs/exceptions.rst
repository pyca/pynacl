Exceptions
==========

These are the exceptions implemented in :py:mod:`nacl.exceptions`:

PyNaCl specific exceptions
--------------------------

.. class:: CryptoError

    Base exception for all nacl related errors


.. class:: BadSignatureError

    Raised when the signature was forged or otherwise corrupt.


.. class:: InvalidkeyError

    Raised on password/key verification mismatch


PyNaCl exceptions mixing-in standard library ones
-------------------------------------------------

Both for clarity and for compatibility with previous releases
of the PyNaCl, the following exceptions mix-in the same-named
standard library exception to :py:class:`~nacl.exceptions.CryptoError`.

.. class:: RuntimeError

    is a subclass of both CryptoError and standard library's
    RuntimeError, raised for internal library errors


.. class:: AssertionError

    is a subclass of both CryptoError and standard library's
    AssertionError, raised by default from
    :py:func:`~nacl.utils.ensure` when the checked condition is `False`


.. class:: TypeError

    is a subclass of both CryptoError and standard library's
    TypeError


.. class:: ValueError

    is a subclass of both CryptoError and standard library's
    ValueError
