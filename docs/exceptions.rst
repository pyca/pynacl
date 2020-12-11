Exceptions
==========

.. currentmodule:: nacl.exceptions

All of the exceptions raised from PyNaCl-exposed methods/functions
are subclasses of :py:exc:`nacl.exceptions.CryptoError`. This means
downstream users can just wrap cryptographic operations inside a

.. code-block:: python

    try:
        # cryptographic operations
    except nacl.exceptions.CryptoError:
        # cleanup after any kind of exception
        # raised from cryptographic-related operations

These are the exceptions implemented in :py:mod:`nacl.exceptions`:

PyNaCl specific exceptions
--------------------------

.. class:: CryptoError

    Base exception for all nacl related errors


.. class:: BadSignatureError

    Raised when the signature was forged or otherwise corrupt.


.. class:: InvalidkeyError

    Raised on password/key verification mismatch


.. class:: UnavailableError

    is a subclass of :class:`~nacl.exceptions.RuntimeError`, raised when
    trying to call functions not available in a minimal build of
    libsodium.


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


Utility functions for exception handling
----------------------------------------

.. function:: ensure(cond, *args, raising=nacl.exceptions.AssertionError)

    Returns if a condition is true, otherwise raise a caller-configurable
    :py:class:`Exception`

    :param cond: the condition to be checked
    :type cond: bool
    :param sequence args: the arguments to be passed to the exception's
                          constructor
    :param raising: the exception to be raised if `cond` is `False`
    :type raising: exception

Example usage:

.. code-block:: python

    nacl.exceptions.ensure(
        a == 1 or a == 2,
        "a must be either 1 or 2"
    )
