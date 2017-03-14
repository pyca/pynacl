PyNaCl: Python binding to the Networking and Cryptography (NaCl) library
========================================================================

Contents
--------

.. toctree::
   :maxdepth: 2

   public
   secret
   signing
   hashing
   password_hashing


Support Features
----------------

.. toctree::
    :maxdepth: 2

    encoding
    exceptions
    utils


Api Documentation
-----------------

.. toctree::
    :maxdepth: 2
    :glob:

    api/hash
    api/hashlib

Doing A Release
===============

To run a PyNaCl release follow these steps:

* Update the version number in ``src/nacl/__init__.py``.
* Update ``README.rst`` changelog section with the date of the release.
* Send a pull request with these items and wait for it to be merged.
* Run ``invoke release {version}``

Once the release script completes you can verify that the sdist and wheels are
present on PyPI and then send a new PR to bump the version to the next major
version (e.g. ``1.2.0.dev1``).


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
