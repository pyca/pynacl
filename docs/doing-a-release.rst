Doing A Release
===============

To run a PyNaCl release follow these steps:

* Update the version number in ``src/nacl/__init__.py``.
* Update ``README.rst`` changelog section with the date of the release.
* Send a pull request with these items and wait for it to be merged.
* Run ``python release.py release {version}``

Once the release script completes you can verify that the sdist and wheels are
present on PyPI and then send a new PR to bump the version to the next major
version (e.g. ``1.2.0.dev1``).
