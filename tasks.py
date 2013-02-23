import hashlib
import os
import urllib2

from invoke import task, run


def download(url, hash, path):
    resp = urllib2.urlopen(url)
    content = resp.read()
    content_hash = hashlib.sha256(content).hexdigest()
    assert hash == content_hash

    with open(path, "wb") as fp:
        fp.write(content)


@task(aliases=["install-nacl"])
def install_nacl(library):
    def _install_libsodium():
        tarball_path = os.path.expanduser("~/libsodium-0.2.tar.gz")

        # Download libsodium and verify it's hash
        download(
            "http://download.dnscrypt.org/libsodium/releases/libsodium-0.2.tar.gz",
            "e99a6b69adc080a5acf6b8a49fdc74b61d6f3579b590e85c93446a8325dde100",
            tarball_path,
        )

        curdir = os.getcwd()
        try:
            os.chdir(os.path.expanduser("~/"))

            # Unpack the tarball
            run("tar xf libsodium-0.2.tar.gz")

            # Configure and install the library
            os.chdir(os.path.expanduser("~/libsodium-0.2/"))
            run("./configure --disable-debug --disable-dependency-tracking")
            run("make")
            run("sudo make install")
        finally:
            os.chdir(curdir)

    def _install_nacl():
        raise NotImplementedError

    libraries = {
        "libsodium": _install_libsodium,
        "nacl": _install_nacl,
    }

    # Install the library
    libraries[library]()


@task
def install(dev=False):
    if dev:
        # Install once to get the tests extra
        run("pip install file://$PWD#egg=pynacl[tests]")
        # Install again to get an editable install
        run("pip install -e .")
    else:
        run("pip install .")


@task
def tests(suite=None):
    if suite is None:
        suite = set(["pep8", "lint", "unit"])
    else:
        suite = set(suite.split(","))

    if "pep8" in suite:
        run("pep8 nacl")

    if "lint" in suite:
        run("pylint --rcfile .pylintrc -r y nacl")

    if "unit" in suite:
        run("py.test")
