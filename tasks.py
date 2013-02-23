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
            run("./configure --disable-debug --disable-dependency-tracking", hide="out")
            run("make", hide="out")
            run("sudo make install", hide="out")
        finally:
            os.chdir(curdir)

    def _install_nacl():
        tarball_path = os.path.expanduser("~/nacl-20110221.tar.bz2")

        # Download libnacl and verify it's hash
        download(
            "http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2",
            "4f277f89735c8b0b8a6bbd043b3efb3fa1cc68a9a5da6a076507d067fc3b3bf8",
            tarball_path,
        )

        curdir = os.getcwd()
        try:
            os.chdir(os.path.expanduser("~/"))

            # Unpack the tarball
            run("tar xf nacl-20110221.tar.bz2", hide="out")

            # Configure and install the library
            os.chdir(os.path.expanduser("~/nacl-20110221/"))
            run("sudo ./do", hide="out")
        finally:
            os.chdir(curdir)

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
        run("pip install file://$PWD#egg=pynacl[tests]", hide="out")
        # Install again to get an editable install
        run("pip install -e .", hide="out")
    else:
        run("pip install .", hide="out")


@task
def tests():
    run("py.test")
