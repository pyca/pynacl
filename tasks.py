import hashlib
import os
import urllib2

from invoke import task, run


LIBSODIUM_VERSION = "0.2"
LIBSODIUM_URL = "http://download.dnscrypt.org/libsodium/releases/libsodium-0.2.tar.gz"
LIBSODIUM_HASH = b"e99a6b69adc080a5acf6b8a49fdc74b61d6f3579b590e85c93446a8325dde100"


@task(aliases=["install.sodium"])
def install_sodium():
    tarball_path = os.path.expanduser(
                        "~/libsodium-{}.tar.gz".format(LIBSODIUM_VERSION),
                    )

    # Download libsodium and verify it's hash
    resp = urllib2.urlopen(LIBSODIUM_URL)
    content = resp.read()
    content_hash = hashlib.sha256(content).hexdigest()

    if content_hash != LIBSODIUM_HASH:
        raise ValueError("Hash mismatch for downloaded libsodium")

    with open(tarball_path, "wb") as fp:
        fp.write(content)

    curdir = os.getcwd()
    try:
        os.chdir(os.path.expanduser("~/"))

        # Unpack the tarball
        run("tar xf libsodium-{}.tar.gz".format(LIBSODIUM_VERSION))

        # Configure and install the library
        os.chdir(os.path.expanduser(
                    "~/libsodium-{}/".format(LIBSODIUM_VERSION),
                ))
        run("./configure --disable-debug --disable-dependency-tracking",
            hide="out",
        )
        run("make", hide="out")
        run("sudo make install", hide="out")
    finally:
        os.chdir(curdir)


@task(aliases=["install.requirements"])
def install_requirements(dev=False):
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
