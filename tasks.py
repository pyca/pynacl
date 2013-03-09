import hashlib
import os
import urllib2

from invoke import task, run


LIBSODIUM_VERSION = "0.3"
LIBSODIUM_URL = "http://download.dnscrypt.org/libsodium/releases/libsodium-0.3.tar.gz"
LIBSODIUM_HASH = b"908a26f84bedb432305c81ec6773aa95b8e724ba2ece6234840685a74e033750"
LIBSODIUM_AUTOGEN = False


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

        if LIBSODIUM_AUTOGEN:
            run("./autogen.sh", hide="out")

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
        run("pip install file://$PWD#egg=pynacl[tests]")
        # Install again to get an editable install
        run("pip install -e .")
    else:
        run("pip install .")


@task
def tests():
    run("py.test")
