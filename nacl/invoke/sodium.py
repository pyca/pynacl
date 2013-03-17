import hashlib
import os

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

from invoke import task, run

LIBSODIUM_VERSION = "0.3"
LIBSODIUM_URL = "http://download.dnscrypt.org/libsodium/releases/libsodium-0.3.tar.gz"
LIBSODIUM_HASH = b"908a26f84bedb432305c81ec6773aa95b8e724ba2ece6234840685a74e033750"


@task
def install():
    path = os.path.expanduser("~/libsodium-%s.tar.gz" % LIBSODIUM_VERSION)

    # Download libsodium and verify it's hash
    resp = urlopen(LIBSODIUM_URL)
    content = resp.read()
    content_hash = hashlib.sha256(content).hexdigest()

    # Verify our content matches the expected hash
    if content_hash != LIBSODIUM_HASH:
        raise ValueError("Hash mismatch for downloaded sodium")

    # Write out the tarball
    with open(path, "wb") as fp:
        fp.write(content)

    curdir = os.getcwd()
    try:
        os.chdir(os.path.expanduser("~/"))

        # Unpack the tarball
        run("tar xf libsodium-%s.tar.gz" % LIBSODIUM_VERSION)

        # Configure and install the library
        os.chdir(os.path.expanduser("~/libsodium-%s/" % LIBSODIUM_VERSION))

        run("./configure --disable-debug --disable-dependency-tracking",
            hide="out",
        )
        run("make", hide="out")
        run("sudo make install", hide="out")
    finally:
        os.chdir(curdir)
