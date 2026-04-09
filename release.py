# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# /// script
# dependencies = [
#     "click",
# ]
# ///

import subprocess

import click


def run(*args, **kwargs):
    print("[running] {}".format(list(args)))
    subprocess.check_call(list(args), **kwargs)


@click.command()
@click.argument("version")
def release(version):
    """
    ``version`` should be a string like '0.4' or '1.0'.
    """
    run("git", "tag", "-s", version, "-m", "{} release".format(version))
    run("git", "push", "git@github.com:pyca/pynacl.git", version)


if __name__ == "__main__":
    release()
