from invoke import Collection, task, run

from nacl.invoke import sodium

ns = Collection()
ns.add_collection(sodium)


@ns.add_task
@task
def tests():
    run("py.test")


@ns.add_task
@task
def install_pypy():
    import os

    run("wget -q https://bitbucket.org/pypy/pypy/downloads/pypy-2.0-beta1-linux.tar.bz2")
    run("tar xf pypy-2.0-beta1-linux.tar.bz2")
    # run("rm -rf ~/virtualenv/pypy")
    run("ls pypy-2.0-beta1/bin")
    run(os.path.expanduser("virtualenv -p pypy-2.0-beta1/bin/pypy ~/virtualenv/pypy2"))
