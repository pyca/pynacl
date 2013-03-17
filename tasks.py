from invoke import Collection, task, run

from nacl.invoke import sodium

ns = Collection()
ns.add_collection(sodium)


@ns.add_task
@task
def tests():
    run("py.test")
