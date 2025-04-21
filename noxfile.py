import nox

nox.options.reuse_existing_virtualenvs = True
nox.options.default_venv_backend = "uv|virtualenv"


@nox.session
def tests(session: nox.Session) -> None:
    session.install("coverage", "pretend", ".[tests]")

    session.run(
        "coverage",
        "run",
        "--parallel-mode",
        "-m",
        "pytest",
        "--capture=no",
        "--strict-markers",
        *session.posargs,
    )
    session.run("coverage", "combine")
    session.run("coverage", "report", "-m")


@nox.session
def docs(session: nox.Session) -> None:
    session.install("doc8", ".[docs]")
    tmpdir = session.create_tmp()

    session.run(
        "sphinx-build",
        "-W",
        "-b",
        "html",
        "-d",
        f"{tmpdir}/doctrees",
        "docs",
        "docs/_build/html",
    )
    session.run(
        "sphinx-build",
        "-W",
        "-b",
        "doctest",
        "-d",
        f"{tmpdir}/doctrees",
        "docs",
        "docs/_build/html",
    )
    session.run(
        "sphinx-build", "-W", "-b", "linkcheck", "docs", "docs/_build/html"
    )
    session.run("doc8", "README.rst", "docs/", "--ignore-path", "docs/_build/")


@nox.session
def meta(session: nox.Session) -> None:
    session.install("ruff", "check-manifest")
    session.run("ruff", "check", ".")
    session.run("ruff", "format", "--check", ".")
    session.run("check-manifest", ".")


@nox.session
def mypy(session: nox.Session) -> None:
    session.install(".[tests]", "mypy")

    session.run("mypy")
