#!/bin/bash -ex

cd /test

echo "Building for ${PLATFORM}"

PYBIN="/opt/python/${PYTHON}/bin"

mkdir -p /test/wheelhouse.final

"${PYBIN}"/python -m venv .venv

.venv/bin/pip install -U pip wheel cffi

.venv/bin/python setup.py sdist
cd dist
tar zxf PyNaCl*.tar.gz
rm -rf PyNaCl*.tar.gz
cd PyNaCl*

REGEX="cp3([0-9])*"
if [[ "${PYBIN}" =~ $REGEX ]]; then
    PY_LIMITED_API="--py-limited-api=cp3${BASH_REMATCH[1]}"
fi

LIBSODIUM_MAKE_ARGS="-j$(nproc)" ../../.venv/bin/python setup.py bdist_wheel "$PY_LIMITED_API"

auditwheel repair --plat "${PLATFORM}" -w wheelhouse/ dist/PyNaCl*.whl

../../.venv/bin/pip install pynacl --no-index -f wheelhouse/
../../.venv/bin/python -c "import nacl.signing; key = nacl.signing.SigningKey.generate();signature = key.sign(b'test'); key.verify_key.verify(signature)"

mv wheelhouse/* /test/wheelhouse.final
