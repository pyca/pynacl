#!/bin/bash
#
# Script to upgrade the vendored copy of libsodium.
#
# Usage:
#     .github/bin/update-libsodium.sh <version>
#
# Example:
#     .github/bin/update-libsodium.sh 1.0.20

set -euo pipefail

BASE_URL="https://download.libsodium.org/libsodium/releases"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC_DIR="$REPO_ROOT/src"
LIBSODIUM_DIR="$SRC_DIR/libsodium"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>" >&2
    echo "Example: $0 1.0.20" >&2
    exit 1
fi

VERSION="$1"
TARBALL_NAME="libsodium-${VERSION}-stable.tar.gz"
MSVC_NAME="libsodium-${VERSION}-stable-msvc.zip"
TARBALL_URL="${BASE_URL}/${TARBALL_NAME}"
MSVC_URL="${BASE_URL}/${MSVC_NAME}"
MSVC_PATH="${SRC_DIR}/${MSVC_NAME}"

echo "Upgrading libsodium to version ${VERSION}"
echo

# Step 1: Check git is clean (ignore untracked files)
echo "Checking git working tree..."
if git status --porcelain | grep -qv '^??'; then
    echo "Error: Git working tree has uncommitted changes." >&2
    echo "Please commit or stash your changes first." >&2
    exit 1
fi
echo "  -> Working tree is clean"
echo

# Step 2: Download new files to temp location first to verify they exist
echo "Downloading new files..."
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

TMP_TARBALL="${TMPDIR}/${TARBALL_NAME}"
TMP_MSVC="${TMPDIR}/${MSVC_NAME}"

echo "Downloading ${TARBALL_URL}..."
if ! curl -fSL -o "$TMP_TARBALL" "$TARBALL_URL"; then
    echo "Error downloading tarball." >&2
    echo "Version ${VERSION} may not exist. Check available versions at:" >&2
    echo "  ${BASE_URL}/" >&2
    exit 1
fi
echo "  -> Downloaded tarball"

echo "Downloading ${MSVC_URL}..."
if ! curl -fSL -o "$TMP_MSVC" "$MSVC_URL"; then
    echo "Error downloading MSVC zip." >&2
    echo "Version ${VERSION} may not exist. Check available versions at:" >&2
    echo "  ${BASE_URL}/" >&2
    exit 1
fi
echo "  -> Downloaded MSVC zip"
echo

# Step 3: Remove old files
echo "Removing old files..."
if [ -d "$LIBSODIUM_DIR" ]; then
    echo "Removing ${LIBSODIUM_DIR}..."
    rm -rf "$LIBSODIUM_DIR"
fi

# Remove old MSVC zip (but not the one for the version we're upgrading to)
for old_file in "$SRC_DIR"/libsodium-*-stable-msvc.zip; do
    [ -e "$old_file" ] || continue
    if [[ "$old_file" == *"-${VERSION}-"* ]]; then
        continue
    fi
    echo "Removing old archive ${old_file}..."
    rm -f "$old_file"
done
echo

# Step 4: Extract tarball and install MSVC zip
echo "Extracting tarball to ${LIBSODIUM_DIR}..."
mkdir -p "$LIBSODIUM_DIR"
tar -xzf "$TMP_TARBALL" -C "$LIBSODIUM_DIR" --strip-components=1

echo "Installing MSVC zip..."
mv "$TMP_MSVC" "$MSVC_PATH"
echo "  -> ${MSVC_PATH}"
echo

echo "Successfully upgraded libsodium to ${VERSION}"
echo
echo "Next steps:"
echo "  1. Review the changes with 'git diff'"
echo "  2. Test the build"
echo "  3. Commit the changes"
