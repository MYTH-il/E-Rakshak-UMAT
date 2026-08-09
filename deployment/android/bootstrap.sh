#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="6462901d1aaa0b090b867934ea5a01a82d31bc03"
readonly TREE_SHA256="9c554d1e1e2c7c5e70cf3d5b6504a28bc37ed62b81ddc0b0f3007b4bec2c58fa"
readonly REPOSITORY="https://github.com/d4ruvil/erakshak.git"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PATCH="$PROJECT_ROOT/deployment/android/patches/0001-reproducible-complete-container-build.patch"

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /absolute/path/to/android-upstream" >&2
  exit 2
fi
readonly CHECKOUT="$1"
if [[ "$CHECKOUT" != /* || "$CHECKOUT" == "/" ]]; then
  echo "checkout must be a non-root absolute path" >&2
  exit 2
fi
if [[ ! -d "$CHECKOUT/.git" ]]; then
  git clone --filter=blob:none --no-checkout "$REPOSITORY" "$CHECKOUT"
fi
git -C "$CHECKOUT" fetch origin "$COMMIT"
readonly OBSERVED_TREE="$(git -C "$CHECKOUT" archive "$COMMIT" | sha256sum | cut -d' ' -f1)"
if [[ "$OBSERVED_TREE" != "$TREE_SHA256" ]]; then
  echo "pinned Android source tree digest mismatch" >&2
  exit 1
fi
readonly BUILD_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$BUILD_ROOT"' EXIT
git -C "$CHECKOUT" archive "$COMMIT" | tar -x -C "$BUILD_ROOT"
patch --batch --forward -d "$BUILD_ROOT" -p1 <"$PATCH"
docker build --pull --tag umat-mobsf:6462901d "$BUILD_ROOT"
echo "Built umat-mobsf:6462901d from verified commit $COMMIT"
