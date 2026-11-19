#!/bin/sh
set -eu

# Resolve the repository root from this script so the command works from any CWD.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$ROOT"

TARGET=x86_64-unknown-linux-musl
BUILDER_IMAGE=${BUILDER_IMAGE:-rust:1-alpine}
IMAGE=${IMAGE:-kr0nus/vsm:devel}

push=0
for arg in "$@"; do
    case "$arg" in
        --push) push=1 ;;
    esac
done

mkdir -p dist

# Some hosts have no working IPv6 route; Alpine's resolver returns AAAA records
# first and `apk add` then stalls indefinitely. Disabling IPv6 in the builder
# container makes the package step deterministic. Probe once because the sysctl
# is not permitted on every CI runner, and fall back to a plain run there.
sysctl_flags=""
if docker run --rm --sysctl net.ipv6.conf.all.disable_ipv6=1 "$BUILDER_IMAGE" true >/dev/null 2>&1; then
    sysctl_flags="--sysctl net.ipv6.conf.all.disable_ipv6=1"
fi

echo "==> Compiling static $TARGET binary in $BUILDER_IMAGE into $ROOT/dist/vsm"
# The repository is mounted read-only so the host tree is never polluted by
# root-owned build artifacts. The named volume keeps Cargo's target dir cached.
docker run --rm $sysctl_flags \
    -v "$ROOT:/src:ro" \
    -v vsm-build-cache:/tmp/target \
    -v "$ROOT/dist:/out" \
    "$BUILDER_IMAGE" \
    sh -eu -c "
        apk add --no-cache build-base musl-dev
        cd /src
        CARGO_TARGET_DIR=/tmp/target cargo build --release --target $TARGET
        cp /tmp/target/$TARGET/release/vsm /out/vsm
    "

if [ ! -f "$ROOT/dist/vsm" ]; then
    echo "error: builder did not produce $ROOT/dist/vsm" >&2
    exit 1
fi

echo "==> Building $IMAGE from a context containing only dist/vsm"
if [ "$push" -eq 1 ]; then
    docker buildx build -t "$IMAGE" "$@" .
else
    docker buildx build -t "$IMAGE" --load "$@" .
fi
