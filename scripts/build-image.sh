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

# The toolchain, crate registry and target dir are cached either in named
# volumes (default) or in directories under VSM_CACHE_DIR (for CI).
if [ -n "${VSM_CACHE_DIR:-}" ]; then
    mkdir -p "$VSM_CACHE_DIR/rustup" "$VSM_CACHE_DIR/cargo" "$VSM_CACHE_DIR/target"
    # The rust image keeps its cargo/rustup shims in $CARGO_HOME/bin. A named
    # volume is seeded from the image by Docker, but an empty bind mount is
    # not, so seed it once before hiding that path in the builder.
    if [ ! -x "$VSM_CACHE_DIR/cargo/bin/cargo" ]; then
        docker run --rm -v "$VSM_CACHE_DIR/cargo:/seed" "$BUILDER_IMAGE" \
            sh -c 'cp -R /usr/local/cargo/. /seed/'
    fi
    rustup_mount="$VSM_CACHE_DIR/rustup:/usr/local/rustup"
    cargo_mount="$VSM_CACHE_DIR/cargo:/usr/local/cargo"
    target_mount="$VSM_CACHE_DIR/target:/tmp/target"
    cache_kind="cache directories under $VSM_CACHE_DIR"
else
    rustup_mount="vsm-rustup:/usr/local/rustup"
    cargo_mount="vsm-cargo:/usr/local/cargo"
    target_mount="vsm-build-cache:/tmp/target"
    cache_kind="named Docker volumes"
fi

# An un-smudged Git LFS pointer would be embedded as if it were the real asset.
# Reject it before compiling instead of shipping a broken binary.
if grep -r -l '^version https://git-lfs' static/ >/dev/null 2>&1; then
    echo "error: static/ contains un-smudged Git LFS pointer files; run: git lfs install && git lfs pull" >&2
    exit 1
fi

echo "==> Compiling static $TARGET binary in $BUILDER_IMAGE into $ROOT/dist/vsm (using $cache_kind)"
# The repository is mounted read-only so the host tree is never polluted by
# root-owned build artifacts. --locked makes an out-of-date Cargo.lock fail
# instead of silently resolving a different dependency set.
docker run --rm $sysctl_flags \
    -v "$ROOT:/src:ro" \
    -v "$rustup_mount" \
    -v "$cargo_mount" \
    -v "$target_mount" \
    -v "$ROOT/dist:/out" \
    "$BUILDER_IMAGE" \
    sh -eu -c "
        apk add --no-cache build-base musl-dev
        cd /src
        CARGO_TARGET_DIR=/tmp/target cargo build --release --locked --target $TARGET
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
