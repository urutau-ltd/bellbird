#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "Usage: $0 [all|ci|build|e2e|verify]"
}

target="${1:-all}"
case "$target" in
all)
	make_cmd='make verify'
	;;
ci)
	make_cmd='make ci'
	;;
build)
	make_cmd='make build'
	;;
e2e)
	make_cmd='make e2e'
	;;
verify)
	make_cmd='make verify'
	;;
proof)
	# Compatibility alias.
	make_cmd='make verify'
	;;
*)
	usage
	exit 2
	;;
esac

root_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
image="${PIPELINE_IMAGE:-localhost/bellbird-ci:1.0.0}"
containerfile="${PIPELINE_CONTAINERFILE:-${root_dir}/Containerfile.ci}"
pull_policy="${PIPELINE_PULL_POLICY:-missing}"

if ! command -v podman >/dev/null 2>&1; then
	echo "podman is required but was not found in PATH" >&2
	exit 1
fi

if [[ ! -f "$containerfile" ]]; then
	echo "containerfile not found: $containerfile" >&2
	exit 1
fi

cache_root="${root_dir}/.cache/pipeline"
build_cache="${cache_root}/go-build"
mod_cache="${cache_root}/go-mod"
mkdir -p "$build_cache" "$mod_cache"

echo "==> Building CI image: $image"
podman build \
	--pull="$pull_policy" \
	-f "$containerfile" \
	-t "$image" \
	"$root_dir"

echo "==> Running pipeline target: $target"
podman run --rm \
	--user "$(id -u):$(id -g)" \
	-v "${root_dir}:/workspace" \
	-v "${build_cache}:/cache/go-build" \
	-v "${mod_cache}:/cache/go-mod" \
	-w /workspace \
	-e GOCACHE=/cache/go-build \
	-e GOMODCACHE=/cache/go-mod \
	"$image" \
	/bin/sh -lc "$make_cmd"

echo "==> Pipeline finished"
