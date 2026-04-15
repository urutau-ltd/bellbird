#!/usr/bin/env bash
set -euo pipefail

binary="${1:-./build/bell}"

if [[ ! -x "$binary" ]]; then
	echo "verification: binary not found or not executable: $binary" >&2
	exit 1
fi

echo "==> verification: baseline e2e"
"$binary" selftest --timeout 15s

echo "==> verification: token-authenticated e2e"
"$binary" selftest --timeout 15s --token "verify-token-v1"

echo "==> verification: negative auth check (expected failure)"
if "$binary" selftest --timeout 15s --relay-token "verify-token-v1" --client-token "wrong-token" >/dev/null 2>&1; then
	echo "verification: expected auth failure did not occur" >&2
	exit 1
fi

echo "==> verification: all checks passed"
