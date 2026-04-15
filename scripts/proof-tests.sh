#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

echo "note: scripts/proof-tests.sh is kept as a compatibility alias; use scripts/verification-tests.sh"
"${script_dir}/verification-tests.sh" "$@"
