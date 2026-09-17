#!/usr/bin/env bash
# Local checks use the adjacent manifest; official grading uses the canonical bundle.
set -euo pipefail
_HERE=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$(git rev-parse --show-toplevel)"
python3 "$_HERE/integrity.py" --manifest "$_HERE/manifest.sha256" --workspace "$PWD"
