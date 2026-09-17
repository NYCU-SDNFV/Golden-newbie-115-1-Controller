#!/bin/sh
# Check Part B -- 11-switch ring with random MACs. Do not modify.
# Tests that the controller does not hardcode switch count or MAC patterns.
. "$(dirname "$0")/lib.sh"
banner "check B2: 11-switch ring (random MACs)"

require_container

grade_ring 11 ring11_topo.py
