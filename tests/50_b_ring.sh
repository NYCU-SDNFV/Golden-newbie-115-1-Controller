#!/bin/sh
# Check Part B -- 9-switch ring shortest-path controller. Do not modify.
. "$(dirname "$0")/lib.sh"
banner "check B1: 9-switch ring (sequential MACs)"

require_container

grade_ring 9 ring_topo.py
