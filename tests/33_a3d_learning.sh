#!/bin/sh
# Check A3 part a3d - grades results/controller.json + captures/controller.pcap from check A3a. Do not modify.
. "$(dirname "$0")/lib.sh"
banner "check A3d: learning-switch behaviour"
[ -f results/controller.json ] || die "results/controller.json is missing" "run check A3a first (make a3)"
grade2 a3d
