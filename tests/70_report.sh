#!/bin/sh
# Check C - the report is filled in and its numbers are your own. Do not modify.
. "$(dirname "$0")/lib.sh"
banner "check C: report cross-checked against your results"
for m in flood normal reference controller proactive; do
  [ -f "results/$m.json" ] || die "results/$m.json is missing" \
      "the report check needs all five runs; run make a0 a1 a2 a3 a4 first"
done
grade2 report
