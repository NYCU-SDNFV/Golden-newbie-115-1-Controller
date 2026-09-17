#!/bin/sh
# Check A0 - run the reference controller and capture what it says on the wire. Do not modify.
exec sh "$(dirname "$0")/run_mode.sh" reference "check A0: reference controller + capture"
