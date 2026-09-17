#!/bin/sh
# Check A3a - run YOUR controller, then grade the handshake (HELLO / FEATURES / ECHO). Do not modify.
# This is the only A3 step that runs the experiment; A3b-A3d grade the same results/ and captures/.
exec sh "$(dirname "$0")/run_mode.sh" controller "check A3a: your controller -- handshake and keepalive" a3a
