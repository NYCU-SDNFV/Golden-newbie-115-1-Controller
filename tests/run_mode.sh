#!/bin/sh
# Shared driver for the four mode checks. Do not modify.
#   tests/run_mode.sh <flood|normal|reference|controller|proactive> "<banner>" [grader-part]
. "$(dirname "$0")/lib.sh"
MODE="$1"
PART="${3:-$1}"
banner "$2"
require_container

dexec test -f /workspace/harness/run_mode.py \
  || die "/workspace/harness/run_mode.py is not visible inside the container" \
         "the repository must be mounted at /workspace (docker-compose.yml)"

# Run the experiment inside the container and show its output (flow table etc.).
if ! dexec sh -c "cd /workspace && python3 harness/run_mode.py $MODE 2>&1"; then
  die "harness/run_mode.py $MODE exited with an error" \
      "an 'unfinished: TODO ...' line means you have not done that part yet; a traceback means a bug in your harness/modes.py or harness/controller.py"
fi

# Grade the JSON it produced (on the host; results/ is the mounted repo).
grade2 "$PART"
