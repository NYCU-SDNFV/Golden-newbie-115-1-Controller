#!/bin/sh
# Check 0 - the container is up, has the tools, sees the repo. Do not modify.
. "$(dirname "$0")/lib.sh"
banner "check 0: container and toolchain"

require_container
pass "container '$CONTAINER' is running"

for tool in mn ovs-vsctl ovs-ofctl ovs-appctl osken-manager python3 tcpdump ping; do
  dexec sh -c "command -v $tool >/dev/null 2>&1" \
    || die "'$tool' not found inside the container" \
           "the image ghcr.io/nycu-sdnfv/lab-base:115-1 provides it (osken-manager is only for the A0 reference controller); an old cached image lacks it -- try make build"
done
pass "mn / ovs-* / osken-manager / python3 / tcpdump / ping are all present"

dexec python3 -c "import os_ken, mininet" 2>/dev/null \
  || die "python3 inside the container cannot import os_ken / mininet" "rebuild the image: make build"
pass "python3 can import os_ken and mininet"

dexec test -f /workspace/harness/run_mode.py && dexec test -f /workspace/reference/refctl.py \
  || die "/workspace/harness/run_mode.py is not visible inside the container" \
         "the repository must be mounted at /workspace (see docker-compose.yml)"
pass "the repository is mounted at /workspace"

printf '      %s\n' "$(dexec ovs-vsctl --version | head -1)"
printf '      mininet %s\n' "$(dexec mn --version 2>&1 | head -1)"
