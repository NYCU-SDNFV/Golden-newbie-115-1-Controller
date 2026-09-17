#!/bin/sh
# Wait until the container is up and ovs-vswitchd answers. Do not modify.
. "$(dirname "$0")/lib.sh"

i=0
while [ "$i" -lt 30 ]; do
  if container_running && dexec ovs-vsctl show >/dev/null 2>&1; then
    pass "container '$CONTAINER' is running, ovs-vswitchd answers"
    preflight_apparmor   # 定義在 lib.sh；本 Lab 的 compose 是 privileged，這只是保險
    preflight_nofile
    exit 0
  fi
  i=$((i + 1))
  sleep 1
done

die "container '$CONTAINER' did not become ready in 30s" \
    "run 'make logs'; most likely TODO 1, 2 or 4 in docker-compose.yml"
