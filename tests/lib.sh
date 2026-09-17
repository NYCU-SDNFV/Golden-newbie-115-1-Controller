# Shared helpers for the Lab 1 checks. Do not modify.
# shellcheck shell=sh

CONTAINER="${CONTAINER:-lab1}"

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; }

die() {
  fail "$1"
  [ -n "$2" ] && printf '      hint: %s\n' "$2" >&2
  exit 1
}

banner() {
  printf '\n=== %s ===\n' "$1"
}

# Is the container up?
container_running() {
  [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ]
}

# Run a command inside the container.
dexec() {
  docker exec "$CONTAINER" "$@"
}

# AppArmor pre-flight。為什麼要查：capability（cap_add）和 LSM（AppArmor）是兩層
# 不同的東西。容器可以拿到 SYS_ADMIN 卻仍被 docker 預設的 `docker-default` profile
# 擋掉 mount —— 而 Mininet 建 network namespace 時就要 mount。症狀是 net.start()
# 靜靜卡死，不報錯，所以沒有這個檢查只會看到 test timeout。
# 為什麼本機不會遇到：Docker Desktop（Windows/macOS）跑在 LinuxKit VM 上沒有
# AppArmor；autograder 的 Ubuntu 主機有。
# 成功時不印任何東西（每個 check 都會呼叫，別洗版）。
preflight_apparmor() {
  aa=$(dexec sh -c 'cat /proc/self/attr/current 2>/dev/null' 2>/dev/null \
       | tr -d '\000' | tr -d '\n' | tr -d '\r')
  case "$aa" in
    "" | unconfined*) return 0 ;;
  esac
  die "the container is confined by the AppArmor profile '$aa' -- Mininet will hang" \
      "cap_add grants capabilities, but AppArmor is a separate layer on top.
      Add   security_opt:
              - apparmor:unconfined
      next to your cap_add, or use 'privileged: true' (which turns off both layers).
      Your laptop probably has no AppArmor, which is why this passes locally
      and hangs on the autograder."
}

preflight_nofile() {
  limit=$(dexec sh -c 'ulimit -n') \
    || die "cannot read the container's file-descriptor limit" "recreate it with make up"
  case "$limit" in
    "" | *[!0-9]*) die "unexpected file-descriptor limit: $limit" \
      "docker-compose.yml must set ulimits.nofile to 65536" ;;
  esac
  [ "$limit" -le 1048576 ] || die \
    "RLIMIT_NOFILE=$limit makes Mininet's mnexec close billions of descriptors" \
    "use the supplied docker-compose.yml (nofile soft/hard 65536), then make up"
}

require_container() {
  container_running || die \
    "container '$CONTAINER' is not running" \
    "check TODO 1 and TODO 4 in docker-compose.yml, then: make up; make logs"
  preflight_apparmor
  preflight_nofile
}

# lab1_grade.py 住在哪裡取決於誰在跑：
#   學生 checkout       -> tests/lab1_grade.py
#   Classroom 50 bundle -> 跟 test 腳本同一層（canonical，學生改不到）
# $0 是呼叫端的腳本，所以這裡用 $0 而不是 lib.sh 自己的路徑。
grade2() {
  g="$(dirname "$0")/lab1_grade.py"
  python3 "$g" "$@"
}

grade_ring() {
  docker exec -i "$CONTAINER" python3 - --num "$1" \
    --topo "/workspace/topo/$2" --start-controller \
    < "$(dirname "$0")/grade_ring.py"
}
