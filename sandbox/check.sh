#!/bin/sh
# Starts a sandboxed server the way portcullis does and checks from inside
# the container that it can't reach the host: no host mounts, no network,
# no capabilities, not root, read-only root filesystem.
#
#   sandbox/check.sh filesystem
set -eu
name=${1:?usage: check.sh <filesystem|git|everything>}
dir=$(dirname "$0")

# Keep the server's stdin open while we probe it.
sleep 60 | "$dir/run.sh" "$name" >/dev/null 2>&1 &
trap 'kill $! 2>/dev/null || true' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  id=$(docker ps -q --filter label=portcullis.sandbox=1 --filter ancestor="portcullis-sandbox/$name" | head -1)
  [ -n "$id" ] && break
  sleep 1
done
[ -n "${id:-}" ] || { echo "container didn't start" >&2; exit 1; }

fail=0
check() { # check <description> <command that must succeed>
  if sh -c "$2" >/dev/null 2>&1; then echo "ok    $1"; else echo "FAIL  $1"; fail=1; fi
}

# connect <host> <port> tries a TCP connection from inside the container with
# whatever runtime the image has. Exit 0: it failed to connect, which is what
# we want. Exit 1: it connected. Exit 2: no runtime to test with, so the check
# fails rather than passing by accident.
connect() {
  docker exec "$id" sh -c '
    if command -v node >/dev/null; then
      exec node -e "const s=require(\"net\").connect({host:process.argv[1],port:+process.argv[2],timeout:3000});
        s.on(\"connect\",()=>process.exit(1)); s.on(\"timeout\",()=>process.exit(0)); s.on(\"error\",()=>process.exit(0))" "$1" "$2"
    elif command -v python3 >/dev/null; then
      exec python3 -c "import socket,sys
try: socket.create_connection((sys.argv[1], int(sys.argv[2])), 3)
except OSError: sys.exit(0)
sys.exit(1)" "$1" "$2"
    fi
    exit 2' sh "$1" "$2"
}

check "no volumes or bind mounts" "[ \"\$(docker inspect -f '{{len .Mounts}}' $id)\" = 0 ]"
check "network mode is none" "[ \"\$(docker inspect -f '{{.HostConfig.NetworkMode}}' $id)\" = none ]"
check "not privileged" "[ \"\$(docker inspect -f '{{.HostConfig.Privileged}}' $id)\" = false ]"
check "no Docker socket inside" "! docker exec $id test -e /var/run/docker.sock"
check "no network interface up except loopback" "docker exec $id sh -c 'for i in /sys/class/net/*; do [ \$(basename \$i) = lo ] && continue; [ -f \$i/flags ] || continue; [ \$((\$(cat \$i/flags) & 1)) = 0 ] || exit 1; done'"
check "runs as a non-root user" "[ \"\$(docker exec $id id -u)\" != 0 ]"
check "no capabilities" "docker exec $id grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/self/status"
check "no privilege escalation" "docker exec $id grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status"
check "root filesystem is read-only" "! docker exec $id touch /should-fail"
check "workspace is writable" "docker exec $id touch /workspace/ok"
# The host by name, the Docker Desktop host (macOS) and docker0 (Linux) by
# address, and the internet.
for target in "host.docker.internal 11434" "192.168.65.254 11434" "172.17.0.1 11434" "1.1.1.1 443"; do
  # shellcheck disable=SC2086
  if connect $target; then echo "ok    can't connect to $target"; else echo "FAIL  can connect to $target (or nothing to test with)"; fail=1; fi
done

# Stopping the server must stop the container, or it would outlive portcullis.
kill -TERM "$(pgrep -f "docker run -i --rm --init.*portcullis-sandbox/$name" | head -1)"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  docker inspect "$id" >/dev/null 2>&1 || break
  sleep 1
done
check "container is gone after SIGTERM" "! docker inspect $id"
exit $fail
