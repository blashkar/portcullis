#!/bin/sh
# Runs one sandboxed MCP server on stdio:
#
#   portcullis wrap -- sandbox/run.sh filesystem
#
# The container gets no host files (no volumes or bind mounts), no network,
# no Linux capabilities, a read-only root filesystem and resource limits.
# Its only link to the host is the stdin/stdout stream portcullis inspects.
#
# --init runs a tiny init as PID 1 so SIGTERM reaches the server: a process
# running as PID 1 ignores SIGTERM unless it handles it, which would leave
# the container running after portcullis gives up on it.
set -eu

name=${1:?usage: run.sh <filesystem|git|everything>}
# The non-root user each image runs as: node (1000) or app (999).
case $name in
  filesystem | everything) uid=1000 ;;
  git) uid=999 ;;
  *) echo "run.sh: unknown server $name" >&2; exit 2 ;;
esac

exec docker run -i --rm --init \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --tmpfs /workspace:rw,noexec,nosuid,size=32m,uid=$uid,gid=$uid \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1 \
  --user $uid:$uid \
  --label portcullis.sandbox=1 \
  "portcullis-sandbox/$name"
