#!/usr/bin/env bash
# Stop servers started by start_servers.sh
WORK=${1:?work dir}
[ -f "$WORK/pids" ] && xargs kill < "$WORK/pids" 2>/dev/null
[ -f "$WORK/ssh/sshd.pid" ] && kill "$(cat "$WORK/ssh/sshd.pid")" 2>/dev/null
[ -f "$WORK/agent.sock.path" ] && rm -rf "$(dirname "$(cat "$WORK/agent.sock.path")")" "$WORK/agent.sock.path"
rm -f "$WORK/pids"
echo "stopped"
