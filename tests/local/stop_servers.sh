#!/usr/bin/env bash
# Stop servers started by start_servers.sh
WORK=${1:?work dir}
if [ -f "$WORK/pids" ]; then
  for p in $(cat "$WORK/pids"); do kill "$p" 2>/dev/null; done
fi
[ -f "$WORK/ssh/sshd.pid" ] && kill "$(cat "$WORK/ssh/sshd.pid" 2>/dev/null)" 2>/dev/null
rm -f "$WORK/pids"

# The agent: stopped if its process id is known, and its socket directory
# removed only once nothing listens on the socket any more. An agent that is
# still alive keeps its socket, and agent.sock.path keeps pointing at it.
if [ -f "$WORK/agent.sock.path" ]; then
  SOCK=$(cat "$WORK/agent.sock.path")
  if [ -f "$WORK/agent.pid" ]; then
    kill "$(cat "$WORK/agent.pid")" 2>/dev/null
    for _ in $(seq 1 20); do [ -S "$SOCK" ] || break; sleep 0.1; done
  fi
  # ssh-add -l exits with 2 when it cannot reach an agent.
  SSH_AUTH_SOCK=$SOCK ssh-add -l > /dev/null 2>&1
  if [ $? -eq 2 ]; then
    rm -rf "$(dirname "$SOCK")" "$WORK/agent.sock.path" "$WORK/agent.pid"
  else
    echo "ssh-agent on $SOCK is still running (not started by start_servers.sh?); left alone"
  fi
fi
echo "stopped"
