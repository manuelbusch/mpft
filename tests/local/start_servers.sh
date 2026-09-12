#!/usr/bin/env bash
# Start local test servers (no Docker needed) and print the MPT_IT_* variables
# for `cargo test --test integration`. Requires a Python venv with:
#   pip install pyftpdlib pyopenssl aiosmtpd "moto[server]" wsgidav cheroot
# Usage: bash tests/local/start_servers.sh <venv-dir> <work-dir>
#        source <work-dir>/env.sh && cargo test --test integration
# Stop:  bash tests/local/stop_servers.sh <work-dir>
set -u
VENV=$(cd "${1:?venv dir}" && pwd); mkdir -p "${2:?work dir}"; WORK=$(cd "$2" && pwd); PY=$VENV/bin/python
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$WORK"/{ftp,http,webdav,mail/tmp,mail/new,mail/cur,ssh,logs}
cd "$WORK"

# self-signed cert for FTPS
if [ ! -f cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj "/CN=localhost" 2>/dev/null
  cat key.pem cert.pem > ftp_cert.pem
fi

start() { # name, port, command...
  local name=$1 port=$2; shift 2
  if nc -z -w1 127.0.0.1 "$port" 2>/dev/null; then echo "$name: port $port already in use, skipping"; return; fi
  nohup "$@" > "logs/$name.log" 2>&1 &
  echo $! >> pids
}
: > pids
start ftp    2121 $PY "$HERE/ftp_server.py" 2121 2122 "$WORK/ftp" "$WORK/ftp_cert.pem"
start smtp   8025 $PY -m aiosmtpd -n -c aiosmtpd.handlers.Mailbox "$WORK/mail" -l 127.0.0.1:8025
start s3     9000 $VENV/bin/moto_server -p 9000
start webdav 8081 $VENV/bin/wsgidav --host=127.0.0.1 --port=8081 --root="$WORK/webdav" --auth=anonymous
start http   8082 $PY "$HERE/http_put_server.py" 8082 "$WORK/http"

# user-level sshd on port 2222 (key auth with a throwaway key)
if [ ! -f ssh/host_key ]; then
  ssh-keygen -q -t ed25519 -N "" -f ssh/host_key
  ssh-keygen -q -t ed25519 -N "" -f ssh/client_key
  cp ssh/client_key.pub ssh/authorized_keys
  chmod 600 ssh/authorized_keys
  # A CA and a key that is deliberately *not* in authorized_keys: only the
  # certificate can let it in, which is what the cert test proves.
  ssh-keygen -q -t ed25519 -N "" -f ssh/ssh_ca
  ssh-keygen -q -t ed25519 -N "" -f ssh/cert_key
  ssh-keygen -q -s ssh/ssh_ca -I mpt-test -n "$USER" -V -5m:+52w ssh/cert_key.pub
  SFTP=$(ls /usr/libexec/sftp-server /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server 2>/dev/null | head -1)
  cat > ssh/sshd_config <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $WORK/ssh/host_key
AuthorizedKeysFile $WORK/ssh/authorized_keys
TrustedUserCAKeys $WORK/ssh/ssh_ca.pub
PasswordAuthentication no
PubkeyAuthentication yes
PidFile $WORK/ssh/sshd.pid
Subsystem sftp $SFTP
StrictModes no
UsePAM no
CFG
fi
start sshd 2222 /usr/sbin/sshd -f "$WORK/ssh/sshd_config" -D -e

# An ssh-agent of its own holding cert_key and its certificate, for the tests
# that authenticate through an agent rather than from a key file. The socket
# lives under /tmp: a Unix socket path has to stay short.
AGENT_SOCK=$(cat agent.sock.path 2>/dev/null)
if [ -z "$AGENT_SOCK" ] || [ ! -S "$AGENT_SOCK" ]; then
  AGENT_SOCK=$(mktemp -d /tmp/mpt-agent.XXXXXX)/sock
  echo "$AGENT_SOCK" > agent.sock.path
  nohup ssh-agent -D -a "$AGENT_SOCK" > logs/ssh-agent.log 2>&1 &
  echo $! >> pids
  for _ in $(seq 1 50); do [ -S "$AGENT_SOCK" ] && break; sleep 0.1; done
  SSH_AUTH_SOCK=$AGENT_SOCK ssh-add -q ssh/cert_key 2>/dev/null
fi

sleep 2
# create the S3 bucket
curl -s -X PUT http://127.0.0.1:9000/testbucket > /dev/null

mkdir -p ssh/data ssh/scp
cat > env.sh <<ENV
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_REGION=us-east-1
# connect_retries: pyftpdlib duplicates its greeting on ~1.5 % of concurrent
# connects (see ftp_server.py), which desynchronizes that one control channel.
export MPT_IT_FTP="ftp://ftpuser:ftppass@127.0.0.1:2121/?connect_retries=1"
export MPT_IT_FTPS="ftps://ftpuser:ftppass@127.0.0.1:2122/?insecure=true&connect_retries=1"
export MPT_IT_HTTP="http://127.0.0.1:8082/"
export MPT_IT_WEBDAV="webdav://127.0.0.1:8081/"
export MPT_IT_S3="s3://testbucket/it/?endpoint=http://127.0.0.1:9000"
export MPT_IT_MAILTO="mailto:dest@example.com?from=sender@example.com"
export MPT_SMTP_URL="smtp://127.0.0.1:8025/?tls=none"
export MPT_IT_MAILDIR="$WORK/mail"
# connect_retries: under a burst of parallel tests the user-level sshd
# occasionally resets a connection before authentication; one retry absorbs it.
export MPT_IT_SFTP="sftp://$USER@127.0.0.1:2222/$WORK/ssh/data/?key=$WORK/ssh/client_key&known_hosts=off&connect_retries=1"
# A directory of its own: sftp and scp targets in one fan-out would otherwise
# write the same file (including the same .mpt-part) at the same time.
export MPT_IT_SCP="scp://$USER@127.0.0.1:2222/$WORK/ssh/scp/?key=$WORK/ssh/client_key&known_hosts=off&connect_retries=1"
# Certificate authentication: cert_key is not in authorized_keys, so this URL
# only works if the certificate is presented.
export MPT_IT_SFTP_CERT="sftp://$USER@127.0.0.1:2222/$WORK/ssh/data/?key=$WORK/ssh/cert_key&cert=$WORK/ssh/cert_key-cert.pub&known_hosts=off"
# An agent that holds cert_key together with its certificate.
export MPT_IT_SSH_AGENT="$AGENT_SOCK"
export MPT_IT_SSH_HOSTKEY="$(ssh-keygen -lf "$WORK/ssh/host_key.pub" | cut -d' ' -f2)"
ENV
echo "servers started; logs in $WORK/logs"
echo "next: source $WORK/env.sh && cargo test --test integration"
