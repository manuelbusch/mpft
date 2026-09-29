#!/usr/bin/env bash
# Start local test servers (no Docker needed) and print the MPFT_IT_* variables
# for `cargo test --test integration`. Requires a Python venv with:
#   pip install pyftpdlib pyopenssl aiosmtpd "moto[server]" wsgidav cheroot
# Usage: bash tests/local/start_servers.sh <venv-dir> <work-dir>
#        source <work-dir>/env.sh && cargo test --test integration
# Stop:  bash tests/local/stop_servers.sh <work-dir>
# The ports can be moved, to run a second set beside the first with a work
# dir of its own: MPFT_IT_PORT_FTP (2121), MPFT_IT_PORT_FTPS (2122),
# MPFT_IT_PORT_SMTP (8025), MPFT_IT_PORT_S3 (9000), MPFT_IT_PORT_WEBDAV (8081),
# MPFT_IT_PORT_HTTP (8082), MPFT_IT_PORT_SSH (2222).
set -u
FTP_PORT=${MPFT_IT_PORT_FTP:-2121}; FTPS_PORT=${MPFT_IT_PORT_FTPS:-2122}
SMTP_PORT=${MPFT_IT_PORT_SMTP:-8025}; S3_PORT=${MPFT_IT_PORT_S3:-9000}
WEBDAV_PORT=${MPFT_IT_PORT_WEBDAV:-8081}; HTTP_PORT=${MPFT_IT_PORT_HTTP:-8082}
SSH_PORT=${MPFT_IT_PORT_SSH:-2222}
VENV=$(cd "${1:?venv dir}" && pwd); mkdir -p "${2:?work dir}"; WORK=$(cd "$2" && pwd); PY=$VENV/bin/python
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$WORK"/{ftp,http,webdav,mail/tmp,mail/new,mail/cur,ssh,logs}
cd "$WORK"

# self-signed cert for FTPS
if [ ! -f cert.pem ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj "/CN=localhost" 2>/dev/null
  cat key.pem cert.pem > ftp_cert.pem
fi

# `pids` keeps what an earlier run started and is still running: a server
# that is skipped below as "already in use" may be one of those, and
# stop_servers.sh has to find it.
touch pids
for p in $(cat pids); do kill -0 "$p" 2>/dev/null && echo "$p"; done > pids.alive
mv pids.alive pids

start() { # name, port, command...
  local name=$1 port=$2; shift 2
  if nc -z -w1 127.0.0.1 "$port" 2>/dev/null; then echo "$name: port $port already in use, skipping"; return; fi
  nohup "$@" > "logs/$name.log" 2>&1 &
  echo $! >> pids
}
start ftp    $FTP_PORT $PY "$HERE/ftp_server.py" $FTP_PORT $FTPS_PORT "$WORK/ftp" "$WORK/ftp_cert.pem"
start smtp   $SMTP_PORT $PY -m aiosmtpd -n -c aiosmtpd.handlers.Mailbox "$WORK/mail" -l 127.0.0.1:$SMTP_PORT
start s3     $S3_PORT $VENV/bin/moto_server -p $S3_PORT
start webdav $WEBDAV_PORT $VENV/bin/wsgidav --host=127.0.0.1 --port=$WEBDAV_PORT --root="$WORK/webdav" --auth=anonymous
start http   $HTTP_PORT $PY "$HERE/http_put_server.py" $HTTP_PORT "$WORK/http"

# user-level sshd (key auth with a throwaway key); the port is given on its
# command line, which overrides the one in the file
if [ ! -f ssh/host_key ]; then
  ssh-keygen -q -t ed25519 -N "" -f ssh/host_key
  ssh-keygen -q -t ed25519 -N "" -f ssh/client_key
  cp ssh/client_key.pub ssh/authorized_keys
  chmod 600 ssh/authorized_keys
  # A CA and a key that is deliberately *not* in authorized_keys: only the
  # certificate can let it in, which is what the cert test proves.
  ssh-keygen -q -t ed25519 -N "" -f ssh/ssh_ca
  ssh-keygen -q -t ed25519 -N "" -f ssh/cert_key
  ssh-keygen -q -s ssh/ssh_ca -I mpft-test -n "$USER" -V -5m:+52w ssh/cert_key.pub
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
start sshd $SSH_PORT /usr/sbin/sshd -f "$WORK/ssh/sshd_config" -p $SSH_PORT -D -e

# An ssh-agent of its own holding cert_key and its certificate, for the tests
# that authenticate through an agent rather than from a key file. The socket
# lives under /tmp: a Unix socket path has to stay short. An agent from an
# earlier run is used again; its process id stays in agent.pid, so that
# stop_servers.sh can stop it.
AGENT_SOCK=$(cat agent.sock.path 2>/dev/null)
if [ -z "$AGENT_SOCK" ] || [ ! -S "$AGENT_SOCK" ]; then
  AGENT_SOCK=$(mktemp -d /tmp/mpft-agent.XXXXXX)/sock
  echo "$AGENT_SOCK" > agent.sock.path
  nohup ssh-agent -D -a "$AGENT_SOCK" > logs/ssh-agent.log 2>&1 &
  echo $! > agent.pid
  for _ in $(seq 1 50); do [ -S "$AGENT_SOCK" ] && break; sleep 0.1; done
  SSH_AUTH_SOCK=$AGENT_SOCK ssh-add -q ssh/cert_key 2>/dev/null
fi

# Wait until every server answers (up to 30s each): moto in particular takes
# a few seconds to start, longer on a busy CI runner.
for port in $FTP_PORT $FTPS_PORT $SMTP_PORT $S3_PORT $WEBDAV_PORT $HTTP_PORT $SSH_PORT; do
  for _ in $(seq 1 300); do nc -z -w1 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.1; done
  nc -z -w1 127.0.0.1 "$port" 2>/dev/null || echo "port $port: no server answers; see $WORK/logs"
done
# create the S3 bucket
curl -s -X PUT http://127.0.0.1:$S3_PORT/testbucket > /dev/null

mkdir -p ssh/data ssh/scp
cat > env.sh <<ENV
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_REGION=us-east-1
# connect_retries: pyftpdlib duplicates its greeting on ~1.5 % of concurrent
# connects (see ftp_server.py), which desynchronizes that one control channel.
export MPFT_IT_FTP="ftp://ftpuser:ftppass@127.0.0.1:$FTP_PORT/?connect_retries=1"
export MPFT_IT_FTPS="ftps://ftpuser:ftppass@127.0.0.1:$FTPS_PORT/?insecure=true&connect_retries=1"
export MPFT_IT_HTTP="http://127.0.0.1:$HTTP_PORT/"
export MPFT_IT_WEBDAV="webdav://127.0.0.1:$WEBDAV_PORT/"
export MPFT_IT_S3="s3://testbucket/it/?endpoint=http://127.0.0.1:$S3_PORT"
export MPFT_IT_MAILTO="mailto:dest@example.com?from=sender@example.com"
export MPFT_SMTP_URL="smtp://127.0.0.1:$SMTP_PORT/?tls=none"
export MPFT_IT_MAILDIR="$WORK/mail"
# connect_retries: under a burst of parallel tests the user-level sshd
# occasionally resets a connection before authentication; one retry absorbs it.
export MPFT_IT_SFTP="sftp://$USER@127.0.0.1:$SSH_PORT/$WORK/ssh/data/?key=$WORK/ssh/client_key&known_hosts=off&connect_retries=1"
# A directory of its own: sftp and scp targets in one fan-out would otherwise
# write the same file (including the same .mpft-part) at the same time.
export MPFT_IT_SCP="scp://$USER@127.0.0.1:$SSH_PORT/$WORK/ssh/scp/?key=$WORK/ssh/client_key&known_hosts=off&connect_retries=1"
# Certificate authentication: cert_key is not in authorized_keys, so this URL
# only works if the certificate is presented.
export MPFT_IT_SFTP_CERT="sftp://$USER@127.0.0.1:$SSH_PORT/$WORK/ssh/data/?key=$WORK/ssh/cert_key&cert=$WORK/ssh/cert_key-cert.pub&known_hosts=off"
# An agent that holds cert_key together with its certificate.
export MPFT_IT_SSH_AGENT="$AGENT_SOCK"
export MPFT_IT_SSH_HOSTKEY="$(ssh-keygen -lf "$WORK/ssh/host_key.pub" | cut -d' ' -f2)"
ENV
echo "servers started; logs in $WORK/logs"
echo "next: source $WORK/env.sh && cargo test --test integration"
