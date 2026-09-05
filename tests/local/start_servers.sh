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
  SFTP=$(ls /usr/libexec/sftp-server /usr/lib/openssh/sftp-server /usr/lib/ssh/sftp-server 2>/dev/null | head -1)
  cat > ssh/sshd_config <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $WORK/ssh/host_key
AuthorizedKeysFile $WORK/ssh/authorized_keys
PasswordAuthentication no
PubkeyAuthentication yes
PidFile $WORK/ssh/sshd.pid
Subsystem sftp $SFTP
StrictModes no
UsePAM no
CFG
fi
start sshd 2222 /usr/sbin/sshd -f "$WORK/ssh/sshd_config" -D -e

sleep 2
# create the S3 bucket
curl -s -X PUT http://127.0.0.1:9000/testbucket > /dev/null

mkdir -p ssh/data
cat > env.sh <<ENV
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_REGION=us-east-1
export MPT_IT_FTP="ftp://ftpuser:ftppass@127.0.0.1:2121/"
export MPT_IT_FTPS="ftps://ftpuser:ftppass@127.0.0.1:2122/?insecure=true"
export MPT_IT_HTTP="http://127.0.0.1:8082/"
export MPT_IT_WEBDAV="webdav://127.0.0.1:8081/"
export MPT_IT_S3="s3://testbucket/it/?endpoint=http://127.0.0.1:9000"
export MPT_IT_MAILTO="mailto:dest@example.com?from=sender@example.com"
export MPT_SMTP_URL="smtp://127.0.0.1:8025/?tls=none"
export MPT_IT_MAILDIR="$WORK/mail"
export MPT_IT_SFTP="sftp://$USER@127.0.0.1:2222/$WORK/ssh/data/?key=$WORK/ssh/client_key&known_hosts=off"
export MPT_IT_SCP="scp://$USER@127.0.0.1:2222/$WORK/ssh/data/?key=$WORK/ssh/client_key&known_hosts=off"
ENV
echo "servers started; logs in $WORK/logs"
echo "next: source $WORK/env.sh && cargo test --test integration"
