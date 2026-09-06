#!/usr/bin/env bash
# Builds mpt with the server feature, starts it on a free port with three
# profiles on temporary directories, fills the inbox and runs the client
# against it. Everything temporary is removed at the end.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mb=${DEMO_MB:-32}   # the smallest file; the others are two and three times it

echo "== building mpt --features server"
cargo build --release --features server --manifest-path "$root/Cargo.toml" --quiet
mpt="$root/target/release/mpt"

work=$(mktemp -d)
cleanup() {
    if [ -n "${pid:-}" ]; then
        kill -INT "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

mkdir -p "$work/inbox" "$work/outbox" "$work/archive"
echo "== filling $work/inbox"
for n in 1 2 3; do
    head -c $((n * mb * 1024 * 1024)) /dev/urandom > "$work/inbox/file$n.bin"
done

# Three profiles on local directories: a job may only name these.
cat > "$work/mpt.toml" <<TOML
[server]
token = { env = "MPT_API_TOKEN" }

[profiles.inbox]
url = "$work/inbox/"

[profiles.outbox]
url = "$work/outbox/"

[profiles.archive]
url = "$work/archive/"
TOML
chmod 600 "$work/mpt.toml"

MPT_API_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
export MPT_API_TOKEN
echo "== starting mpt serve"
"$mpt" --config "$work/mpt.toml" serve --bind 127.0.0.1:0 --port-file "$work/port" \
    2> "$work/server.log" &
pid=$!
for _ in $(seq 1 100); do
    [ -s "$work/port" ] && break
    sleep 0.1
done
[ -s "$work/port" ] || { echo "the server did not start:"; cat "$work/server.log"; exit 1; }
MPT_API_URL="http://127.0.0.1:$(cat "$work/port")"
export MPT_API_URL
echo "   $MPT_API_URL"

cd "$here"
run() { echo; echo "\$ mpt-client $*"; uv run --quiet mpt-client "$@"; }

run health
# One file to two targets, with a checksum file next to each copy.
run submit --follow --hash blake3 mpt://inbox/file1.bin mpt://outbox/ mpt://archive/
# A batch: a pattern and a job with two targets, two transfers at a time.
run batch --follow --parallel 2 jobs.example.json
# The copy in the outbox came with a .b3 file: verify it on the way back.
run submit --follow --check mpt://outbox/file2.bin mpt://archive/
# A profile the server does not know is refused with 400 (exit status 3).
run submit mpt://nowhere/file1.bin mpt://outbox/ || true
run list
echo
echo "== outbox now holds:"
ls -l "$work/outbox"
