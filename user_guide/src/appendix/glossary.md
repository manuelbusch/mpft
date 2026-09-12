# Glossary

The words this guide uses with a fixed meaning, and where each is explained.

**atomic finishing** — writing a file as `<name>.mpt-part` and renaming it to
`<name>` only when it is complete, so nothing on the far side sees a partial
file. On by default; `--no-atomic` switches it off. [A file appears only when it
is whole](../guide/reliability.md#a-file-appears-only-when-it-is-whole).

**batch** — a list of jobs run with a bounded number in flight, from `cp -t`,
`cp` with a pattern or `-r`, or `mpt batch`. [Many files](../guide/many-files.md),
[Job lists and pipelines](../guide/job-lists.md).

**checksum file** — the one-line file `<name>.sha256` (or `.sha512`, `.b3`)
written beside a target by `--hash`, in the format `sha256sum -c` reads. The
JSON report calls it the `sidecar`. [Checksums](../trust/checksums.md).

**credential reference** — `{ env = … }`, `{ file = … }`, `{ cmd = … }`,
`{ keyring = … }` or `{ vault = … }` in the configuration: where a secret comes
from, fetched when the endpoint is used. [Credentials and
secrets](../configuration/credentials.md).

**endpoint** — one side of a transfer, named by a URL: a local path, a server
directory, a bucket prefix, a list of recipients. An endpoint can receive, send,
or both. [Thinking in URLs](../getting-started/addressing.md).

**fan-out** — one source delivered to several targets in one command, the
source read once. [Several targets at once](../guide/fan-out.md).

**hop** — a target that the relay reading the source hands on to a second
relay rather than writing itself. [A target behind another relay](../server/relay-topologies.md#a-target-behind-another-relay).

**job** — one source with its targets, the unit a batch is made of; on the
command line, one `cp`. The HTTP server uses *job* for what it was submitted —
one transfer or a whole batch — and *transfer* for each source within it.
[Jobs and batches](../server/serve.md#jobs-and-batches).

**part file** — `<name>.mpt-part`, the file a transfer writes until it is
complete. Removed on failure, kept by `--resume`. [Resuming with
`--resume`](../guide/reliability.md#resuming-with---resume).

**policy** — a `[policy]` setting: a rule for every endpoint of the process
that a URL option cannot switch off. [Policies](../configuration/policies.md).

**profile** — a named endpoint in the configuration, used as `mpt://<name>/…`.
[Profiles](../configuration/profiles.md).

**relay** — `mpt relay`: a program on a well-connected host that takes a file
once over SSH and delivers it to the targets itself; also that host. The
client side is `cp --via`. [Relaying through a fast host](../server/relay.md).

**sidecar** — see *checksum file*; in the JSON report also the signature file.

**source, target** — where a transfer reads from and writes to. In job lists,
the JSON report and the API they are `src` and `dst`.

**transfer** — one source moving to its targets. The server's word for the
members of a job. [Following a job](../server/serve.md#following-a-job).

**trust file** — an OpenSSH `allowed_signers` file or an OpenPGP keyring: the
keys whose signatures are accepted by `--check`. [Trust
files](../trust/signatures.md#trust-files).

**via** — the relay an endpoint is reached through: `--via`, `[defaults] via`,
or `via` in a profile. A source with a `via` is read by that relay. [Making it
the rule](../server/relay.md#making-it-the-rule).
