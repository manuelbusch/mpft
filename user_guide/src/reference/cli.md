# Command line

Lookup material. `mpt --help` and `mpt <command> --help` print the same thing
from the binary you actually have, and `mpt man` produces a manual page.

```
mpt [OPTIONS] <COMMAND>
```

## Commands

| Command | What it does |
|---|---|
| `mpt cp <URL>...` | copy the first URL to the rest; with `-t`, copy every URL into the target |
| `mpt batch <FILE\|->` | run a job list from a file or standard input |
| `mpt ls <URL>` | list a directory |
| `mpt schemes` | print the supported schemes and their options |
| `mpt profiles` | list the profiles the configuration defines |
| `mpt config check` | read the configuration and print what it sets |
| `mpt credentials set\|get\|delete <ENTRY>` | manage OS key store entries (feature `keyring`) |
| `mpt serve` | take jobs over HTTP and run them (feature `server`, not in the default build) |
| `mpt relay [--listen]` | take one upload on stdin and deliver it; with `--listen`, as an SSH server (feature `relay`) |
| `mpt completions <SHELL>` | print a completion script |
| `mpt man` | print the manual page in roff |
| `mpt help [COMMAND]` | the same as `--help` |

`<SHELL>` is `bash`, `zsh`, `fish`, `elvish` or `powershell`.

### `cp`

```
mpt cp [OPTIONS] <SRC> <DST>...          # one source, one or more targets
mpt cp [OPTIONS] -t <DST> [-t <DST>] <SRC>...   # every source into the targets
```

Without `-t` the first URL is the source and the rest are its targets. With
`-t` every positional URL is a source, and the targets must be directories.

### `batch`

```
mpt batch [OPTIONS] <FILE>
mpt batch [OPTIONS] -        # read the list from standard input
```

### `serve`

```
mpt serve [OPTIONS]
```

Each flag wins over its key in [`[server]`](configuration.md#server); the
global flags set the defaults for every job the server runs. See [Jobs over
HTTP](../server/serve.md).

| Flag | Default | Meaning |
|---|---|---|
| `--bind <ADDR>` | `127.0.0.1:7788` | address to listen on; anything but loopback needs a token |
| `--token-env <VAR>` | – | environment variable holding the bearer token |
| `--journal <PATH>` | – | JSONL journal; jobs left open are run again after a restart |
| `--retention <SPAN>` | `24h` | how long finished jobs stay available; `0` keeps them until the server stops |
| `--parallel <N>` | `4` | transfers in flight at once, over all jobs |
| `--grace <SECONDS>` | `30` | how long a shutdown waits for running jobs before cancelling them |
| `--allow-any-url` | off | take any URL in a job, not only `mpt://<profile>/` ones |
| `--allow-delete` | off | let jobs set `delete_source` |
| `--max-transfers <N>` | `10000` | transfers one job may hold after patterns and trees are expanded |
| `--max-queued <N>` | `1000` | open jobs before a `POST` gets 429 |
| `--port-file <PATH>` | – | write the port actually bound, for `--bind 127.0.0.1:0` |

### `relay`

```
mpt relay                    # one upload on stdin, for use under sshd
mpt relay --listen [ADDR]    # an SSH server of its own
```

Each flag wins over its key in [`[relay]`](configuration.md#relay); the
global flags apply to every relay the process runs. The table is under
[On the relay host](../server/relay.md#on-the-relay-host).

## Flags

All flags below are **global**: they may stand before or after the subcommand,
and they are accepted by every subcommand even where they do nothing (`--hash`
on `mpt ls` is ignored). The exceptions are listed under
[Job flags](#job-flags), which belong to `cp` and `batch` and must follow the
subcommand.

### Output and diagnostics

| Flag | Default | Meaning |
|---|---|---|
| `-v`, `-vv`, `-vvv` | – | log level: info, debug, trace. `$RUST_LOG` overrides it |
| `--color <auto\|always\|never>` | `auto` | colour on stderr. `auto` means a terminal, honouring `NO_COLOR`; `always` wins over both |
| `--progress <auto\|always\|never>` | `auto` | progress line. `auto` means a terminal and no `--json` |
| `--json` | off | machine-readable report on stdout; human lines stay on stderr |
| `-h`, `--help` | – | help for the command |
| `-V`, `--version` | – | version |

### Configuration and credentials

| Flag | Meaning |
|---|---|
| `--config <PATH>` | configuration file; an error if it does not exist |
| `--password <PW>` | password for endpoints that need one. Visible in `ps`; prefer the two below |
| `--password-file <PATH>` | read the password from the first line of a file |
| `--password-stdin` | read the password from the first line of standard input |
| `--refuse-plaintext-auth` | refuse rather than warn when credentials would travel unencrypted |
| `--insecure` | **deprecated**: skip TLS verification for *every* endpoint. Use `?insecure=true` on the one URL that needs it |

### How the payload moves

| Flag | Default | Meaning |
|---|---|---|
| `--cache` | off | hold the whole payload in memory instead of streaming; never spills to disk |
| `--cache-limit <SIZE>` | `256M` | maximum payload for `--cache`; a larger one fails |
| `--retries <N>` | `0` | retry a failed transfer this often **and** set `?connect_retries=N` on every endpoint without its own. Needs `--cache`; for connect retries alone use the URL option |
| `--chunk <SIZE>` | `64K` | chunk size when streaming to several targets; values below 1024 are raised to it |
| `--queue <N>` | `16` | chunks buffered per target before the source is paused; at least 1 |
| `--timeout <SECONDS>` | `30` | inactivity limit for connections, streams and stalled targets. `0` disables it |

### What happens at the target

| Flag | Default | Meaning |
|---|---|---|
| `--no-atomic` | off | write straight to the final name instead of `<name>.mpt-part` |
| `--resume` | off | continue from an existing part file, and keep it if interrupted |
| `--skip-existing` | off | leave a target alone that has a file of the same name and size |
| `--delete-source` | off | delete the source once every target has it |

### Integrity

| Flag | Meaning |
|---|---|
| `--hash <sha256\|sha512\|blake3>` | compute a checksum while streaming and write it beside every target |
| `--check` | verify against a checksum file beside the source; fails if there is none |
| `--sign <SPEC>` | sign the checksum file. `ssh`, `ssh:<key>` or `pgp:<key.asc>`. Implies `--hash sha256` |
| `--verify-signers <FILE>` | require an OpenSSH signature from a key in this `allowed_signers`. Implies `--check` |
| `--verify-keyring <FILE>` | require an OpenPGP signature from a key in this armoured keyring. Implies `--check` |

### Job flags

These belong to `cp` and `batch` and must come **after** the subcommand.

| Flag | Default | Meaning |
|---|---|---|
| `-t`, `--target <URL>` | – | `cp` only: a target directory; every positional URL becomes a source. Repeatable |
| `-r`, `--recursive` | off | copy directories with everything below them |
| `--parallel <N>` | `4` | jobs in flight at once |
| `--fail-fast` | off | stop starting jobs after the first failure and cancel the running ones |
| `--dry-run` | off | print the jobs that would run, and run nothing |
| `--allow-empty` | off | a source pattern that matches nothing is not an error |
| `--format <lines\|jsonl\|csv>` | guessed | `batch` only: the job list format |
| `--follow` | off | `batch -` only: run each job as its line arrives |
| `--via <URL>` | `[defaults] via` | send every source once to this SSH host running `mpt relay` and let it deliver; an `ssh://` URL or a profile with one. See [Relaying through a fast host](../server/relay.md) |
| `--no-via` | off | copy from here even though `[defaults] via` or a profile names a relay |
| `--via-credentials <MODE>` | `[defaults] via_credentials`, else `header` | how the relay gets the targets' passwords: `header` (in the URLs it is sent) or `on-demand` (asked of this side at every login; the relay has to allow it) |
| `--no-via-agent` | off | do not forward an ssh-agent to the relay; SSH targets then need a password or a key on the relay |

```
mpt cp -r --parallel 8 /data/export/ sftp://srv/in/     # right
mpt -r cp /data/export/ sftp://srv/in/                  # error: unexpected argument
```

## Flags that exclude each other

| Combination | Why |
|---|---|
| `--password` with `--password-file` or `--password-stdin` | one source for the password |
| `--password-file` with `--password-stdin` | likewise |
| `--resume` with `--no-atomic` | resuming continues a part file, which `--no-atomic` never creates |
| `--password-stdin` with `batch -` | both would read standard input |
| `--retries` without `--cache` | a stream cannot be replayed |
| `--via` with `--no-via` | one decision about the relay |
| `--via` with `--check`, `--sign` or `--resume` | those need what only the client has: the checksum file, the key, the source |
| `--via` with `--delete-source` | unless the relay reads the source itself and writes every target of the job ([see the relay chapter](../server/relay.md#letting-the-relay-read-the-source)) |

The first three and `--via` with `--no-via` are rejected by the parser (`the
argument '--resume' cannot be used with '--no-atomic'`), the others by `mpt`
itself:

```
error: the job list and the password cannot both come from stdin
```

`-t` is not a conflict but a change of meaning: with it, **every** positional
URL is a source, so `mpt cp -t a/ f1 f2` copies both files into `a/` rather
than treating `f2` as a target.

The `--retries` rule is reported when the copy starts, the `--via` rules
before anything connects:

```
error: copy report.pdf: invalid option 'retries': retries need the memory cache
       (a stream cannot be replayed)
error: --check is not available with a relay: it needs what only this side has
       (the checksum file, the source, the key)
```

## Where each flag can also come from

Most flags have a `[defaults]` key of the same name and, for the per-endpoint
ones, a URL option. The precedence differs between the two groups —
see [Precedence](../configuration/file.md#precedence).

| Flag | `[defaults]` key | URL option |
|---|---|---|
| `--timeout` | `timeout` | `?timeout=` |
| `--retries` | `retries` | `?connect_retries=` |
| `--cache` | `cache` | – |
| `--cache-limit` | `cache_limit` | – |
| `--chunk` | `chunk` | – |
| `--queue` | `queue` | – |
| `--no-atomic` | `atomic` (inverted) | – |
| `--resume` | `resume` | – |
| `--skip-existing` | `skip_existing` | – |
| `--delete-source` | `delete_source` | – |
| `--hash` | `hash` | – |
| `--parallel` | `parallel` | – |
| `--via` | `via` | – |
| `--via-credentials` | `via_credentials` | – |
| `--no-via-agent` | `via_agent` (inverted) | – |
| `--json` | `json` | – |
| `--color` | `color` | – |
| `-v` | `log` | – |
| `--refuse-plaintext-auth` | `[policy] refuse_plaintext_auth` | – |
| `--insecure` | – | `?insecure=true` |
| `--sign` | `[signing] key` | – |
| `--verify-signers` | `[verify] allowed_signers` | – |
| `--verify-keyring` | `[verify] keyring` | – |
