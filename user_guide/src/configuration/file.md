# The configuration file

Everything that is not a source or a target can live in a TOML file: timeouts,
checksum defaults, SSH keys, SMTP servers, security policies, and names for the
endpoints you use every day. The file stops settings from being retyped, and it
lets a machine carry a decision that every run on it should follow.

Nothing is required. `mpt` runs with no configuration at all.

## Where it is read from

The first of these that exists is the user file:

1. `--config <path>`, an error if it does not exist
2. `$MPT_CONFIG`, likewise
3. `$XDG_CONFIG_HOME/mpt/config.toml`, else `~/.config/mpt/config.toml`

Name the file explicitly in a service unit or a CI job, where the home
directory may not be what you expect:

```
mpt --config /etc/mpt/config.toml cp …
MPT_CONFIG=/etc/mpt/config.toml mpt cp …
```

In addition, **`./mpt.toml` in the working directory** is read on top of the
user file, so a project can carry its own timeouts or a stricter policy. What
it may contribute is limited; see
[below](#the-file-in-the-working-directory).

## What it looks like

```toml
[defaults]                    # values for the flags of the same name
timeout      = 60             # seconds of inactivity, 0 disables it
retries      = 2
parallel     = 8              # jobs in parallel for cp -t and batch
hash         = "sha256"
cache        = false
cache_limit  = "256M"
chunk        = "64K"
queue        = 16
atomic       = true           # finish through <name>.mpt-part
resume       = false
skip_existing = false
delete_source = false
color        = "auto"         # auto | always | never
log          = "warn"         # a level, or RUST_LOG syntax
json         = false

[policy]                      # see "Policies"
known_hosts           = "strict"
refuse_plaintext_auth = true

[ssh]                         # defaults for sftp:// and scp://
user             = "deploy"
key              = "~/.ssh/id_ed25519"
known_hosts_file = "~/.ssh/known_hosts"

[mail]                        # defaults for mailto: and smtp://
smtp = "smtp://reports@example.com@smtp.example.com:587?tls=starttls"
from = "reports@example.com"

[s3]                          # defaults for s3://
endpoint   = "https://minio.example.com"
region     = "eu-central-1"
path_style = true

[http]                        # defaults for http(s):// and WebDAV
# token = { cmd = "…" }       # see "Credentials and secrets"

[profiles.prod]               # see "Profiles"
url = "sftp://deploy@srv.example.com/data/"
```

`[signing]` and `[verify]` round out the list and belong to
[Signatures](../trust/signatures.md). Every section is optional, and so is
every key in it.

## Validating with `mpt config check`

`mpt config check` reads the configuration as a real run would, and prints
which files were used and what they set:

```
$ mpt config check
ok /home/deploy/.config/mpt/config.toml
[defaults] hash                 sha256
[defaults] timeout              60
[defaults] parallel             8
[policy] known_hosts            strict
[policy] refuse_plaintext_auth  true
[ssh] user                      deploy
[ssh] key                       ~/.ssh/id_ed25519
```

A misspelled key is an error, not a setting that quietly does nothing, and the
message lists what was expected:

```
$ mpt config check
error: configuration: config.toml: unknown field `timeuot`, expected one of `color`, `hash`,
       `cache`, `cache_limit`, `retries`, `chunk`, `queue`, `timeout`, `atomic`, `resume`,
       `skip_existing`, `delete_source`, `log`, `json`, `parallel`
in `defaults`
```

So does a value of the wrong shape:

```
error: configuration: config.toml: invalid type: string "soon", expected u64
in `defaults.timeout`
```

Both exit with code 2. Run `mpt config check` after every edit; it is the
only place these mistakes are reported before a real transfer needs them.

Profiles are listed by [`mpt profiles`](profiles.md), not by `config check`,
and a handful of keys are applied without being listed; see the
[reference](../reference/configuration.md). The `ok <path>` line says that
the file was read and accepted.

## Precedence

Two kinds of setting follow two different rules.

**Run-wide settings** (`cache`, `retries`, `chunk`, `queue`, `parallel`,
`hash`, `json`, `color`, `log`, `atomic`, `resume`) follow the usual rule:

```
command-line flag  >  [defaults]  >  built-in
```

```
$ mpt cp --hash sha256 f.txt mpt://loc/     # the flag wins over a profile's hash = "blake3"
sha256  98ea…
```

**Per-endpoint options** (`timeout`, `key`, `known_hosts`, `hostkey`,
`insecure`, `connect_retries` and everything else that can appear in a URL)
follow the opposite principle: the more specific the place it was written, the
more it counts.

```
URL option  >  profile  >  command-line flag  >  [defaults]  >  built-in
```

```
$ mpt --timeout 7 cp f.txt "ftp://srv/in/?timeout=5"      # → timeout=5
$ mpt --timeout 7 ls mpt://prod/                          # → timeout=120, from the profile
$ mpt ls "mpt://prod/?timeout=5"                          # → timeout=5, the reference wins
```

`--timeout 120` means "be patient with everything in this run"; `?timeout=5`
on one URL means "this endpoint in particular", and a narrower statement is
not overruled by a broader one. The [echoed
target](../getting-started/addressing.md#the-result-line-echoes-the-options-used)
in the result line always shows what was used.

Environment variables slot in between a URL option and the configuration
file: a URL option wins over a variable, and a variable wins over the
configuration key it corresponds to. `MPT_SSH_KEY` therefore overrides
`[ssh] key`, and `MPT_SSH_USER` overrides `[ssh] user`, but `?key=` in the URL
overrides both. `MPT_PASSWORD`, `MPT_SMTP_URL` and the AWS variables are the
other common ones; the [reference](../reference/environment.md) has them all.

## Value formats

- **Sizes** take a unit: `64K`, `256M`, `2G`. Plain numbers are bytes.
- **Durations** take one too: `30m`, `24h`, `7d`. `0` means "no limit".
- **Paths** may start with `~/`, which is expanded against the home directory.
- **Any string may contain `${VAR}`**, replaced by that environment variable:

  ```toml
  [ssh]
  key = "${SECRETS_DIR}/id_ed25519"
  ```

  A variable that is not set is an error rather than an empty string:

  ```
  error: configuration: config.toml: '${SECRETS_DIR}/id_ed25519' refers to ${SECRETS_DIR}, which is not set
  ```

  Interpolation happens after the file is parsed, on values only, so a variable
  can never introduce new keys or change the structure of the file.

## The file in the working directory

`./mpt.toml` is read in addition to the user file and overrides it, but only
for `[defaults]` and `[policy]`. A directory you happen to be standing in may
tune how a transfer runs; it must not be able to say *where* a transfer goes or
which key signs it.

```
$ mpt config check
WARN mpt: mpt.toml: ignoring [ssh] — a configuration file in the working directory
     only contributes [defaults] and [policy]
ok /home/deploy/.config/mpt/config.toml
ok mpt.toml
```

The two sections are an allow-list, so a section added to `mpt` later is
dropped here as well. A `[profiles.…]` block in `./mpt.toml` therefore cannot
redirect `mpt://prod/` to somewhere else, and a `password = { cmd = … }` inside
one never runs.

Three keys of `[defaults]` are dropped too: `via`, which names the
[relay](../server/relay.md) that receives every target's credentials, and
`via_credentials` and `via_agent`, which decide how much of them it gets. All
three say as much about where credentials go as a profile does.

```
warning mpt.toml: ignoring [defaults] via — a configuration file in the working
        directory may not choose the relay that receives the targets' credentials
```

Keep credentials out of `./mpt.toml` in any case; a file in a repository is a
file that gets committed.

## Permissions

A configuration file that holds credentials, or that points at a command which
produces them, gives them away if others can read it:

```
WARN mpt: config.toml holds credentials and is readable by others (mode 644); chmod 600 it
```

`[policy] strict_permissions = true` turns that into a refusal:

```
error: configuration: config.toml holds credentials and is readable by others (mode 644); chmod 600 it
```

The check applies only when the file actually mentions a secret, so a file with
nothing but timeouts in it is never complained about. On Windows there are no
mode bits, and the file's location is judged instead; see the
[Windows appendix](../appendix/windows.md).
