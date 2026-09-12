# Configuration keys

Every section and key of the TOML file. [The configuration
file](../configuration/file.md) explains how it is found and what wins over
what; this page is the list.

`mpt config check` validates a file and prints what it sets. An unknown key is
an error, and the message names the keys that were expected.

The listing it prints is a summary rather than a dump: a handful of keys —
`[policy] strict_permissions` and `max_signature_age`, `[ssh] cert` and
`hostkey`, `[mail] auth` and `max_attachment`, `[s3] profile` — are read and
applied but not shown, and a secret appears as `(reference)` rather than as its
value. A key missing from the listing has not been ignored; `ok <path>` at the
top is what says the file was accepted.

## `[defaults]`

Values for the flags of the same name. A flag on the command line wins.

| Key | Type | Default | Flag |
|---|---|---|---|
| `color` | `"auto"`, `"always"`, `"never"` | `auto` | `--color` |
| `hash` | `"sha256"`, `"sha512"`, `"blake3"` | none | `--hash` |
| `cache` | boolean | `false` | `--cache` |
| `cache_limit` | size | `"256M"` | `--cache-limit` |
| `retries` | integer | `0` | `--retries` |
| `chunk` | size | `"64K"` | `--chunk` |
| `queue` | integer | `16` | `--queue` |
| `timeout` | integer, seconds | `30` | `--timeout` |
| `atomic` | boolean | `true` | `--no-atomic` inverts it |
| `resume` | boolean | `false` | `--resume` |
| `skip_existing` | boolean | `false` | `--skip-existing` |
| `delete_source` | boolean | `false` | `--delete-source` |
| `parallel` | integer, at least 1 | `4` | `--parallel` |
| `log` | level or `RUST_LOG` syntax | `"warn"` | `-v` |
| `json` | boolean | `false` | `--json` |

## `[policy]`

Rules for every endpoint of the process. A URL option cannot switch these off.
See [Policies](../configuration/policies.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `known_hosts` | `"strict"`, `"accept-new"`, `"off"` | `strict` | default host-key policy for SSH |
| `refuse_plaintext_auth` | boolean | `false` | refuse rather than warn about unencrypted credentials |
| `refuse_insecure_tls` | boolean | `false` | refuse `?insecure=true` |
| `require_signature` | boolean | `false` | `--check` must verify a signature as well |
| `strict_permissions` | boolean | `false` | a readable file with credentials is an error, not a warning |
| `max_signature_age` | duration | `"0"` | refuse signatures older than this; `0` means no limit |

## `[signing]`

Defaults for `--sign`.

| Key | Type | Meaning |
|---|---|---|
| `key` | string | signing key in `--sign` syntax: `ssh`, `ssh:<file>`, `pgp:<file>` |
| `agent_fingerprint` | `"SHA256:…"` | which ssh-agent identity to sign with |
| `passphrase` | secret | passphrase of the signing key |

## `[verify]`

Trusted keys for `--check`, used when no `--verify-*` flag is given.

| Key | Type | Meaning |
|---|---|---|
| `allowed_signers` | path | OpenSSH `allowed_signers` file |
| `keyring` | path | armoured OpenPGP public keyring |

## `[ssh]`

Defaults for `sftp://` and `scp://`.

| Key | Type | Meaning |
|---|---|---|
| `user` | string | login name when the URL has none |
| `key` | path | private key file |
| `cert` | path | OpenSSH certificate for that key |
| `passphrase` | secret | passphrase of the private key |
| `known_hosts_file` | path | which file to check against |
| `hostkey` | string or list of strings | pinned host-key fingerprints |

## `[mail]`

Defaults for `mailto:` and `smtp://`.

| Key | Type | Meaning |
|---|---|---|
| `smtp` | `smtp://` URL | the server `mailto:` targets use |
| `password` | secret | SMTP password, or the access token with `auth = "xoauth2"` |
| `auth` | `"auto"`, `"xoauth2"`, `"plain"`, `"login"` | SASL mechanism |
| `from` | address | sender address |
| `max_attachment` | size | attachment limit; default 25 MiB |

## `[http]`

Defaults for `http://`, `https://` and WebDAV.

| Key | Type | Meaning |
|---|---|---|
| `token` | secret | OAuth2 bearer token, sent as `Authorization: Bearer …` |

## `[s3]`

Defaults for `s3://`.

| Key | Type | Meaning |
|---|---|---|
| `endpoint` | URL | the server, when it is not AWS |
| `region` | string | region |
| `path_style` | boolean | path-style addressing instead of virtual-host style |
| `access_key_id` | secret | access key |
| `secret_access_key` | secret | secret key |
| `profile` | string | AWS profile from `~/.aws/config` (not an `mpt://` profile); also switches the credential chain on (feature `s3-aws-auth`) |

## `[profiles.<name>]`

A profile: a named endpoint addressed as `mpt://<name>/<path>`. See [Named
targets](../configuration/profiles.md).

| Key | Type | Meaning |
|---|---|---|
| `url` | URL | **required**: what the name stands for |
| `password` | secret | password for this endpoint |
| `sign` | string | sign transfers to this target, in `--sign` syntax |
| `hash` | string | checksum algorithm for this target |
| `atomic` | boolean | finish through a part file; `false` switches it off |
| *anything else* | string or list | becomes a URL option on the profile's URL |

The last row is what lets a profile carry `key`, `hostkey`, `timeout`,
`endpoint`, `subject` and any other option its scheme understands. A key that
`mpt` does not know is not an error here — it becomes an option the protocol
may ignore.

## Secrets

Every key marked *secret* takes either a string, which warns, or one of these
references, which is resolved when the endpoint is used. See [Credentials and
secrets](../configuration/credentials.md).

```toml
password = { env = "PROD_PW" }                            # environment variable
password = { file = "~/.config/mpt/prod.pw" }             # first line of a file
password = { cmd = "op read op://Infra/prod/password" }   # stdout of a command
password = { keyring = "mpt/prod" }                       # OS key store (feature "keyring")
password = { vault = "secret/data/mpt/prod#password" }    # HashiCorp Vault (feature "vault")
```

## Value formats

| Kind | Syntax | Examples |
|---|---|---|
| size | number with an optional binary unit | `1024`, `"64K"`, `"256M"`, `"2G"` |
| duration | number with a unit | `"30m"`, `"24h"`, `"7d"`, `"0"` for none |
| path | may start with `~/` | `"~/.ssh/id_ed25519"` |
| any string | may contain `${VAR}` | `"${SECRETS_DIR}/key"` |

`${VAR}` is replaced after the file is parsed, so it can only change values,
never keys or structure, and an unset variable is an error; see [Value
formats](../configuration/file.md#value-formats).

## A complete example

```toml
[defaults]
timeout       = 60
retries       = 2
parallel      = 8
hash          = "sha256"
skip_existing = true

[policy]
known_hosts           = "strict"
refuse_plaintext_auth = true
refuse_insecure_tls   = true
require_signature     = true
strict_permissions    = true
max_signature_age     = "7d"

[signing]
key = "ssh:~/.ssh/release_ed25519"

[verify]
allowed_signers = "~/.config/mpt/allowed_signers"

[ssh]
user             = "deploy"
key              = "~/.ssh/id_ed25519"
known_hosts_file = "~/.ssh/known_hosts"

[mail]
smtp     = "smtp://reports@example.com@smtp.example.com:587?tls=starttls"
password = { keyring = "mpt/smtp" }
from     = "reports@example.com"

[s3]
endpoint   = "https://minio.example.com"
region     = "eu-central-1"
path_style = true

[http]
token = { cmd = "az account get-access-token --query accessToken -o tsv" }

[profiles.prod]
url     = "sftp://deploy@srv.example.com/data/"
key     = "~/.ssh/prod_ed25519"
hostkey = "SHA256:f29GJDwDP5hekqa22VhNdaNPBM+q6AzG3FvQaBCJnmg"
timeout = 120
sign    = "ssh:~/.ssh/prod_ed25519"

[profiles.archive]
url        = "s3://archive-bucket/reports/"
path_style = true

[profiles.boss]
url     = "mailto:boss@example.com"
subject = "Report"
```
