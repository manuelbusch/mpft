# Configuration keys

Every section and key of the TOML file. [The configuration
file](../configuration/file.md) explains how it is found and what wins over
what; this page is the list.

`mpft config check` validates a file and prints what it sets. An unknown key is
an error, and the message names the keys that were expected.

The listing shows every key the file sets, with three exceptions to what it
prints as the value: a secret appears as `(reference)` when the file says
where to fetch it and as `*** (in the file)` when it is written out; the
password in `[mail] smtp` appears as `***`; and the profiles are listed by name
in one `[profiles]` row, since `mpft profiles` shows what they hold. `ok <path>`
at the top is what says the file was accepted.

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
| `via` | `ssh://` URL or `mpft://` profile | none | `--via`; `--no-via` switches it off for one run |
| `via_credentials` | `"header"`, `"on-demand"` | `"header"` | `--via-credentials` |
| `via_agent` | boolean | `true` | `--no-via-agent` switches the forwarding off |
| `log` | level or `RUST_LOG` syntax | `"warn"` | `-v` |
| `json` | boolean | `false` | `--json` |

`via`, `via_credentials` and `via_agent` are not read from a [file in the
working directory](../configuration/file.md#the-file-in-the-working-directory):
they decide where the targets' credentials go. `mpft serve` takes
`via_credentials` and `via_agent` for the relays its profiles name, but not
`via` (see [Jobs through a relay](../server/serve.md#jobs-through-a-relay)).

## `[policy]`

Rules for every endpoint of the process. Nothing of a run loosens them: not a
URL option or a profile's (`?known_hosts=off`, `?insecure=true`), not a flag
and not a variable. A [file in the working
directory](../configuration/file.md#the-file-in-the-working-directory) may only
make them stricter. See [Policies](../configuration/policies.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `known_hosts` | `"strict"`, `"accept-new"`, `"off"` | `strict` | default host-key policy for SSH, and the least a URL or `MPFT_SSH_KNOWN_HOSTS` may ask for |
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
| `password` | secret | SMTP password for the `smtp` server (and no other), or the access token with `auth = "xoauth2"` |
| `auth` | `"auto"`, `"xoauth2"`, `"plain"`, `"login"` | SASL mechanism |
| `from` | address | sender address |
| `max_attachment` | size | attachment limit; default 25 MiB |

## `[http]`

Defaults for `http://`, `https://` and WebDAV.

| Key | Type | Meaning |
|---|---|---|
| `token` | secret | OAuth2 bearer token, sent as `Authorization: Bearer …` to `hosts` over TLS |
| `hosts` | list of host names | the hosts `token` is for; [nothing else gets it](../protocols/http.md#authentication) |

## `[s3]`

Defaults for `s3://`.

| Key | Type | Meaning |
|---|---|---|
| `endpoint` | URL | the server, when it is not AWS |
| `region` | string | region |
| `path_style` | boolean | path-style addressing instead of virtual-host style |
| `access_key_id` | secret | access key |
| `secret_access_key` | secret | secret key |
| `profile` | string | AWS profile from `~/.aws/config` (not an `mpft://` profile); also switches the credential chain on (feature `s3-aws-auth`) |

## `[server]`

Settings for [`mpft serve`](../server/serve.md) (feature `server`). Each flag
of `mpft serve` wins over its key here.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `bind` | `host:port` | `"127.0.0.1:7788"` | address to listen on; anything but loopback needs a token |
| `token` | secret | none | the bearer token every request must carry |
| `journal` | path | none | JSONL file of submitted jobs; those left open are run again after a restart |
| `retention` | duration | `"24h"` | how long finished jobs stay available; `"0"` keeps them until the server stops |
| `parallel` | integer, at least 1 | `4` | transfers in flight at a time, over all jobs |
| `grace` | duration | `"30s"` | how long a shutdown waits for running jobs before cancelling them |
| `max_body` | size | `"8M"` | largest request body |
| `urls` | `"profiles"`, `"any"` | `profiles` | which URLs a job may name |
| `profiles` | string or list | all | with `urls = "profiles"`: only these |
| `allow_delete` | boolean | `false` | let jobs set `delete_source` |
| `max_transfers` | integer, at least 1 | `10000` | transfers one job may hold after patterns and trees are expanded |
| `max_queued` | integer, at least 1 | `1000` | open jobs before a `POST` is refused with 429 |

## `[relay]`

Settings for [`mpft relay --listen`](../server/relay-host.md#on-the-relay-host)
(feature `relay`). Each flag of `mpft relay` wins over its key here.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `host_key` | path | [by system](../server/relay-host.md#where-the-host-key-is-kept) | the server's host key; generated when the file is missing |
| `authorized_keys` | path | `~/.config/mpft/authorized_keys` | who may relay, in OpenSSH format |
| `parallel` | integer, at least 1 | `4` | relays running concurrently; further sessions wait |
| `grace` | duration | `"30s"` | how long a shutdown waits for running relays |
| `max_size` | size | `"0"` (no limit) | refuse larger uploads and sources |
| `max_entries` | integer | `100000` | refuse to list a directory with more entries; `0` for no limit |
| `credentials` | `"header"`, `"on-demand"`, `"any"` | `"header"` | which way a client may send the targets' passwords |
| `agent_forwarding` | boolean | `true` | take the ssh-agent a client forwards |
| `allow_delete` | boolean | `false` | let a client have the source deleted that the relay read for it; never a file on the relay host |
| `own_keys` | boolean | `false` | log in to the SSH hosts a client names with the relay's own identity too (its agent, `~/.ssh/id_*`, `[ssh] key`); see [Trust](../server/relay-host.md#trust) |
| `local_files` | boolean | `false` | let a client name files on the relay host; off, only the relay's own profiles reach its disk |

## `[profiles.<name>]`

A profile: a named endpoint addressed as `mpft://<name>/<path>`. See [Named
targets](../configuration/profiles.md).

| Key | Type | Meaning |
|---|---|---|
| `url` | URL | **required**: what the name stands for |
| `password` | secret | password for this endpoint |
| `sign` | string | sign transfers to this target, in `--sign` syntax |
| `via` | `ssh://` URL or `mpft://` profile | the relay this endpoint is reached through; as a source, and in `ls`, the relay reads it |
| `hash` | string | checksum algorithm for this target |
| `atomic` | boolean | finish through a part file; `false` switches it off |
| *anything else* | string or list | becomes a URL option on the profile's URL |

The last row is what lets a profile carry `key`, `hostkey`, `timeout`,
`endpoint`, `subject` and any other option its scheme understands. A key that
`mpft` does not know is not an error here — it becomes an option the protocol
may ignore.

## Secrets

Every key marked *secret* takes either a string, which warns, or one of these
references, which is resolved when the endpoint is used. See [Credentials and
secrets](../configuration/credentials.md).

```toml
password = { env = "PROD_PW" }                            # environment variable
password = { file = "~/.config/mpft/prod.pw" }             # first line of a file
password = { cmd = "op read op://Infra/prod/password" }   # stdout of a command
password = { keyring = "mpft/prod" }                       # OS key store (feature "keyring")
password = { vault = "secret/data/mpft/prod#password" }    # HashiCorp Vault (feature "vault")
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
allowed_signers = "~/.config/mpft/allowed_signers"

[ssh]
user             = "deploy"
key              = "~/.ssh/id_ed25519"
known_hosts_file = "~/.ssh/known_hosts"

[mail]
smtp     = "smtp://reports@example.com@smtp.example.com:587?tls=starttls"
password = { keyring = "mpft/smtp" }
from     = "reports@example.com"

[s3]
endpoint   = "https://minio.example.com"
region     = "eu-central-1"
path_style = true

[http]
token = { cmd = "az account get-access-token --query accessToken -o tsv" }
hosts = ["graph.microsoft.com"]

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
