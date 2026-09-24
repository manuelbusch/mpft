# Environment variables

Every variable `mpt` reads. A URL option always wins over a variable, and a
variable wins over the configuration file — except where noted.

## Credentials

| Variable | Meaning |
|---|---|
| `MPT_PASSWORD` | password for `sftp`, `scp`, `ftp`, `ftps`, `http(s)`, `webdav(s)` when the URL has none; never for `s3`, `ssh` or mail |
| `MPT_SMTP_PASSWORD` | password for `mailto:`, `smtp://` and `smtps://` |
| `MPT_REFUSE_PLAINTEXT_AUTH` | `1` makes unencrypted credentials an error instead of a warning |

`--password`, `--password-file` and `--password-stdin` override
`MPT_PASSWORD`. A password already in the URL is never replaced. A relay
applies none of these to the URLs its clients name, only to its own
profiles; see [Trust](../server/relay-host.md#trust).

## SSH

| Variable | Meaning |
|---|---|
| `MPT_SSH_USER` | login name when the URL has none; then `[ssh] user`, then `$USER` |
| `MPT_SSH_KEY` | private key file. Naming a key means the agent and the default keys are not tried |
| `MPT_SSH_KEY_PASSPHRASE` | passphrase for it |
| `MPT_SSH_CERT` | OpenSSH certificate for that key; `<key>-cert.pub` is found without it |
| `MPT_SSH_KNOWN_HOSTS` | host-key policy: `strict` (the default), `accept-new`, `off` |
| `MPT_SSH_HOSTKEY` | pinned fingerprints, comma-separated |
| `SSH_AUTH_SOCK` | ssh-agent socket; on Windows a named-pipe path |
| `USER` | the fallback login name |

## Signing

| Variable | Meaning |
|---|---|
| `MPT_SIGN_KEY_PASSPHRASE` | passphrase of the signing key |
| `MPT_SIGN_KEY_FINGERPRINT` | which ssh-agent identity to sign with (`SHA256:…`) |

## Mail

| Variable | Meaning |
|---|---|
| `MPT_SMTP_URL` | the SMTP server `mailto:` targets use, e.g. `smtp://user@mail.example.com:587?tls=starttls` |
| `MPT_MAIL_FROM` | sender address; after `?from=` and before `[mail] from` |
| `MPT_MAIL_MAX_ATTACHMENT` | attachment limit **in bytes** (the configuration key takes a unit) |

## S3

The standard AWS names are used, so an environment that already works with the
AWS tools works here.

| Variable | Meaning |
|---|---|
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | access key and secret |
| `AWS_SESSION_TOKEN` | session token for temporary credentials |
| `AWS_REGION`, `AWS_DEFAULT_REGION` | region |
| `AWS_ENDPOINT_URL` | the server, when it is not AWS |
| `AWS_PROFILE` | AWS profile from `~/.aws/config` (not an `mpt://` profile); also switches the credential chain on (feature `s3-aws-auth`) |

`user:pass@` in the URL and `[s3] access_key_id` override the key pair.

## HashiCorp Vault

Read by `{ vault = "…" }` references (feature `vault`).

| Variable | Meaning |
|---|---|
| `VAULT_ADDR` | the server |
| `VAULT_TOKEN` | the token to read with |

## General

| Variable | Meaning |
|---|---|
| `MPT_CONFIG` | configuration file; an error if it does not exist |
| `XDG_CONFIG_HOME` | where `mpt/config.toml` is looked for, if `--config` and `MPT_CONFIG` are unset |
| `RUST_LOG` | log filter. **Overrides `-v` and `[defaults] log`** |
| `NO_COLOR` | any value switches colour off under `--color auto`; `--color always` still wins |

## Settings that are not environment variables

Three settings people look for here and will not find:

- **The known-hosts file** is `[ssh] known_hosts_file`, not an environment
  variable. `MPT_SSH_KNOWN_HOSTS` sets the *policy*, not the path.
- **The parallelism** is `--parallel` or `[defaults] parallel`.
- **The API token** of [`mpt serve`](../server/serve.md) has no fixed
  variable name. `[server] token = { env = "MPT_API_TOKEN" }` or
  `--token-env MPT_API_TOKEN` names the variable to read.
