# Credentials and secrets

A password on a command line is public. It stands in `ps` for every user on the
machine, it lands in the shell history, and it turns up in CI logs that nobody
meant to keep. `mpt` warns when it sees one:

```
WARN mpt::policy: the password stands in the URL, where the process list and the shell
     history can read it. Use MPT_PASSWORD, --password-file or --password-stdin instead
```

This page is about the alternatives. There are two levels: keeping a secret out
of the command line for one run, and putting a *reference* to it in the
configuration so that no run ever handles it directly.

## For one run

```
mpt --password-stdin cp report.pdf ftps://upload@ftp.example.com/in/ < secret.txt
mpt --password-file ~/.config/mpt/partner.pw cp report.pdf ftps://…
MPT_PASSWORD=… mpt cp report.pdf ftps://…
```

`--password-file` reads the first line, ignoring the newline an editor leaves
behind, and complains if others can read the file. `--password-stdin` reads the
first line of standard input, which suits a secret manager's output. All three
apply to `sftp`, `scp`, `ftp`, `ftps`, `http` and `webdav`; SMTP has
`MPT_SMTP_PASSWORD` of its own.

There is also `--password <PW>`, which is the same as `MPT_PASSWORD` but
stands in the argument list and is therefore visible in `ps` like a password
in the URL. It is there for a quick test on a machine nobody shares; the other
three are the ones to use.

SSH keys need none of this: the agent and the default keys are found on their
own, in the order [SFTP and SCP](../protocols/ssh.md#authentication) lists.

## For every run: references

In the configuration file a secret is not written down. What is written down is
where to get it, and it is fetched when the endpoint is about to be used:

```toml
[profiles.prod]
url      = "sftp://deploy@srv.example.com/data/"
password = { env = "PROD_PW" }
```

| Provider | Where it reads from | Good for |
|---|---|---|
| `{ env = "NAME" }` | an environment variable | CI, containers, systemd `LoadCredential` |
| `{ file = "~/path" }` | the first line of a file; permissions are checked | mounted secrets, Kubernetes |
| `{ cmd = "…" }` | the standard output of a command, run through `sh -c` | any secret manager with a CLI |
| `{ keyring = "service/user" }` | the OS key store | a workstation |
| `{ vault = "path#field" }` | HashiCorp Vault over HTTP | servers without CLI tools |

```toml
password = { file = "/run/secrets/partner-ftp" }
password = { cmd = "op read op://Infra/prod-sftp/password" }
password = { cmd = "pass show hosting/partner-ftp" }
password = { keyring = "mpt/partner-ftp" }
password = { vault = "secret/data/mpt/prod#password" }
```

`keyring` and `vault` are optional cargo features. A binary built without them
says so rather than quietly falling back to nothing:

```
error: authentication failed: password of profile 'k': keyring credentials need
       the 'keyring' feature, which is not compiled in
```

[Installation](../getting-started/installation.md) covers how to build them in.

### Where a reference may stand

The same syntax works for every secret in the file:

| Key | What it is |
|---|---|
| `[profiles.<name>] password` | password for that endpoint |
| `[ssh] passphrase` | passphrase of the SSH key |
| `[signing] passphrase` | passphrase of the signing key |
| `[mail] password` | SMTP password, or the OAuth2 token with `auth = "xoauth2"` |
| `[http] token` | bearer token for HTTP and WebDAV |
| `[s3] access_key_id`, `secret_access_key` | S3 keys |

A plain string (`password = "hunter2"`) works too, and warns. It is meant for
a quick test, not as something to leave in place.

### When references are resolved

A reference is resolved when the endpoints of *this* command need it, not when
the file is read. Two things follow.

**Commands do not run for endpoints you are not using.** A configuration with
ten profiles, each with a `cmd` that talks to a password manager, costs one
invocation for the one profile a command touches, not ten.

**The value is fetched once per run** and shared between the endpoints that
name the same reference, so a fan-out to three targets behind one credential
does not query it three times.

Errors name what the secret was for, which matters when several are in play:

```
error: authentication failed: password of profile 'q': $DEFINITELY_NOT_SET is not set
error: authentication failed: password of profile 'r': `exit 3` failed (exit status: 3):
```

## The OS key store

With the `keyring` feature, `mpt credentials` manages the entries that
`{ keyring = "…" }` reads:

```
$ printf 'hunter2' | mpt credentials set mpt/partner-ftp
stored mpt/partner-ftp
$ mpt credentials get mpt/partner-ftp
hunter2
$ mpt credentials delete mpt/partner-ftp
deleted mpt/partner-ftp
```

The name is `<service>/<user>`, and it maps onto the macOS Keychain, the
Windows Credential Manager and the Linux Secret Service. Without the feature
the subcommand does not exist:

```
error: unrecognized subcommand 'credentials'
```

## The `cmd` provider

The `cmd` provider is the most useful of the five, because every secret manager
has a command-line interface, and the most dangerous, for the same reason: the
configuration file decides what runs.

Two consequences:

- **Keep the file to yourself.** `mpt` warns when a file that holds or points
  at credentials is readable by others, and `[policy] strict_permissions = true`
  makes it an error. See [Policies](policies.md).
- **A [`./mpt.toml`](file.md#the-file-in-the-working-directory) cannot carry
  a credential command**, so a directory you happen to be standing in cannot
  make `mpt` run something on your behalf.

The provider passes the string to `sh -c` (on Windows, `cmd /C`), so pipes and
quoting work as usual. Only the first line of standard output is used, and a
non-zero exit is an error.

## Files with secrets in them

The `file` provider and `--password-file` both check permissions:

```
WARN mpt::credentials: /home/deploy/partner.pw is readable by others (mode 644); chmod 600 it
```

The same applies to SSH keys, which OpenSSH already insists on. On Windows,
where there are no mode bits, a file outside the user's profile directory is
warned about instead.

## Single sign-on

Where a protocol has an answer that is better than a long-lived password, `mpt`
uses it, and the token arrives through the same providers as a password would:

- **S3**: the [AWS credential chain](../protocols/s3.md#single-sign-on-and-roles),
  with the `s3-aws-auth` feature.
- **SMTP**: [`auth = "xoauth2"`](../protocols/mail.md#encryption-and-login)
  with the token in `[mail] password`.
- **HTTP and WebDAV**: [`[http] token`](../protocols/http.md#authentication)
  as a bearer token.
- **SFTP and SCP**: [OpenSSH certificates](../protocols/ssh.md#certificates),
  from an agent or a file.

The protocol pages have the worked examples.

## In memory

Passwords and passphrases are held in a type that redacts itself in debug
output and overwrites its memory when dropped, so a secret does not linger
after use or appear in a log line by accident. Every log line that mentions a
URL shows the password as `***`.
