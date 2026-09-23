# Policies

`[defaults]` sets values that a command line can override. `[policy]` sets
rules that it cannot. A default is a convenience; a policy is a decision that
has already been made, by you for your machine or by whoever administers the
service account this runs under.

```toml
[policy]
known_hosts           = "strict"   # built-in default
refuse_plaintext_auth = true       # built-in default: false
refuse_insecure_tls   = true       # built-in default: false
require_signature     = false      # built-in default
max_signature_age     = "0"        # built-in default: no limit
strict_permissions    = false      # built-in default
```

All six are optional. The block above tightens two of them; the
[reference](../reference/configuration.md#policy) lists the built-in defaults.

## Refusing unencrypted credentials

Credentials that would travel unprotected [produce a
warning](../trust/connections.md#credentials-in-the-clear).
`refuse_plaintext_auth = true` makes that a refusal instead, before any
connection is made; that page shows the message. `--refuse-plaintext-auth`
and `MPT_REFUSE_PLAINTEXT_AUTH=1` do the same for one run, which shows what
the policy would break before it is made permanent. Either of them holds even
where the file says `refuse_plaintext_auth = false`.

## Refusing to skip certificate checks

[`?insecure=true`](../trust/connections.md#tls-certificates) switches off TLS
certificate verification for one endpoint, because self-signed certificates on
internal servers exist. `refuse_insecure_tls = true` takes the option away:

```
error: authentication failed: ftps://upload:***@ftp.example.com/?insecure=true:
       insecure=true would switch off certificate verification, which
       policy.refuse_insecure_tls forbids
```

Set it where nobody should be making that trade on their own. The better
answer is to fix the certificate or install the internal CA, since
`insecure=true` disables *all* verification, the hostname included.

## The host-key policy for the machine

`known_hosts` sets the default host-key policy for `sftp://` and `scp://`:
`strict`, `accept-new` or `off`, as described under [SSH host
keys](../trust/connections.md#ssh-host-keys). A URL may still name its own
`?known_hosts=`, so this is a default rather than a prohibition. It makes
`accept-new` the norm on a workstation, or keeps `strict` explicit on a
server.

## Requiring signatures

`require_signature = true` means that whenever a transfer is checked, a
signature must be checked too. A `--check` without trusted keys then fails
rather than settling for a bare checksum:

```
$ mpt cp --check sftp://srv/in/report.pdf ./
error: policy.require_signature is set, but no trusted keys are given: use
       --verify-signers/--verify-keyring or [verify] in the configuration
```

Point it at the trust store once and the requirement is satisfied for every
run:

```toml
[policy]
require_signature = true

[verify]
allowed_signers = "~/.config/mpt/allowed_signers"
```

It does not make checking mandatory; a plain `cp` is still a plain `cp`. It
ensures that a check, when asked for, is a signature check, since a bare
checksum can be replaced by whoever can write to that directory.

## Refusing stale signatures

`max_signature_age` refuses a signature older than the given age, judged
against the signing time recorded in the checksum file:

```toml
[policy]
max_signature_age = "7d"      # "30m", "24h", "7d"; "0" means no limit
```

This keeps a correctly signed but *old* file from being served in place of the
current one. An attacker who cannot forge a signature can still replay one,
and a nightly export that is three weeks old is a problem whether or not
somebody arranged it.

[Signing time](../trust/signatures.md#signing-time) explains where the
timestamp comes from and why a checksum file without one is refused under this
policy.

## Strict file permissions

A configuration file that holds credentials, or names a command that produces
them, is [warned about](file.md#permissions) when others can read it.
`strict_permissions = true` makes it an error instead, and does the same for
a [secret file](credentials.md#files-with-secrets-in-them) the configuration
or `--password-file` names. Set it on a shared machine and in any image where
the file is baked in.

## Where to put a policy

For a person, `~/.config/mpt/config.toml` is the whole story.

For a service account, put the file where the account reads it and cannot edit
it, and name it explicitly with `--config` or `$MPT_CONFIG`; see [where it is
read from](file.md#where-it-is-read-from). A policy in a file the running user
can rewrite is a reminder, not a control. `./mpt.toml` may add to a policy
but [only make it stricter](file.md#the-file-in-the-working-directory), so a
directory you are standing in cannot switch a rule off.

Because `[policy]` is process-wide, it applies to every endpoint of a run,
including the ones a [profile](profiles.md) or a
[job list](../guide/job-lists.md) named rather than you. The same holds for
a process that runs other people's jobs: the policy of the machine that runs
[`mpt serve`](../server/serve.md) covers every job it accepts, and the policy
of a [relay](../server/relay.md) covers every target it delivers to.
