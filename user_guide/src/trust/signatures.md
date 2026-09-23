# Signatures

A [checksum](checksums.md) protects against a transfer that went wrong. It does
not protect against someone who can write to the directory the file sits in:
replacing the file and recomputing the checksum beside it takes one command,
and the result verifies.

A signature answers the other question, *who* put this here, and `mpt`
answers it before the data is copied, not after.

```
mpt cp --sign ssh:~/.ssh/release_ed25519 report.pdf "s3://bucket/releases/"
mpt cp --verify-signers allowed_signers "s3://bucket/releases/report.pdf" ./
```

## Signing

`--sign` writes a detached signature over the **checksum file**, so one
signature covers the payload however large it is:

```
$ mpt cp --sign ssh:signer report.pdf out/
report.pdf -> out/: 12 bytes in 6.02ms
+ out/report.pdf.sha256
+ out/report.pdf.sha256.sig
sha256  4dc21b974cc293d0dfbb25326f0df4ac461f29d69ccc2c2dc5391f4f39a45aed
signed  SHA256:GHBfnine/dnKwNm0OtOe0+FFRYHoSc1HkLfEI4QGj4I (release@example.com) (OpenSSH)
```

`--sign` implies `--hash sha256` unless `--hash` says otherwise. The signature
is written **last**, after the payload and after the checksum file, so its
presence means the whole transfer finished.

| Backend | `--sign` | Signature file |
|---|---|---|
| OpenSSH | `ssh` (agent, then `$MPT_SSH_KEY`, then `~/.ssh/id_*`), or `ssh:<key>` | `<name>.sha256.sig` |
| OpenPGP | `pgp:<secret-key.asc>` | `<name>.sha256.asc` |

```
$ mpt cp --sign pgp:release-secret.asc --hash blake3 report.pdf out/
+ out/report.pdf.b3
+ out/report.pdf.b3.asc
blake3  4ee59acf208cdb32d826d48ea23246352f6c47babdb7f0d237744536ef34c0eb
signed  Release Bot <release@example.com> 5d23077e9c9241ad9fcfda9b00bac98e8af07553 (OpenPGP)
```

Export an OpenPGP key with `gpg --export-secret-keys --armor`. An encrypted key
takes its passphrase from `$MPT_SIGN_KEY_PASSPHRASE` or from
`[signing] passphrase`, which accepts a
[credential reference](../configuration/credentials.md). `--sign ssh` without a
key uses the ssh-agent; `$MPT_SIGN_KEY_FINGERPRINT` or
`[signing] agent_fingerprint` picks one identity out of several.

To sign every transfer to a particular place without anyone having to remember,
attach the key to a [profile](../configuration/profiles.md) for that place:

```toml
[profiles.releases]
url  = "s3://releases/artifacts/"
sign = "ssh:~/.ssh/release_ed25519"
hash = "sha256"
```

## Verifying

`--verify-signers <allowed_signers>` (OpenSSH) and `--verify-keyring
<pubkeys.asc>` (OpenPGP) both imply `--check`:

```
$ mpt cp --verify-signers allowed_signers out/report.pdf back/
sha256  4dc21b974cc293d0dfbb25326f0df4ac461f29d69ccc2c2dc5391f4f39a45aed
signature ok release@example.com (SHA256:GHBfnine/dnKwNm0OtOe0+FFRYHoSc1HkLfEI4QGj4I)
check ok (SHA-256)
```

**The signature is checked before any data is copied.** The checksum file and
its signature sit next to the source and are fetched first; if the signature is
missing, invalid or made by a key you do not trust, the transfer never starts.
Nothing untrusted reaches the target, and nothing has to be cleaned up
afterwards.

Every way it can fail says which way it was:

```
error: signature: made by SHA256:GHBfnine/dnKwNm0OtOe0+FFRYHoSc1HkLfEI4QGj4I,
       which is not in allowed_signers
error: signature: check: no OpenSSH signature report.pdf.sha256.sig next to the source
error: signature: SSH signature invalid: signature error
```

The last one is what a tampered checksum file looks like: the digest was
changed, the signature no longer covers it. All three exit with code **3**.

The trust file can also live in the configuration, so a routine command needs
no flag:

```toml
[verify]
allowed_signers = "~/.config/mpt/allowed_signers"
keyring         = "~/.config/mpt/trusted.asc"
```

With `[policy] require_signature = true` a bare `--check` is then refused as
insufficient — see [Policies](../configuration/policies.md#requiring-signatures).

## Interoperability with OpenSSH and GnuPG

Nothing here is a private format. An OpenSSH signature is SSHSIG in namespace
`file`, and the recipient can verify it with OpenSSH:

```
$ ssh-keygen -Y verify -f allowed_signers -I release@example.com -n file \
      -s report.pdf.sha256.sig < report.pdf.sha256
Good "file" signature for release@example.com with ED25519 key SHA256:GHBfnine/dnKwNm0OtOe0+FFRYHoSc1HkLfEI4QGj4I
```

An OpenPGP signature is an ordinary detached signature:

```
$ gpg --verify report.pdf.b3.asc report.pdf.b3
gpg: Signature made Thu Sep 10 20:08:38 2026 CEST
gpg: Good signature from "Release Bot <release@example.com>"
```

It works in both directions: `mpt` verifies what `ssh-keygen -Y sign` and `gpg
--detach-sign` produce.

## Trust files

An `allowed_signers` file is OpenSSH's, one principal and key per line, and its
options are honoured rather than ignored:

```
release@example.com valid-after=20260101,valid-before=20270101 ssh-ed25519 AAAAC3Nz…
```

- `valid-after=` and `valid-before=` (`YYYYMMDD[HHMM[SS]]`, read as UTC) must
  contain the moment of verification:

  ```
  error: signature: rejected at 2026-09-10T18:05:31Z: release@example.com:
         key expired at 2020-01-01T00:00:00Z
  ```

- `namespaces="…"` must include `file`, or the key is not accepted for these
  signatures.
- `cert-authority` lines are **skipped**. Certificate signatures are not
  verified, and silently treating a CA line as an ordinary key would trust
  more than the file says.

For OpenPGP the keyring's self-signatures are verified when it is loaded.
Revoked keys and subkeys are refused, and so are keys that have expired, or
have not yet come into force, at the moment of verification.

## Signing time

A signed checksum file carries a second line:

```
4dc21b974cc293d0dfbb25326f0df4ac461f29d69ccc2c2dc5391f4f39a45aed  report.pdf
# mpt-signed-at: 2026-09-10T18:05:31Z
```

It is a comment, so `sha256sum -c` and `b3sum -c` ignore it, and it is inside
what the signature covers, so it cannot be changed unnoticed by anyone but the
signer.

**It does not decide whether the key is valid.** Keys are judged at the moment
of verification, as `ssh-keygen -Y verify` and `gpg --verify` judge them. The
signing time is the signer's own claim: if it counted, a key that has been
retired, or has fallen into the wrong hands, could sign something today and
date it back into the time it was valid. A key whose `valid-before` has passed,
or that has expired, verifies nothing any more, including what it signed while
it was valid; re-sign what should stay verifiable with the key that replaces
it.

**An old signature can be refused as such.** An attacker who cannot forge a
signature can still serve you a correctly signed *old* file in place of the
current one. `[policy] max_signature_age` closes that:

```toml
[policy]
max_signature_age = "7d"
```

```
error: signature: the checksum file was signed 9d ago (2026-09-01T18:05:31Z),
       longer than the 7d the policy allows
```

With the policy set, a checksum file with no signing time is refused as well;
otherwise removing the line would be enough to escape the rule.

## Practical notes

- [**Mail targets**](../protocols/mail.md#the-message) get the signature as a
  third attachment.
- **The backends are [cargo features](../getting-started/installation.md#choosing-protocols)**,
  `sign-ssh` and `sign-pgp`, both on by default. A binary built without one
  says so:

  ```
  error: unsupported scheme 'OpenSSH signatures (compiled without the 'sign-ssh' feature)'
  ```

- **Signing costs one signature per transfer**, over a file of one or two
  lines, so its cost does not depend on the size of the payload.
