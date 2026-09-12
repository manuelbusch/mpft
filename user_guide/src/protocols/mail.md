# E-mail

`mailto:` and `smtp://` turn a file into an attachment. They are the only
endpoints that can send but never receive, and the only ones where the
"directory" in a URL is a list of people.

```
mpt cp report.pdf "mailto:boss@example.com?subject=Weekly%20report"
mpt cp report.pdf "smtp://reports@mail.example.com:587/boss@example.com?subject=Report"
```

Being send-only is checked before anything connects:

```
$ mpt cp mailto:x@example.com ./
error: copy mailto:x@example.com?timeout=30: scheme 'mailto' cannot receive
```

## `mailto:` versus `smtp://`

**`mailto:`** names recipients and takes the server from the configuration.
This is the form to use, because the server belongs in one place rather than in
every command:

```toml
[mail]
smtp     = "smtp://reports@mail.example.com:587?tls=starttls"
password = { keyring = "mpt/smtp" }
from     = "reports@example.com"
```

```
mpt cp report.pdf "mailto:boss@example.com"
```

`$MPT_SMTP_URL` and `$MPT_SMTP_PASSWORD` do the same for one run. Without
either:

```
error: authentication failed: mailto: requires MPT_SMTP_URL or [mail] smtp in the
       configuration (e.g. smtp://user@mail.example.com:587?tls=starttls)
```

**`smtp://`** puts the server in the URL and the recipients in the path, which
suits a one-off or a script that talks to a local relay:

```
mpt cp report.pdf "smtp://127.0.0.1:25/ops@example.com?tls=none&from=cron@example.com"
```

Several recipients are separated by commas or semicolons:

```
mpt cp report.pdf "mailto:boss@example.com,team@example.com"
```

## The message

| Option | Meaning |
|---|---|
| `?subject=` | subject line; percent-encode spaces (`Weekly%20report`) |
| `?body=` | body text; the default names the attachment |
| `?cc=`, `?bcc=` | further recipients, comma-separated |
| `?from=` | sender address |
| `?filename=` | name the attachment differently from the source |

```
$ mpt cp --hash sha256 report.pdf "mailto:boss@example.com,team@example.com?subject=Weekly%20report&cc=cc@example.com"
report.pdf -> mailto:boss@example.com,team@example.com?subject=Weekly report&cc=cc@example.com: 12 bytes in 18.79ms
sha256  92455f427ad655c4a7d21709eb2d121d5567e30736c2614e6dcab1af884c8252
```

What arrives is a multipart message with the file attached under its own name,
its content type guessed from the extension:

```
From: reports@example.com
Subject: Weekly report
To: boss@example.com, team@example.com
Cc: cc@example.com
Content-Type: multipart/mixed;
  Content-Disposition: attachment; filename="report.pdf"
  Content-Disposition: attachment; filename="report.pdf.sha256"
```

**Checksums and signatures travel as further attachments.** A mail target has
no directory to put a sidecar file in, so `--hash` adds a second attachment
(and a line in the body) and `--sign` a third. The recipient verifies them with
`sha256sum -c` and `ssh-keygen -Y verify` exactly as they would elsewhere; see
[Checksums](../trust/checksums.md) and [Signatures](../trust/signatures.md).

## The sender

Mail needs a `From:`, and it is looked for in this order:

1. `?from=` on the URL
2. `$MPT_MAIL_FROM`
3. `[mail] from` in the configuration
4. the SMTP user name, if it is an address

```
error: invalid URL: mail: no sender (use ?from=, MPT_MAIL_FROM or an e-mail address
       as SMTP user)
```

Many servers reject a `From:` that does not match the authenticated account, so
the fourth rule is usually the one that applies.

## Encryption and login

| `?tls=` | Meaning | Usual port |
|---|---|---|
| `starttls` | connect in the clear, upgrade before logging in | 587 |
| `implicit` | TLS from the first byte | 465 |
| `none` | no encryption — a local relay only | 25 |

`tls=none` with a password [warns](../trust/connections.md#credentials-in-the-clear),
and `[policy] refuse_plaintext_auth = true` refuses it.

`?auth=` picks the SASL mechanism: `xoauth2`, `plain`, `login`, or `auto` (the
default, which lets the server and the library agree).

**XOAUTH2** is what Microsoft 365 and Google want now that they have switched
basic authentication off. The access token takes the place of the password, so
a [credential provider](../configuration/credentials.md) fetches it when the
mail is about to be sent:

```toml
[mail]
smtp     = "smtp://reports@example.com@smtp.office365.com:587?tls=starttls"
auth     = "xoauth2"
password = { cmd = "az account get-access-token --resource https://outlook.office365.com --query accessToken -o tsv" }
```

Note the `@` in the user name: the SMTP user is an address here, which is also
what supplies the sender.

## Attachment size limit

Mail is the one protocol that cannot stream. The message has to be assembled
and base64-encoded before it can be sent, so the payload is held in memory, and
there is a limit:

- `$MPT_MAIL_MAX_ATTACHMENT`, in bytes, or
- `[mail] max_attachment`, with a unit (`25M`), or
- 25 MiB by default.

Raising it raises the memory the process needs. For anything large, send a link
instead — a `s3://` upload and a `mailto:` notification in the same fan-out do
that in one command:

```
mpt cp big-report.pdf "s3://reports/2026/" "mailto:boss@example.com?subject=Report%20uploaded&body=In%20the%20reports%20bucket"
```

Base64 also means the message is about a third larger than the file, which
matters against a server's own limit rather than against this one.

## In a fan-out

A mail target behaves like any other, with two differences.

**It pauses the stream at the start**, while it connects and negotiates, the
same as SCP does. That is
[head-of-line blocking](../guide/fan-out.md#slow-targets-stalled-targets) and
it passes.

**A retried mail may be delivered twice**, because SMTP cannot say whether a
message that failed halfway was accepted. Every other kind of target overwrites
a name and is safe to retry; see
[Retrying a target](../guide/fan-out.md#retrying-a-target). If duplicates would
be a problem, leave `--retries` off when a mail target is in the list.

## Next

That is the last protocol. The [reference](../reference/cli.md) is the lookup
material: every flag, key, variable and exit code.
