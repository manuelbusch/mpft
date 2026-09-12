# Thinking in URLs

`mpt` has one addressing model, and every command uses it. A source is a URL, a
target is a URL, and the prefix of the URL decides which protocol does the
work. Once this page is internalised, most of the tool follows from it.

```
<scheme>://[user[:password]@]host[:port]/path[?option=value&option=value]
```

```
sftp://deploy@srv.example.com/var/log/app.log
ftps://upload@ftp.partner.example:990/in/?tls=implicit
https://example.com/data.json
s3://bucket/reports/?endpoint=https://minio.example.com&region=eu-central-1
webdavs://cloud.example.com/documents/
mailto:boss@example.com?subject=Report
/var/backups/report.pdf
```

The last one is a URL too, in the way that matters: a path without a scheme is
a local file. You never have to write `file://` unless you want to.

## The trailing slash decides where a file lands

This is the rule to remember. A path that ends in `/` is a **directory**, and
the source's file name is appended to it. A path that does not is the **file
name itself**.

| Target | Source `report.pdf` ends up as |
|---|---|
| `backup/` | `backup/report.pdf` |
| `backup/2026-09-10.pdf` | `backup/2026-09-10.pdf` |
| `sftp://srv/incoming/` | `/incoming/report.pdf` |
| `sftp://srv/incoming/final.pdf` | `/incoming/final.pdf` |

It works the same for every protocol, including the ones with no real
directories: an `s3://bucket/reports/` target appends the file name to the key
prefix, which is what makes S3 keys look like paths.

A missing slash where you meant one is the most common early mistake, and it is
silent — you get a file named after a directory you expected. When in doubt,
add the slash.

The rule also cuts the other way for sources. `mpt cp sftp://srv/incoming/ ./`
asks to copy a *directory*, which a plain `cp` cannot do; that is what
[`-r`](../guide/many-files.md) is for.

## Options belong to one endpoint

Everything after `?` configures **that endpoint alone**. This matters as soon
as a command has more than one:

```
mpt cp "ftps://old.example.com/x.csv?insecure=true" "sftp://new.example.com/in/"
```

The old server with its expired certificate is trusted; the new one is still
checked properly. A global flag could not express that, which is why
`--insecure` exists only as a deprecated leftover and per-URL options are the
supported way.

Options fall into three groups:

- **Protocol-specific**, listed by `mpt schemes`: `key=` and `known_hosts=` for
  SSH, `tls=` and `passive=` for FTP, `endpoint=` and `region=` for S3,
  `subject=` and `cc=` for mail.
- **Shared by all schemes**: `timeout=`, `connect_retries=`, `insecure=` where
  TLS is involved.
- **Passed through** to the server: for `http(s)://` and `webdav(s)://`, any
  query parameter that is not one of the above stays in the request URL, so an
  API that expects `?format=json` gets it.

An option may be repeated where that makes sense: `header=` and `hostkey=` take
several, and each one counts.

One caveat: a **misspelled option is ignored, not reported**. `?timeuot=5`
changes nothing and says nothing, because for HTTP and WebDAV an unrecognised
option is meant to reach the server, and the other schemes do not police the
query string either. Options in the [configuration
file](../configuration/file.md) are checked strictly — an unknown key there is
an error that `mpt config check` will name — so a setting you rely on is better
placed there than repeated on the command line.

### The echo tells you what was used

The result line prints the target with the options that were **actually in
force**, including those that came from a default or a configuration file:

```
$ mpt cp report.pdf sftp://deploy@srv.example.com/incoming/
report.pdf -> sftp://deploy@srv.example.com/incoming/?timeout=30: 40000 bytes in 83.38ms
```

`?timeout=30` was never typed. Reading it back is the quickest way to check
what a run really did when several layers of configuration are involved.

## Quoting

`?` and `&` are shell metacharacters. A URL with options needs quotes:

```
mpt cp report.pdf "sftp://srv/in/?key=~/.ssh/deploy&timeout=120"     # right
mpt cp report.pdf sftp://srv/in/?key=~/.ssh/deploy&timeout=120       # the shell eats it
```

The habit worth forming is to quote every URL that contains a `?`. A plain
`sftp://srv/in/` needs nothing.

Two details inside a URL:

- **`~` is expanded by `mpt`, not by the shell**, in option values such as
  `key=~/.ssh/id_ed25519`. Inside quotes the shell leaves it alone, and `mpt`
  resolves it against the home directory.
- **Special characters are percent-encoded.** A subject with a space is
  `subject=Report%20KW36`; a `+` in a host-key fingerprint may be written as
  `%2B` or left as it is.

## Credentials in a URL, and why not to

`user:password@host` is understood, and it is the wrong place for a password:
it is visible in `ps` to every user on the machine and it lands in the shell
history. `mpt` warns when it sees one.

The user name alone is fine and often necessary:

```
mpt cp report.pdf sftp://deploy@srv.example.com/incoming/
```

For the password itself use `--password-stdin`, `--password-file`, the
`MPT_PASSWORD` environment variable, or a
[credential reference](../configuration/credentials.md) in the configuration
file. SSH keys are found automatically; see
[SFTP and SCP](../protocols/ssh.md).

## Not every scheme goes both ways

An endpoint can receive (be a source), send (be a target), or both. `mpt
schemes` has the exact table; the exceptions are worth knowing up front:

- **`mailto:` and `smtp://` can only send.** There is no way to read from a
  mailbox.
- **`scp://` cannot list**, so `mpt ls` and patterns do not work with it, and
  it cannot be the source of a tree copy. `sftp://` can do all of that over the
  same SSH connection, so prefer it unless the far side offers nothing else.
- **`http://` cannot list either**, and has no rename, which rules out
  [atomic finishing](../guide/reliability.md). Use `webdav://` against a server
  that speaks it.

Asking for the impossible fails immediately, before any connection:

```
$ mpt cp mailto:x@example.com ./
error: copy mailto:x@example.com?timeout=30: scheme 'mailto' cannot receive
```

## Paths on the far side

Path conventions differ, and `mpt` keeps each protocol's own:

| Scheme | Path is |
|---|---|
| local | a file-system path; relative to the working directory unless it starts with `/` |
| `sftp://`, `scp://` | absolute on the server; `/~/reports/` is relative to the login directory |
| `ftp://`, `ftps://` | as the server presents it, usually relative to the login directory |
| `http(s)://`, `webdav(s)://` | the request path |
| `s3://` | `bucket/key`, where the first segment is the bucket |
| `mailto:` | the recipient list, comma-separated |

On Windows a local path may carry a drive letter or be a UNC path, and `\` is
a separator; both are recognised as local files rather than mistaken for a
scheme.

## Short names for long URLs

A URL that recurs — with its key, its host-key pin, its timeout — can be given
a name in the configuration file and used as `mpt://<name>/`:

```toml
[profiles.prod]
url         = "sftp://deploy@srv.example.com/data/"
key         = "~/.ssh/prod_ed25519"
hostkey     = "SHA256:f29GJDwDP5hekqa22VhNdaNPBM+q6AzG3FvQaBCJnmg"
timeout     = 60
```

```
mpt cp report.pdf mpt://prod/incoming/
```

The path of the reference is appended to the profile's own path, and it cannot
climb out of it. [Named targets](../configuration/profiles.md) covers this in
full.

## Next

That is the whole model. With it, the rest of the guide is about what to do
once the endpoints are named: [copying a file](../guide/copying.md), then
[several targets at once](../guide/fan-out.md) and
[many files](../guide/many-files.md).
