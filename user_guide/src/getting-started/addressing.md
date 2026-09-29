# Thinking in URLs

`mpft` has one addressing model, and every command uses it. A source is a URL, a
target is a URL, and the prefix of the URL decides which protocol does the
work. Most of the tool follows from this page.

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

## Where a file lands

A path that ends in `/` is a **directory**, and the source's file name is
appended to it. A path that does not is the **file name itself**, unless it
names a directory that already exists: then the file goes into it, as with
`cp` and `scp`.

| Target | Source `report.pdf` ends up as |
|---|---|
| `backup/` | `backup/report.pdf` |
| `backup`, an existing directory | `backup/report.pdf` |
| `backup/2026-09-10.pdf` | `backup/2026-09-10.pdf` |
| `sftp://srv/incoming/` | `/incoming/report.pdf` |
| `sftp://srv/incoming`, an existing directory | `/incoming/report.pdf` |
| `sftp://srv/incoming/final.pdf` | `/incoming/final.pdf` |

The slash works the same for every protocol, including the ones with no real
directories: an `s3://bucket/reports/` target appends the file name to the key
prefix. The existing directory counts where directories are real: local paths,
`sftp://`, `scp://`, `ftp://`, `ftps://`, `webdav://` and `webdavs://`, each
of which asks the server first. On `s3://` and `http(s)://` only the slash
decides, as with `aws s3 cp` and `curl`: `s3://bucket/reports` is the key
`reports`.

A missing slash where you meant one is still the most common early mistake
where the directory does not exist yet, or on S3 and HTTP, and there it is
silent: you get a file named after the directory you expected. When in doubt,
add the slash.

The rule also cuts the other way for sources. `mpft cp sftp://srv/incoming/ ./`
asks to copy a *directory*, which a plain `cp` cannot do; that is what
[`-r`](../guide/many-files.md) is for.

## Options belong to one endpoint

Everything after `?` configures **that endpoint alone**. This matters as soon
as a command has more than one:

```
mpft cp "ftps://old.example.com/x.csv?insecure=true" "sftp://new.example.com/in/"
```

The old server with its expired certificate is trusted; the new one is still
checked. A global flag could not express that, which is why `--insecure` is
deprecated and per-URL options are the supported way.

Options fall into three groups:

| Group | Examples | Listed by |
|---|---|---|
| Protocol-specific | `key=`, `known_hosts=` (SSH); `tls=`, `passive=` (FTP); `endpoint=`, `region=` (S3); `subject=`, `cc=` (mail) | `mpft schemes` and the protocol pages |
| Shared by all schemes | `timeout=`, `connect_retries=`, `insecure=` where TLS is involved | [Protocols overview](../protocols/overview.md#options-every-scheme-understands) |
| Passed through to the server | `?format=json` on an `http(s)://` or `webdav(s)://` URL | the server's own API |

An option may be repeated where that makes sense: `header=` and `hostkey=` take
several, and each one counts.

A **misspelled option is ignored, not reported**. `?timeuot=5` changes nothing
and says nothing, because for HTTP and WebDAV an unrecognised option is meant
to reach the server, and the other schemes do not police the query string
either. Options in the [configuration file](../configuration/file.md) are
checked strictly, so a setting you rely on is better placed there than
repeated on the command line.

### The result line echoes the options used

The result line prints the target with the options that were **actually in
force**, including those that came from a default or a configuration file:

```
$ mpft cp report.pdf sftp://deploy@srv.example.com/incoming/
report.pdf -> sftp://deploy@srv.example.com/incoming/?timeout=30: 40000 bytes in 83.38ms
```

`?timeout=30` was never typed. Reading it back is the quickest way to check
what a run really did when several layers of configuration are involved.

## Quoting

`?` and `&` are shell metacharacters. A URL with options needs quotes:

```
mpft cp report.pdf "sftp://srv/in/?key=~/.ssh/deploy&timeout=120"     # right
mpft cp report.pdf sftp://srv/in/?key=~/.ssh/deploy&timeout=120       # the shell eats it
```

Quote every URL that contains a `?`. A plain `sftp://srv/in/` needs nothing.

Two details inside a URL:

- **`~` in a URL option is expanded by `mpft`.** Inside quotes the shell leaves
  `key=~/.ssh/id_ed25519` alone, and `mpft` resolves the `~` against the home
  directory. A `~` in a *local path* (`~/reports/x.pdf`) is the shell's job as
  usual, so write that one unquoted.
- **Special characters are percent-encoded.** A subject with a space is
  `subject=Report%20KW36`. A `+` is a plus sign, not a space as in an HTML
  form, so a `+` in a host-key fingerprint, a token or a passphrase may be
  written as `%2B` or left as it is.

## Credentials in a URL, and why not to

`user:password@host` is understood, and `mpft` warns when it sees it: the
password is visible in the process list and the shell history. The user name
alone is fine and often necessary:

```
mpft cp report.pdf sftp://deploy@srv.example.com/incoming/
```

[Credentials and secrets](../configuration/credentials.md) covers where the
password goes instead.

## Send-only and receive-only schemes

An endpoint can receive (be a source), send (be a target), or both. `mpft
schemes` has the exact table. The exceptions:

- **`mailto:` and `smtp://` can only send.** There is no way to read from a
  mailbox.
- **`scp://` cannot list**, so `mpft ls` and patterns do not work with it, and
  it cannot be the source of a tree copy. `sftp://` can do all of that over the
  same SSH connection, so prefer it unless the far side offers nothing else.
- **`http://` cannot list either**, and has no rename, which rules out
  [atomic finishing](../guide/reliability.md). Use `webdav://` against a server
  that speaks it.

Asking for the impossible fails immediately, before any connection, with exit
code 2.

## Paths on the far side

Path conventions differ, and `mpft` keeps each protocol's own:

| Scheme | Path is |
|---|---|
| local | a file-system path; relative to the working directory unless it starts with `/` |
| `sftp://`, `scp://`, `ftp://`, `ftps://` | absolute on the server; `/~/reports/` is relative to the login directory |
| `http(s)://`, `webdav(s)://` | the request path |
| `s3://` | `bucket/key`, where the first segment is the bucket |
| `mailto:` | the recipient list, comma-separated |

On Windows a local path may carry a drive letter or be a UNC path, and `\` is
a separator; both are recognised as local files rather than mistaken for a
scheme.

## Profiles

A URL that recurs — with its key, its host-key pin, its timeout — can be given
a name in the configuration file and used as `mpft://<name>/`:

```
mpft cp report.pdf mpft://prod/incoming/
```

The path of the reference is appended to the profile's own path.
[Profiles](../configuration/profiles.md) covers how to define one.
