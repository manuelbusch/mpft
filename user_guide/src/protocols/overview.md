# Overview

Every protocol answers to the same commands and the same flags. What differs is
what the far side can actually do — a mailbox cannot be listed, HTTP cannot
rename, S3 has no directories — and those differences show up as capabilities
rather than as separate commands.

`mpt schemes` prints this table for the binary you have, which is also how you
find out which [cargo features](../getting-started/installation.md#choosing-protocols)
were compiled in.

## The schemes

| Prefix | Protocol | Port | Feature |
|---|---|---|---|
| `file://`, or a bare path | [local file system](local.md) | – | always |
| `sftp://` | [SFTP over SSH](ssh.md) | 22 | `ssh` |
| `scp://` | [SCP over SSH](ssh.md) | 22 | `ssh` |
| `ftp://` | [FTP without TLS](ftp.md) | 21 | `ftp` |
| `ftps://` | [FTP with TLS](ftp.md) | 21, or 990 implicit | `ftp` |
| `http://`, `https://` | [HTTP GET and PUT](http.md) | 80, 443 | `http` |
| `webdav://`, `webdavs://` | [WebDAV](http.md) | 80, 443 | `webdav` |
| `s3://` | [S3-compatible storage](s3.md) | – | `s3` |
| `mailto:` | [e-mail, server from the configuration](mail.md) | – | `mail` |
| `smtp://` | [e-mail, server in the URL](mail.md) | 587 | `mail` |
| `mpt://` | a [profile](../configuration/profiles.md) — resolves to one of the above | – | always |

## What each one can do

| | receive | list | size | send | rename | append | mkdir |
|---|---|---|---|---|---|---|---|
| local | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `sftp://` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `scp://` | ✓ | – | – | ✓ | ✓ | – | ✓ |
| `ftp://`, `ftps://` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `http://`, `https://` | ✓ | – | ✓ | ✓ | – | – | – |
| `webdav://`, `webdavs://` | ✓ | ✓ | ✓ | ✓ | ✓ | – | ✓ |
| `s3://` | ✓ | ✓ | ✓ | ✓ | – | – | n/a |
| `mailto:`, `smtp://` | – | – | – | ✓ | – | – | – |

Reading the columns as features:

- **receive** — can be a source. Mail cannot; asking fails before any
  connection is made.
- **list** — `mpt ls` works, and so do [patterns](../guide/many-files.md#patterns-on-the-far-side)
  and `-r` with this scheme as the *source*.
- **size** — the source can say how large it is, which the progress percentage
  and `--skip-existing` need. SCP cannot, which has
  [consequences](ssh.md#scp-needs-the-size-up-front).
- **rename** — [atomic finishing](../guide/reliability.md#a-file-appears-only-when-it-is-whole)
  is possible. S3 does not need it: an object appears only when its upload is
  complete.
- **append** — [`--resume`](../guide/reliability.md#resuming-with---resume)
  is possible.
- **mkdir** — can be the *target* of a tree copy. S3 needs nothing, since a key
  containing slashes is all a directory ever was there.

## Options every scheme understands

| Option | Meaning |
|---|---|
| `?timeout=<seconds>` | inactivity limit for this endpoint; `0` disables it |
| `?connect_retries=<n>` | retry connecting and logging in this often |
| `?insecure=true` | skip TLS certificate verification (where TLS is involved) |

The protocol pages list what is specific to each. A [misspelled option is
ignored rather than reported](../getting-started/addressing.md#options-belong-to-one-endpoint).

## Choosing between near-equivalents

Three pairs come up often, and the protocol pages compare each in detail:

- [**`sftp://` over `scp://`**](ssh.md#sftp-versus-scp): SFTP lists, reports
  sizes and resumes; SCP does none of those.
- [**`webdav://` over `http://`**](http.md#http-versus-webdav): WebDAV adds
  listing, renaming and directory creation.
- [**`ftps://` over `ftp://`**](ftp.md#tls-modes): the same server with the
  credentials and the data encrypted.

## Mixing them

Nothing in a command has to agree on protocol. A fan-out may send to five
different ones, a job list may name a different one per line, and a copy
between two remote systems never touches the local disk:

```
mpt cp ftps://partner.example.com/out/data.csv \
    sftp://internal.example.com/import/ \
    "s3://archive/2026/" \
    "mailto:team@example.com?subject=Received"
```
