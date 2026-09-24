# HTTP and WebDAV

Two schemes over the same client. `http(s)://` is a plain GET or PUT against
whatever the server offers. `webdav(s)://` speaks the WebDAV extensions on top,
which add listing, renaming and directory creation.

```
mpt cp https://example.com/data.json ./
mpt cp report.pdf "https://api.example.com/upload?method=post"
mpt cp report.pdf webdavs://cloud.example.com/documents/
mpt ls webdavs://cloud.example.com/documents/
```

## HTTP versus WebDAV

| | `http(s)://` | `webdav(s)://` |
|---|---|---|
| GET, PUT | ✓ | ✓ |
| list a directory | – | ✓ (`PROPFIND`) |
| rename, and therefore atomic finishing | – | ✓ (`MOVE`) |
| create directories, and therefore `-r` as a target | – | ✓ (`MKCOL`) |
| size of a source | ✓ (`HEAD`) | ✓ |

Nextcloud, ownCloud, SharePoint and most NAS boxes speak WebDAV on the same
URL where plain HTTP would work, so the choice is usually just which prefix you
type. `webdavs://` is WebDAV over HTTPS and is the form to use.

Plain HTTP cannot rename, so a PUT goes straight to the final name. There is no
`.mpt-part` and no `--resume`; an interrupted upload leaves whatever the server
kept.

## The request path

The path goes to the server as the URL spells it. A file name that `mpt`
appends, from a directory target or a listing, is percent-encoded segment by
segment, so a space, `#`, `?`, `%` or `ä` in a name reaches the server as part
of that name, in a `MOVE`'s `Destination` header as well. An encoded `/`
(`%2F`) stays encoded, which is what APIs such as GitLab's expect of
`projects/group%2Fproject`.

## Sending

GET is used for reading. For writing, the method is `PUT` unless you say
otherwise:

```
mpt cp report.pdf "https://api.example.com/files/report.pdf"                # PUT
mpt cp report.pdf "https://api.example.com/upload?method=post"              # POST
mpt cp report.pdf "https://api.example.com/files/report.pdf?method=patch"   # PATCH
```

The payload is streamed, so uploading a large file does not need memory for it.

## Headers and query parameters

```
mpt cp report.pdf "https://api.example.com/upload?header=X-Api-Key:abc123&header=X-Run:42"
```

`?header=Name:Value` may be repeated. Anything else in the query that `mpt`
does not recognise is **passed through to the server**, so an API's own
parameters travel:

```
mpt cp https://api.example.com/export?format=csv&range=30d ./
```

The cost is that a [misspelled `mpt`
option](../getting-started/addressing.md#options-belong-to-one-endpoint)
becomes a query parameter instead of an error.

The options `mpt` keeps for itself are `method`, `header`, `token`, `insecure`,
`timeout` and `connect_retries`.

## Authentication

Basic authentication with `user:password@` works, and over `http://` it
[warns](../trust/connections.md#credentials-in-the-clear), because that sends
the credentials in the clear.

For anything modern the answer is a bearer token:

```
mpt cp report.pdf "https://graph.example.com/upload?token=eyJ0eXAi…"
```

Better, keep it out of the command line and let it be fetched when it is
needed:

```toml
[http]
token = { cmd = "az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv" }
hosts = ["graph.microsoft.com"]
```

The configured token goes only to the hosts `hosts` names (by name, without a
port, in any case), and only over `https://` and `webdavs://`. Every other
URL, a download mirror as much as a plain `http://` address, gets no token,
and with no `hosts` at all it goes nowhere and a warning says so. A token
written into the URL (`?token=`) belongs to that URL alone.

The token is sent as `Authorization: Bearer …`, the header is marked sensitive
so it stays out of logs, and it is fetched when needed and [kept for ten
minutes](../configuration/credentials.md#when-references-are-resolved). Anything that prints a
token on standard output works the same way, such as
`gcloud auth print-access-token` or a script wrapped around a
client-credentials flow. See [Credentials and
secrets](../configuration/credentials.md).

A device-code flow with a refresh token in the key store is not built in; a
script that prints a token covers the same ground.

## Redirects

A download follows up to ten redirects. The endpoint's own headers, its token
and its password go only to the host the URL names: a redirect to another host
(a download API that hands over to a CDN or to a presigned storage URL) is
followed without any of them, and stays without them if it comes back. A
redirect from `https://` to `http://`, or to anything but HTTP, is refused.

An upload is not redirected, since its payload has been streamed once: a
`3xx` answer to a PUT or POST fails the upload and names where the server
wanted it sent.

A `webdav(s)://` endpoint refuses the same downgrade.

## Listing

`mpt ls` on `http://` fails, and says what to do about it:

```
$ mpt ls https://example.com/files/
error: listing https://example.com/files/?timeout=30: scheme 'http' cannot list
       (use webdav:// for PROPFIND)
```

The same applies to [patterns](../guide/many-files.md#patterns-on-the-far-side)
and to `-r` with an HTTP source: both need a listing. An HTTP *target* refuses
`-r` because there are no directories to create.

## Sizes and progress

A source's size comes from `HEAD`, or from `Content-Length` on the GET. A
server that sends neither still transfers fine; the progress display shows
bytes and a rate without a percentage, and
[`--skip-existing`](../guide/reliability.md#skipping-with---skip-existing)
cannot skip a target it cannot measure.
