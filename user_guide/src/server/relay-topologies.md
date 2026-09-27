# Relay topologies: sources and chains

[`cp --via`](relay.md) sends a file from here to a relay, which delivers it.
Two arrangements take this side out of the data path altogether: a source
that the relay reads itself, and a target that one relay hands on to another.
Both are set up with `via` in a [profile](../configuration/profiles.md), and
both keep the client's part to the SSH session that carries the questions,
the progress and the report.

## Letting the relay read the source

A source can be behind a relay as well. Give its profile a `via`, and the
relay opens and reads it itself: this side only says which file, and no byte
of it comes through here. The path is the relay's, so it may be one this
machine cannot even see:

```toml
[profiles.incoming]
url = "in/report.pdf"              # relative to the relay's working directory
via = "mpt://relay"
```

```
$ mpt cp mpt://incoming mpt://prod/
[1/1] in/report.pdf -> sftp://deploy@srv.example.com/data/: 40000 bytes in 17.22ms
1/1 jobs ok in 17.30ms
```

The progress this side prints is the relay's, counted as it reads. Only a
profile's own `via` makes a source travel this way; `[defaults] via` and
`--via` decide where targets are written, never where a source is read.

A path on the relay host, as above, is one the relay hands out only when it
runs with `--allow-local` ([Trust](relay-host.md#trust)). Otherwise name a
profile of the relay's own — `url = "mpt://incoming"` here, with
`[profiles.incoming] url = "in/report.pdf"` in the relay's configuration —
or a source on a third host, as in the examples below.

### Listing a directory behind the relay

`mpt ls` asks the relay as well when the directory's profile names one: the
relay lists it and this side prints the entries as a local `ls` would, with
`--json` too. `mpt ls --no-via` lists from here instead.

```toml
[profiles.inbox]
url = "in/"
via = "mpt://relay"
```

```
$ mpt ls mpt://inbox/
-        40000  report.pdf
d            -  archive
```

The listing is a session of its own, with the same credentials and the same
forwarded agent a copy would use (see [Operations besides the
copy](../reference/relay-protocol.md#operations-besides-the-copy)). A relay of
an older release cannot list, and says so; one lists at most `--max-entries`
(100000) entries and refuses a larger directory as a whole.

### Patterns and trees behind the relay

A [pattern or `-r`](../guide/many-files.md) is expanded where the files are:
a source whose profile names a relay is listed by that relay, and with `-r`
the relay also tells whether the source is a file or a directory. The
directories a tree needs on a target behind a relay — its profile's, or
`--via` — are created by that relay. `--dry-run` lists the same way and
creates nothing.

```
$ mpt cp -r mpt://inbox/ mpt://archive/2026/
```

Each listed directory, and each directory created, is one more SSH session
with the relay, before the copies start.

### Deleting a source the relay read

This is also what makes `--delete-source` possible over a relay, which then
moves a file rather than copying it. The relay read the source, so it knows
when every target has the file. It deletes it only when it was started with
`--allow-delete` (or `[relay] allow_delete = true`), and never when the source
is a file on the relay host itself — a client decides which files a relay
reads, not which of its own it removes. The source is on a third host then:

```toml
[profiles.inbox]
url = "sftp://collect@ingest.example.com/outgoing/report.pdf"
via = "mpt://relay"
```

```
$ mpt cp --delete-source mpt://inbox mpt://prod/
[1/1] sftp://collect@ingest.example.com/outgoing/report.pdf -> sftp://deploy@srv.example.com/data/: 40000 bytes in 14.25ms
[1/1] source deleted
```

Each of the other cases is refused before anything is read:

```
invalid option 'delete_source': this relay deletes no source; start it with --allow-delete (or [relay] allow_delete) if that is meant
invalid option 'delete_source': in/report.pdf: a file on the relay host is never deleted by a relay
```

Add a target the relay does not write, and the client is back in the path —
then nobody can say when the source is safe to remove, and the flag is
refused on this side:

```
[1/1] FAILED in/report.pdf: invalid option 'delete-source': with a relay, only when the source and every target are behind the relay that reads the source (a profile with `via`)
```

## A target behind another relay

Two relays, one job: a target whose profile names a *different* relay is
passed on to it. The relay that reads the source becomes a client of the
second relay and sends the file over the same protocol, so the bytes go from
relay to relay and never through this side:

```toml
[profiles.r1]
url = "ssh://relay@fast.example.com:2222"
[profiles.r2]
url = "ssh://relay@dc2.example.com:2222"

[profiles.incoming]                          # read by r1
url = "in/report.pdf"
via = "mpt://r1"

[profiles.prod]                              # written by r1
url = "sftp://deploy@srv.example.com/data/"
via = "mpt://r1"

[profiles.dc2]                               # written by r2, fed by r1
url = "ftp://upload@dc2-store.example/in/"
via = "mpt://r2"
```

```
$ mpt cp --hash sha256 mpt://incoming mpt://prod/ mpt://dc2/
[1/1] ok             40000 bytes     5.00ms  sftp://deploy@srv.example.com/data/
[1/1]         + sftp://deploy@srv.example.com/data/report.pdf.sha256
[1/1] ok             40000 bytes    22.00ms  ftp://upload@dc2-store.example/in/
[1/1] in/report.pdf: 40000 bytes read, 2/2 targets ok in 37.78ms
[1/1] sha256  e07113054489e8074ce8256f9c1a3aa076b57c3d76b3e7d367abc20d976e27dc
1/1 jobs ok in 38.05ms
```

The second relay's questions travel back through the first: an on-demand
password is still answered from here, and neither relay keeps it. The first
relay logs in to the second with the forwarded agent, so it needs no key of
its own, but it hands the agent on only with `--via-agent-onward`: then an
SSH target behind the second relay can log in with this side's keys too.
Without the flag such a target needs a password or a key on the second
relay. One SSH session per relay and job, and one report, in the order the
targets were named.

The first relay tells the second the file's size up front, as every client
does. When the source does not state its size (an HTTP server that sends no
`Content-Length`, say), the first relay spools the file to a temporary file
before it passes it on, and `--max-size` bounds that file as it bounds the
source.

The checksum file of a chained target is written by the relay that writes the
target, on that side; this side never places it, so the `sidecar` field of
that target's [JSON report](../automation/scripting.md#the-json-report) stays
empty while the file itself is there.

A target with no relay of its own is copied from here as usual — which takes
a source this side can read, so it does not combine with a source only a
relay can see.

