# Relay protocol

What passes over the SSH channel between `cp --via` and `mpt relay`, or over
the standard input and output of `mpt relay` run directly. A session is a copy
or, from version 3 on, one of the [operations besides the
copy](#operations-besides-the-copy): a listing, a size, directories created.

## The header

The client writes one JSON line, at most 64 KiB, within 30 seconds of the
start; a relay that has no complete line by then refuses the session:

```json
{"v": 2, "name": "report.pdf", "size": 40000,
 "dst": ["sftp://deploy:pw@srv.example.com/in/", {"url": "ftp://upload@dc2.example/in/", "via": "ssh://relay@dc2.example:2222/"}],
 "credentials": "header", "agent": false,
 "options": {"hash": "sha256"}}
```

| Field | Meaning |
|---|---|
| `v` | protocol version, `1`, `2` or `3`; **`3` when the field is absent** |
| `op` | `"copy"` (the default), `"list"`, `"size"` or `"mkdir"` (v3) |
| `src` | a URL the relay opens and reads itself, instead of a payload (v2); what a listing or a size is about |
| `name` | the file name the targets receive; required when there is no `src` |
| `size` | how many payload bytes follow; required when there is no `src` |
| `dst` | the targets of a copy, or the directories of a `mkdir`: a URL string, or `{"url": …, "via": …}` for one the relay hands on to a second relay (v2); `dsts` is accepted as another name for it |
| `credentials` | `"header"` (the default) or `"on-demand"` (v2) |
| `agent` | `true` when the client forwards an ssh-agent for the SSH endpoints (v2) |
| `agent_onward` | `true` lets the relay forward that agent on to the relays of chained targets; otherwise it only logs in to them with it (v2) |
| `options` | the [job options](api.md#job-options) the relay honours; may be omitted |

A client sends `"v": 2` for a copy, which needs nothing of version 3, so a
relay of an older release still takes it, and `"v": 3` for the other
operations.

Everything is checked before a byte of the payload is read: the version, that
there is either a `src` or a `name` with a `size`, that `dst` is not empty,
that the credential modes of both sides match, that no endpoint brings a
password along when `credentials` is `on-demand` (in its URL, or from a
profile of the relay's own), and `size` or the source's size against
`--max-size`. A source that does not state its size is held to `--max-size`
as it is read, and fails its targets once it passes it.

## The payload

In version 2 the payload follows the header as frames:

| Bytes | Meaning |
|---|---|
| 1 | kind: `0x01` payload, `0x02` control |
| 4 | length, big-endian `u32` |
| *length* | the bytes, at most 1 MiB for payload and 64 KiB for control |

A payload frame of length 0 is allowed and carries nothing; the payload ends
after `size` bytes, not at an empty frame.

A control frame is a JSON object. The only one a relay acts on is the answer
to a question of its own:

```
{"password": {"id": 7, "value": "…"}}    the password
{"password": {"id": 7}}                  there is none; the target does without
{"password": {"id": 7, "error": "…"}}    the client cannot supply one; the login fails
```

Control frames are not counted against the credit and are written ahead of
queued payload, so an answer never waits behind the file. Anything else in a
control frame is ignored, and logged without its content.

A frame the relay cannot take ends the session: a copy still running is
cancelled, and the session's outcome is an `invalid_option` error (exit 2).
That is the case for an unknown kind, a length beyond
the limit, a control frame that is not JSON, the input ending inside a frame,
payload beyond the credit, or any payload when the relay reads the source
itself. The header is as strict: a field it does not know, in the header or
in a `{"url": …, "via": …}` target, refuses it.

In version 1 the payload is exactly `size` raw bytes after the header, with no
frames, no questions, no `src` and no chained targets.

## Lines from the relay

The relay writes JSON lines to its standard output, each at most 1 MiB; `cp
--via` ends the session on a longer one:

```
{"progress": {"read": 12345, "total": 40000}}   four times a second while bytes move
{"credit": 1048576}                              this many more payload bytes may be sent (v2)
{"need": "password", "id": 7, "dst": 0, "target": "ftp://upload@dc2.example/in/", "user": "upload", "attempt": 1}
{"entry": {"name": "a.csv", "size": 3, "is_dir": false, "modified": "2026-09-01T10:00:00Z"}}   one entry of a listing (v3)
{"listed": {"entries": 12}}                      the end of a listing (v3)
{"size": 40000}                                  the answer to a size, null when there is none (v3)
{"made": {"dirs": 1}}                            the directories of a mkdir exist (v3)
{"report": { … }}                                the object --json prints, at the end
{"error": {"kind": "…", "message": "…"}}         instead of a report, when the relay refused or could not read
```

An `error` of kind `io` may add `"io": "not_found"` or
`"io": "permission_denied"`, so that a missing file or a refusal comes back to
the client as that, and is treated as it would be without the relay.

A `need` line names the endpoint it is about by position, never by URL:
`"dst": <index>` for a target of the header, `"src": true` for the source, or
`"via": <index>` for the relay a target is reached through. `attempt` counts
the logins for that endpoint. The client answers with a control frame of the
same `id`; a relay that gets no answer within the target's timeout fails that
target with `no password from the client within Ns`.

The credit starts at 4 MiB and is topped up in steps of 1 MiB as the copy
consumes what arrived. A client that sends more than it was granted ends the
session, as a malformed frame does.

Its exit status is the [exit code](exit-codes.md) `cp` would have given for
the same fan-out. A relay that refuses the header (`invalid_option`, or
`size` beyond `--max-size`) does so before reading any of the payload.

## Chained targets

A `dst` entry of the form `{"url": …, "via": …}` tells the relay to write that
target through a second relay: it opens an SSH session of its own, sends the
same protocol with a one-target header, and reports what comes back as that
target's result. Questions from the second relay about its one target
(`"dst": 0`) reach the client through the first, translated to the original
target's index; any other question from it is refused without reaching the
client, since its header names nothing else. The relay logs in to the
second relay with a forwarded agent, and forwards the agent on only when the
header says `agent_onward`. See [A target behind another
relay](../server/relay-topologies.md#a-target-behind-another-relay).

## Operations besides the copy

From version 3 on, `op` asks for something other than a copy. That is how the
client reads and prepares what only the relay reaches: `mpt ls`, and the
expansion of patterns and trees, for an endpoint whose profile names a relay.

| `op` | About | The relay | The last line |
|---|---|---|---|
| `"list"` | `src` | lists the directory, an `entry` line per entry in the shape of `ls --json` | `{"listed": {"entries": n}}` |
| `"size"` | `src` | tells its size: `null` for a directory, for a size the protocol does not tell, or for nothing there | `{"size": n}` |
| `"mkdir"` | `dst` | creates each directory with its parents; a target without directories to create is an `unsupported_operation` | `{"made": {"dirs": n}}` |

```json
{"v": 3, "op": "list", "src": "sftp://deploy@srv.example.com/in/", "options": {"timeout": 30}}
```

The relay opens the endpoints by the rules of a copy: its own profiles, the
credential mode, `need` lines (`"src": true`, or `"dst": <index>` for a
`mkdir`), the forwarded agent. An operation has no `name` or `size`, no
`agent_onward`, no chained target, no `dst` when it is about `src` and no
`src` when it is about `dst`, and no option but `timeout`; any of them refuses
the header. The client sends no payload frames, only control frames with
answers, and keeps its input open until the relay is done: its end cancels the
operation.

The relay exits with 0 after the last line. One that fails ends with an
`error` line instead, and the exit code of the failure. A relay of an older
release refuses the header (`op` is a field it does not know, or `3` a version
it does not speak), which the client reports as a relay too old for the
operation.
