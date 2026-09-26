# Compatibility and stability

What a script, a job list or a client can rely on from one version of `mpt` to
the next, and what may change without notice.

## Versions

`mpt` is at 0.1. While the major version is 0, a minor release (0.1 → 0.2)
may change behaviour that the list below does not cover, and the change is
noted in the release notes; a patch release (0.1.0 → 0.1.1) does not. The
version is `mpt --version`, and the guide states which version it describes on
its [first page](../introduction.md).

## What stays stable

| Interface | What is kept |
|---|---|
| **exit codes** | the meaning of 0, 1, 2, 3, 4 and 130 as [Exit codes](exit-codes.md) lists them; a new code would be added, not a meaning changed |
| **the JSON report** | every field on [The JSON report](../automation/scripting.md#the-json-report) keeps its name and type; fields are added, not renamed or removed; a consumer should ignore fields it does not know |
| **job lists** | the line, JSON Lines and CSV forms; an unknown JSON field stays an error |
| **configuration keys** | a key keeps its name and meaning; a removed key would first be accepted with a warning for a release |
| **URL options** | the options each protocol page lists; an unknown option is ignored, as it is today |
| **environment variables** | the names on [Environment variables](environment.md) |
| **the HTTP API** | every route under `/v1/`, the job and transfer objects, the WebSocket events and the error kinds; a change that breaks a client would come under `/v2/` |
| **the relay protocol** | versions 1, 2 and 3 as [Relay protocol](relay-protocol.md) describes them; a relay keeps accepting all of them; a header without `v` means the newest version the relay speaks |
| **checksum and signature files** | `<name>.sha256`, `.sha512`, `.b3`, `.sig`, `.asc` in the formats `sha256sum`, `b3sum`, `ssh-keygen -Y` and `gpg` read |
| **the library** | the crate follows Cargo's semantic versioning; the CLI's exit codes are `Error::exit_code()` and the API's kinds `Error::kind()` |

## What may change

- **Log lines**: the text, the fields and the order of the lines at every
  level. Parse the report, not the log; the message texts of warnings and
  errors are kept, their surroundings are not.
- **The human-readable output**: result lines, summaries, the progress
  display, colour. Scripts read `--json` and the exit code.
- **The order of output in a batch**: jobs finish in whatever order they
  finish.
- **Defaults**: a default may change in a minor release when the safer
  choice was not the default; `[defaults]` pins a value for a machine.
- **Timing**: retries, backoff and the exact moment a timeout fires.

## Deprecation

A flag or key that is going away first stays for at least one minor release,
does what it did, and prints a warning naming its replacement. `--insecure`
is in that state: it works, warns, and `?insecure=true` on the one URL that
needs it is the replacement. Nothing is removed without having warned first.

## Between a client and a server, or a relay

The two sides of the HTTP API or the relay protocol may run different
versions. A newer client against an older server gets an error for a route
or a field the server does not know, never silent acceptance; a newer relay
takes an older client's version 1 header as it always did, and an older
relay tells a newer client which version it speaks. Upgrade the relay and the
server first, then the clients.
