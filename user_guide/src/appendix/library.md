# Using mpt as a library

The command-line program is a thin layer over a Rust library, and everything
the CLI does is available to a program that wants to do it directly: the
protocols, the fan-out, checksums and signatures, job batches, and the two
stream utilities the pipeline is built from.

```toml
[dependencies]
mpt = { path = "…/multi_protocol_transceiver" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

The crate is `multi_protocol_transceiver` and the library is `mpt`. Everything
here is `async` and expects a Tokio runtime. Call `mpt::init_crypto()` once at
start-up: several dependencies build TLS configurations and panic if no
provider has been installed.

## One copy

```rust
mpt::init_crypto();
let src = mpt::open("sftp://deploy@srv.example.com/var/log/app.log")?;
let dst = mpt::open("s3://bucket/logs/?endpoint=https://minio.example.com")?;
let report = mpt::copy(src.as_ref(), dst.as_ref()).await?;
println!("{} bytes in {:?}", report.bytes, report.elapsed);
```

`open` parses the URL, resolves `mpt://` profile names against the installed
configuration and picks the protocol. It makes **no connection**: those happen
lazily, in the operations themselves, which is why a wrong URL fails
immediately and a wrong password does not.

## Many targets, and the options

`copy_many` is what the CLI calls. Everything `mpt cp` can do is a field of
`CopyOptions`:

```rust
let src = mpt::open("/data/export.csv")?;
let targets: Vec<Box<dyn Endpoint>> = vec![
    mpt::open("sftp://srv.example.com/incoming/")?,
    mpt::open("mailto:boss@example.com?subject=Export")?,
];
let refs: Vec<&dyn Endpoint> = targets.iter().map(|t| t.as_ref()).collect();

let opts = CopyOptions {
    cache: CacheMode::Memory { limit: 64 << 20 },
    retries: 2,
    hash: Some(mpt::HashAlgo::Sha256),
    ..Default::default()
};
let report = mpt::copy_many(src.as_ref(), &refs, &opts).await?;
for t in &report.targets {
    println!("{}: {:?} ({} bytes)", t.target, t.result, t.bytes);
}
for (algo, hex) in &report.digests {
    println!("{algo}: {hex}");
}
```

Use `..Default::default()` rather than listing every field: the struct grows,
and a default is always the conservative choice (stream rather than cache,
atomic finishing on, no checksum).

`Err` from `copy_many` means the **source** could not be read. A target that
failed is an `Err` inside its own `TargetReport`, so one target can fail
without taking the others with it.

## Cancellation and progress

A cancellation token stops a copy the way Ctrl-C does in the CLI: running
sends are dropped, part files removed, unfinished targets reported as
cancelled.

```rust
let cancel = tokio_util::sync::CancellationToken::new();
let stop = cancel.clone();
tokio::spawn(async move {
    tokio::signal::ctrl_c().await.ok();
    stop.cancel();
});
let opts = CopyOptions { cancel: Some(cancel), ..Default::default() };
```

`Progress` is a pair of atomic counters the copy fills in, so a caller can
render whatever it likes:

```rust
let progress = mpt::transfer::Progress::new();
let watch = {
    let progress = Arc::clone(&progress);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            println!("{} of {:?}", progress.read(), progress.total());
        }
    })
};
let opts = CopyOptions { progress: Some(progress), ..Default::default() };
```

`total()` is `None` until the source has been asked how large it is, and stays
`None` when it cannot say.

## Many jobs

A `Job` is one source with its targets. `batch::run` puts a list of them
through `copy_many` with a bounded number in flight:

```rust
let jobs = vec![
    mpt::Job {
        src: Location::parse("/data/a.csv")?,
        dsts: vec![Location::parse("sftp://srv.example.com/in/")?],
    },
    mpt::Job {
        src: Location::parse("/data/b.csv")?,
        dsts: vec![Location::parse("sftp://srv.example.com/in/")?],
    },
];
mpt::batch::check_collisions(&jobs)?;

let open = |loc: &Location| mpt::protocols::open(loc.clone());
let opts = mpt::BatchOptions { parallel: 4, ..Default::default() };
let report = mpt::batch::run(jobs, &open, &CopyOptions::default(), &opts, |r| {
    println!("job {}: ok={}", r.index + 1, r.ok());
}).await;
```

The `open` closure is called when a job starts rather than up front, so a list
of a hundred thousand jobs does not hold a client per endpoint in memory. The
callback fires as each job finishes, in completion order; `report.jobs` comes
back in list order.

`batch::run_stream` takes a `Stream<Item = Job>` instead of a vector, for jobs
that arrive while the batch runs. `batch::Targets` is the collision check as a
running one, for the same case.

Job lists in the three textual forms are parsed by `batch::jobs`, which does no
I/O at all:

```rust
use mpt::batch::jobs::{Format, detect, parse};
let specs = parse(text, detect(None, text))?;
```

## Working with a single endpoint

An `Endpoint` exposes a `Receiver`, a `Sender`, or both. Which of them is
`None` is how a send-only channel like e-mail needs no special casing anywhere
else:

```rust
let ep = mpt::open("sftp://srv.example.com/incoming/")?;
for entry in ep.receiver()?.list().await? {
    println!("{} {} {}", entry.name, entry.is_dir, entry.size.unwrap_or(0));
}
```

`receiver()` and `sender()` return a descriptive error for a protocol that
cannot do it; `as_receiver()` and `as_sender()` return `Option` when you would
rather decide yourself.

Sending takes a stream and a `SendMeta`, which is where the file name, the size
and the content type live:

```rust
let payload = b"generated in memory".to_vec();
let meta = SendMeta::from_filename("report.txt")?.with_size(payload.len() as u64);
let dst = mpt::open("sftp://srv.example.com/incoming/")?;
dst.sender()?.send(Box::pin(std::io::Cursor::new(payload)), &meta).await?;
```

`from_filename` normalises the name to a single safe component, so a name that
came from a remote listing cannot escape the target directory.

Data flows as `ByteStream`, which is `Pin<Box<dyn AsyncRead + Send>>`. Anything
that implements `AsyncRead` can be a source, and nothing is buffered in between
except where a protocol forces it.

## Stream utilities: `tee` and `MemoryCache`

`tee` splits one `AsyncRead` into several with backpressure — the source is
read once and paused when the slowest reader falls behind:

```rust
let (readers, driver) = mpt::tee(body, 3, TeeOptions::default());
// spawn a task per reader …
driver.await??;
```

The driver is a `JoinHandle` that does the reading; await it to find out
whether the source failed. A reader that is dropped stops holding the others
up.

`MemoryCache` reads a stream into memory once, refuses to exceed a limit, and
hands out independent readers:

```rust
let cache = mpt::MemoryCache::from_stream(body, 1 << 20).await?;
let reader = cache.reader();
```

Neither ever touches the disk.

## Configuration

A program that wants the same configuration file, profiles and credential
providers as the CLI loads it, resolves the secrets its endpoints need, and
publishes it:

```rust
let mut cfg = mpt::Config::load(None)?;
cfg.resolve_secrets(&["mpt://prod/incoming/"], false).await?;
mpt::config::install(cfg);
let ep = mpt::open("mpt://prod/incoming/")?;
```

`install` also puts the `[policy]` section into force for the process.
`resolve_secrets` takes the URLs that will actually be used, so a `cmd`
provider does not run for a profile this program never touches. Without any of
this, `mpt::open` still works — it simply has no profiles and no configured
defaults.

## The server and the relay

Both are library modules with the binary as a thin caller.

`mpt::server` (feature `server`) runs the [HTTP API](../reference/api.md).
`serve()` takes a `ServerConfig`, a `Runtime` holding the copy options every
job starts from (and, with feature `relay`, the `Via` of the profiles'
relays), and two cancellation tokens for drain and abort. `router()`
hands the routes to an axum application of your own, so the API can sit
beside other routes under one listener.

`mpt::relay` (feature `relay`) is the [relay](../server/relay.md). `run()`
is a relay over any reader and writer, `sshd::serve()` its SSH server, and
`client::send()` the sending side that `cp --via` uses: it opens the session,
writes the header and the payload, and returns the relay's report.
`plan::plan()` is the split of one job across relays — what runs from here,
what one relay uploads, what another reads itself — and `plan::merge()` puts
the parts back into a single report. `via::Via` is all of that for
`cp --via` and the profiles' relays: `Via::table()` gathers the relays in play,
and `Via::run()` copies one job through them.
`stream::ReaderEndpoint` is what makes any reader of a known size a source
for `copy_many`. `options::JobOptions` is the options object of both the API
and the relay header, with `apply()` laying it over a `CopyOptions`.

Credentials reach an endpoint through `mpt::broker`, which is what lets a
password be asked for instead of held: a `Location` may carry a
`PasswordSource` that is consulted at **every** login and an `AgentSource`
that SSH authentication signs through. The relay's side of both is
`relay::broker::RemoteBroker` (asks over the open session) and the client's
forwarded agent is `relay::agent::Responder`. Implement either trait and any
protocol in the crate uses it, no matter where the secret really comes from.

## Errors

`mpt::Error` is one enum, and the CLI's [exit
codes](../reference/exit-codes.md) are a match on it — `Auth`, `Signature`,
`ChecksumMismatch`, `InvalidUrl`, `Config`, `UnsupportedScheme`,
`UnsupportedOperation`, `Cancelled`, `Io`, `Remote`, `Transport`. A caller can
do the same rather than matching on message text; `Error::exit_code()` is
that match, and `Error::kind()` the stable name (`auth`, `io`, …) the API
puts in its error objects. `Error::is_transient()` says whether retrying
could help, and `Error::is_not_found()` whether the file was not there, on
whichever protocol.

## Features

The [cargo features](../getting-started/installation.md#choosing-protocols) are
the same as for the binary: `ssh`, `ftp`, `http`, `webdav`, `s3`, `mail`,
`sign-ssh`, `sign-pgp`, `relay` by default, and `keyring`, `vault`,
`s3-aws-auth`, `server` on request. A protocol that was not compiled in
returns `Error::UnsupportedScheme` naming the missing feature.
