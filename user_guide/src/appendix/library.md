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

`..Default::default()` is worth using rather than listing every field: the
struct grows, and a default is always the conservative choice (stream rather
than cache, atomic finishing on, no checksum).

`Err` from `copy_many` means the **source** could not be read. A target that
failed is an `Err` inside its own `TargetReport`, which is what lets one target
fail without taking the others with it.

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

## Errors

`mpt::Error` is one enum, and the CLI's [exit
codes](../reference/exit-codes.md) are a match on it — `Auth`, `Signature`,
`ChecksumMismatch`, `InvalidUrl`, `Config`, `UnsupportedScheme`,
`UnsupportedOperation`, `Cancelled`, `Io`, `Remote`, `Transport`. A caller can
do the same rather than matching on message text. `Error::is_transient()` says
whether retrying could help.

## Features

The [cargo features](../getting-started/installation.md#choosing-protocols) are
the same as for the binary: `ssh`, `ftp`, `http`, `webdav`, `s3`, `mail`,
`sign-ssh`, `sign-pgp` by default, and `keyring`, `vault`, `s3-aws-auth` on
request. A protocol that was not compiled in returns
`Error::UnsupportedScheme` naming the missing feature.
