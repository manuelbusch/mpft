use std::path::PathBuf;
use std::process::ExitCode;

use anstyle::{AnsiColor, Style};
use anyhow::Context;
use clap::{ColorChoice, Parser, Subcommand};
use mpt::sign::{SignSpec, VerifySpec};
use mpt::{CacheMode, CopyOptions, HashAlgo, Location, Scheme, TeeOptions};

/// Send and receive files over many protocols, addressed by URL prefix.
#[derive(Parser)]
#[command(name = "mpt", version, about, long_about = None)]
struct Cli {
    /// Verbose logging (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Disable TLS certificate verification for all endpoints
    #[arg(long, global = true)]
    insecure: bool,

    /// Colored output: auto (only on a terminal, honours NO_COLOR), always, never
    #[arg(long, global = true, default_value = "auto", value_name = "WHEN")]
    color: ColorChoice,

    /// Password for the source and target if not given in the URL
    #[arg(long, env = "MPT_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,

    /// Hold the whole payload in memory instead of streaming it (enables --retries,
    /// gives senders a known size). Never spills to disk: see --cache-limit.
    #[arg(long, global = true)]
    cache: bool,

    /// Maximum payload size for --cache, e.g. 64M or 2G. Larger inputs fail.
    #[arg(long, global = true, default_value = "256M", value_parser = parse_size)]
    cache_limit: u64,

    /// Retries per target after a failure (requires --cache). Mail targets may
    /// be delivered more than once when retried.
    #[arg(long, global = true, default_value_t = 0)]
    retries: u32,

    /// Chunk size for streaming to several targets, e.g. 64K
    #[arg(long, global = true, default_value = "64K", value_parser = parse_size)]
    chunk: u64,

    /// Chunks buffered per target before the source is paused
    #[arg(long, global = true, default_value_t = 16)]
    queue: usize,

    /// Compute a checksum while copying and write <name>.sha256|.sha512|.b3
    /// next to every target (sha256sum/b3sum format; mail gets it as attachment)
    #[arg(long, global = true, value_name = "ALGO")]
    hash: Option<HashAlgo>,

    /// Verify the content against a checksum file next to the source
    /// (<name>.b3, .sha256 or .sha512); fails if none exists or it mismatches
    #[arg(long, global = true)]
    check: bool,

    /// Sign the checksum file: `ssh` (ssh-agent or default key), `ssh:<key>`
    /// or `pgp:<secret-key.asc>`; passphrase via MPT_SIGN_KEY_PASSPHRASE.
    /// Implies --hash sha256 unless --hash is given.
    #[arg(long, global = true, value_name = "SPEC")]
    sign: Option<SignSpec>,

    /// With --check: require an OpenSSH signature (<name>.<ext>.sig) made by
    /// a key in this allowed_signers file. Implies --check.
    #[arg(
        long,
        global = true,
        value_name = "FILE",
        conflicts_with = "verify_keyring"
    )]
    verify_signers: Option<PathBuf>,

    /// With --check: require an OpenPGP signature (<name>.<ext>.asc) made by
    /// a key in this armored keyring file. Implies --check.
    #[arg(long, global = true, value_name = "FILE")]
    verify_keyring: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Copy from one URL to one or more targets (the source is read once)
    Copy {
        src: String,
        #[arg(required = true, num_args = 1..)]
        dst: Vec<String>,
    },
    /// List a directory
    Ls { url: String },
    /// Send a local file to one or more targets (shorthand for copy)
    Send {
        file: PathBuf,
        #[arg(required = true, num_args = 1..)]
        dst: Vec<String>,
    },
    /// Receive a URL into a local path (default: current directory)
    Recv { src: String, dst: Option<PathBuf> },
    /// Show supported URL schemes and their options
    Schemes,
}

// Styles used for terminal output. Codes are stripped automatically by
// `anstream` when the stream is not a terminal (or `--color never`).
const OK: Style = AnsiColor::Green.on_default().bold();
const FAIL: Style = AnsiColor::Red.on_default().bold();
const WARN: Style = AnsiColor::Yellow.on_default().bold();
const NUM: Style = AnsiColor::Cyan.on_default();
const DIR: Style = AnsiColor::Blue.on_default().bold();
const HEAD: Style = Style::new().bold();
const DIM: Style = Style::new().dimmed();

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_colors(cli.color);
    init_logging(cli.verbose);
    mpt::init_crypto();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            anstream::eprintln!("{FAIL}error:{FAIL:#} {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn init_colors(choice: ColorChoice) {
    let global = match choice {
        ColorChoice::Auto => anstream::ColorChoice::Auto,
        ColorChoice::Always => anstream::ColorChoice::Always,
        ColorChoice::Never => anstream::ColorChoice::Never,
    };
    global.write_global();
}

/// Whether colored output will actually reach stderr (for tracing's ANSI setting).
fn stderr_is_colored() -> bool {
    anstream::AutoStream::choice(&std::io::stderr()) != anstream::ColorChoice::Never
}

fn init_logging(verbosity: u8) {
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(stderr_is_colored())
        .init();
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let open = |url: &str| -> anyhow::Result<Box<dyn mpt::Endpoint>> {
        let mut loc = Location::parse(url)?;
        if cli.insecure {
            loc.set_option("insecure", "true");
        }
        if let Some(pw) = &cli.password
            && loc.password().is_none()
            && loc.scheme() != Scheme::File
        {
            loc.set_password(pw.clone());
        }
        Ok(mpt::protocols::open(loc)?)
    };

    let opts = CopyOptions {
        cache: if cli.cache {
            CacheMode::Memory {
                limit: cli.cache_limit,
            }
        } else {
            CacheMode::Stream
        },
        retries: cli.retries,
        tee: TeeOptions {
            chunk_size: cli.chunk as usize,
            capacity: cli.queue,
        },
        hash: cli.hash.or(cli.sign.as_ref().map(|_| HashAlgo::Sha256)),
        check: cli.check || cli.verify_signers.is_some() || cli.verify_keyring.is_some(),
        sign: match &cli.sign {
            Some(spec) => Some(mpt::sign::load_signer(spec).await?),
            None => None,
        },
        verify: match (&cli.verify_signers, &cli.verify_keyring) {
            (Some(p), _) => Some(mpt::sign::load_verifier(&VerifySpec::SshAllowedSigners(
                p.clone(),
            ))?),
            (_, Some(p)) => Some(mpt::sign::load_verifier(&VerifySpec::PgpKeyring(
                p.clone(),
            ))?),
            _ => None,
        },
    };
    if let Some(s) = &opts.sign {
        tracing::info!(signer = %s.identity(), "signing checksum files");
    }

    match &cli.cmd {
        Cmd::Copy { src, dst } => {
            let targets = dst
                .iter()
                .map(|d| open(d))
                .collect::<anyhow::Result<Vec<_>>>()?;
            do_copy(open(src)?, targets, &opts).await
        }
        Cmd::Send { file, dst } => {
            let targets = dst
                .iter()
                .map(|d| open(d))
                .collect::<anyhow::Result<Vec<_>>>()?;
            do_copy(open(&file.to_string_lossy())?, targets, &opts).await
        }
        Cmd::Recv { src, dst } => {
            let target = match dst {
                Some(p) => p.to_string_lossy().into_owned(),
                None => "./".to_string(),
            };
            do_copy(open(src)?, vec![open(&target)?], &opts).await
        }
        Cmd::Ls { url } => {
            let ep = open(url)?;
            let entries = ep
                .receiver()?
                .list()
                .await
                .with_context(|| format!("listing {}", ep.location()))?;
            for e in entries {
                let kind = if e.is_dir { "d" } else { "-" };
                let size = e.size.map(|s| s.to_string()).unwrap_or_else(|| "-".into());
                let name_style = if e.is_dir { DIR } else { Style::new() };
                anstream::println!(
                    "{DIM}{kind}{DIM:#} {NUM}{size:>12}{NUM:#}  {name_style}{}{name_style:#}",
                    e.name
                );
            }
            Ok(())
        }
        Cmd::Schemes => {
            anstream::println!(
                "{HEAD}{:<11} {:<5} {:<5} {:<7} {:<9} options{HEAD:#}",
                "prefix",
                "recv",
                "send",
                "port",
                "feature"
            );
            for i in Scheme::ALL {
                let yn = |b: bool| {
                    if b {
                        format!("{OK}{:<5}{OK:#}", "yes")
                    } else {
                        format!("{FAIL}{:<5}{FAIL:#}", "no")
                    }
                };
                let port = i
                    .default_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into());
                anstream::println!(
                    "{HEAD}{:<11}{HEAD:#} {} {} {:<7} {:<9} {DIM}{}{DIM:#}",
                    i.prefix,
                    yn(i.can_receive),
                    yn(i.can_send),
                    port,
                    i.feature,
                    i.options
                );
                anstream::println!("{:<11} {}", "", i.description);
            }
            anstream::println!(
                "\n{HEAD}Credentials:{HEAD:#} user[:password]@ in the URL, else MPT_PASSWORD / MPT_SMTP_PASSWORD."
            );
            anstream::println!(
                "{HEAD}SSH keys:{HEAD:#} MPT_SSH_KEY, else ssh-agent (SSH_AUTH_SOCK), else ~/.ssh/id_ed25519, id_rsa."
            );
            anstream::println!(
                "{HEAD}Mail:{HEAD:#} MPT_SMTP_URL (for mailto:), MPT_MAIL_FROM.  {HEAD}S3:{HEAD:#} AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_ENDPOINT_URL."
            );
            Ok(())
        }
    }
}

async fn do_copy(
    src: Box<dyn mpt::Endpoint>,
    targets: Vec<Box<dyn mpt::Endpoint>>,
    opts: &CopyOptions,
) -> anyhow::Result<()> {
    let refs: Vec<&dyn mpt::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let report = mpt::copy_many(src.as_ref(), &refs, opts)
        .await
        .with_context(|| format!("copy {}", src.location()))?;
    if report.targets.len() == 1 {
        let t = &report.targets[0];
        if let Err(e) = &t.result {
            anyhow::bail!("copy {} -> {}: {e}", report.source, t.target);
        }
        anstream::eprintln!(
            "{DIM}{}{DIM:#} -> {DIM}{}{DIM:#}: {NUM}{}{NUM:#} bytes in {NUM}{:.2?}{NUM:#}",
            report.source,
            t.target,
            t.bytes,
            report.elapsed
        );
        if let Some(sc) = &t.sidecar {
            anstream::eprintln!("{DIM}+ {sc}{DIM:#}");
        }
        if let Some(sg) = &t.signature {
            anstream::eprintln!("{DIM}+ {sg}{DIM:#}");
        }
        return print_checksums(&report, opts);
    }
    for t in &report.targets {
        match &t.result {
            Ok(()) => {
                anstream::eprintln!(
                    "{OK}ok    {OK:#}  {NUM}{:>12}{NUM:#} bytes  {NUM}{:>9.2?}{NUM:#}  {DIM}{}{DIM:#}",
                    t.bytes,
                    t.elapsed,
                    t.target
                );
                if let Some(sc) = &t.sidecar {
                    anstream::eprintln!("{DIM}        + {sc}{DIM:#}");
                }
                if let Some(sg) = &t.signature {
                    anstream::eprintln!("{DIM}        + {sg}{DIM:#}");
                }
            }
            Err(e) => anstream::eprintln!(
                "{FAIL}FAILED{FAIL:#}  {NUM}{:>12}{NUM:#} bytes  {NUM}{:>9.2?}{NUM:#}  {DIM}{}{DIM:#}: {FAIL}{e}{FAIL:#}",
                t.bytes,
                t.elapsed,
                t.target
            ),
        }
    }
    let failed = report.failures().count();
    let summary = if failed == 0 { OK } else { WARN };
    anstream::eprintln!(
        "{DIM}{}{DIM:#}: {NUM}{}{NUM:#} bytes read, {summary}{}/{} targets ok{summary:#} in {NUM}{:.2?}{NUM:#}",
        report.source,
        report.bytes_read,
        report.targets.len() - failed,
        report.targets.len(),
        report.elapsed
    );
    print_checksums(&report, opts)?;
    if failed > 0 {
        anyhow::bail!("{failed} of {} targets failed", report.targets.len());
    }
    Ok(())
}

/// Print computed digests and the `--check` verdict; a mismatch is an error.
fn print_checksums(report: &mpt::FanoutReport, opts: &CopyOptions) -> anyhow::Result<()> {
    for (algo, hex) in &report.digests {
        anstream::eprintln!("{HEAD}{:<7}{HEAD:#} {NUM}{hex}{NUM:#}", algo.to_string());
    }
    if let Some(s) = &opts.sign
        && report
            .targets
            .iter()
            .any(|t| t.signature.is_some() || t.result.is_ok())
    {
        anstream::eprintln!(
            "{HEAD}signed {HEAD:#} {DIM}{} ({}){DIM:#}",
            s.identity(),
            s.format().label()
        );
    }
    if let Some(c) = &report.checked {
        if let Some(who) = &c.signer {
            anstream::eprintln!("{OK}signature ok{OK:#} {DIM}{who}{DIM:#}");
        }
        if c.ok() {
            anstream::eprintln!("{OK}check ok{OK:#} ({})", c.algo.label());
        } else {
            anstream::eprintln!(
                "{FAIL}CHECK FAILED{FAIL:#} ({}): expected {NUM}{}{NUM:#}, got {NUM}{}{NUM:#}",
                c.algo.label(),
                c.expected,
                c.actual
            );
            return Err(c.error().into());
        }
    }
    Ok(())
}

/// Parse sizes like `512`, `64K`, `256M`, `2G` (binary units).
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last().map(|c| c.to_ascii_uppercase()) {
        Some('K') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') => (&s[..s.len() - 1], 1u64 << 20),
        Some('G') => (&s[..s.len() - 1], 1u64 << 30),
        _ => (s, 1),
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n * mult)
        .map_err(|e| format!("invalid size '{s}': {e}"))
}
