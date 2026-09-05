use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

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

    /// Disable TLS certificate verification for all endpoints. Deprecated:
    /// use ?insecure=true on the one URL that needs it.
    #[arg(long, global = true)]
    insecure: bool,

    /// Configuration file (default: $MPT_CONFIG, else ~/.config/mpt/config.toml,
    /// plus ./mpt.toml for [defaults] and [policy])
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Colored output: auto (only on a terminal, honours NO_COLOR), always, never
    #[arg(long, global = true, value_name = "WHEN")]
    color: Option<ColorChoice>,

    /// Password for the source and target if not given in the URL. A password
    /// in the URL or in argv is visible to every other process; prefer
    /// MPT_PASSWORD, --password-file or --password-stdin.
    #[arg(long, env = "MPT_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,

    /// Read the password from this file (first line, no trailing newline)
    #[arg(long, global = true, value_name = "PATH", conflicts_with = "password")]
    password_file: Option<PathBuf>,

    /// Read the password from standard input (first line)
    #[arg(
        long,
        global = true,
        conflicts_with = "password",
        conflicts_with = "password_file"
    )]
    password_stdin: bool,

    /// Refuse instead of warning when credentials would go over the wire
    /// unencrypted (ftp://, http:// basic auth, smtp without TLS). Also
    /// settable with MPT_REFUSE_PLAINTEXT_AUTH=1.
    #[arg(long, global = true)]
    refuse_plaintext_auth: bool,

    /// Hold the whole payload in memory instead of streaming it (enables --retries,
    /// gives senders a known size). Never spills to disk: see --cache-limit.
    #[arg(long, global = true)]
    cache: bool,

    /// Maximum payload size for --cache, e.g. 64M or 2G. Larger inputs fail.
    #[arg(long, global = true, value_name = "SIZE", value_parser = parse_size)]
    cache_limit: Option<u64>,

    /// Retries per target after a failure (requires --cache for the payload;
    /// connecting and logging in are retried without it). Mail targets may be
    /// delivered more than once when retried.
    #[arg(long, global = true, value_name = "N")]
    retries: Option<u32>,

    /// Chunk size for streaming to several targets, e.g. 64K
    #[arg(long, global = true, value_name = "SIZE", value_parser = parse_size)]
    chunk: Option<u64>,

    /// Chunks buffered per target before the source is paused
    #[arg(long, global = true, value_name = "N")]
    queue: Option<usize>,

    /// Inactivity timeout in seconds for every connection and stream, and for
    /// a target that stops accepting data. 0 disables it. Per URL: ?timeout=
    #[arg(long, global = true, value_name = "SECONDS")]
    timeout: Option<u64>,

    /// Write straight to the target name instead of uploading to
    /// <name>.mpt-part and renaming it into place when the transfer is done
    #[arg(long, global = true)]
    no_atomic: bool,

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
    /// Without a key part, [signing] key from the configuration is used.
    /// Implies --hash sha256 unless --hash is given.
    #[arg(long, global = true, value_name = "SPEC")]
    sign: Option<String>,

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
    #[command(alias = "copy")]
    Cp {
        src: String,
        #[arg(required = true, num_args = 1..)]
        dst: Vec<String>,
    },
    /// List a directory
    Ls { url: String },
    /// Show supported URL schemes and their options
    Schemes,
    /// Inspect the configuration file
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Read the configuration, report unknown keys and print what it sets
    Check,
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

/// The effective values of the flags that `[defaults]` can preset:
/// command line first, then the configuration file, then the built-in value.
#[derive(Debug)]
struct Settings {
    color: ColorChoice,
    log: Option<String>,
    cache: bool,
    cache_limit: u64,
    retries: u32,
    chunk: u64,
    queue: usize,
    timeout: u64,
    atomic: bool,
    hash: Option<HashAlgo>,
}

impl Settings {
    fn resolve(cli: &Cli, cfg: &mpt::Config) -> anyhow::Result<Settings> {
        let d = &cfg.defaults;
        let size = |v: &Option<String>, what: &str| -> anyhow::Result<Option<u64>> {
            match v {
                None => Ok(None),
                Some(v) => Some(mpt::config::parse_size(v))
                    .transpose()
                    .map_err(|e| anyhow::anyhow!("[defaults] {what}: {e}")),
            }
        };
        Ok(Settings {
            color: match &d.color {
                _ if cli.color.is_some() => cli.color.unwrap(),
                Some(v) => v
                    .parse::<ColorChoice>()
                    .map_err(|e| anyhow::anyhow!("[defaults] color: {e}"))?,
                None => ColorChoice::Auto,
            },
            log: d.log.clone(),
            cache: cli.cache || d.cache.unwrap_or(false),
            cache_limit: cli
                .cache_limit
                .or(size(&d.cache_limit, "cache_limit")?)
                .unwrap_or(256 << 20),
            retries: cli.retries.or(d.retries).unwrap_or(0),
            chunk: cli.chunk.or(size(&d.chunk, "chunk")?).unwrap_or(64 << 10),
            queue: cli.queue.or(d.queue).unwrap_or(16),
            timeout: cli.timeout.or(d.timeout).unwrap_or(30),
            // --no-atomic and `atomic = false` both switch it off.
            atomic: !cli.no_atomic && d.atomic.unwrap_or(true),
            hash: match &d.hash {
                _ if cli.hash.is_some() => cli.hash,
                Some(v) => {
                    Some(HashAlgo::parse(v).map_err(|e| anyhow::anyhow!("[defaults] hash: {e}"))?)
                }
                None => None,
            },
        })
    }
}

/// Marks a run that was stopped with Ctrl-C, so `main` can exit with 130.
#[derive(Debug)]
struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interrupted")
    }
}

impl std::error::Error for Interrupted {}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    // The configuration decides the log level and the colors, so it is read
    // before either is set up; its own complaints are logged afterwards.
    let cfg = match mpt::Config::load(cli.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let settings = match Settings::resolve(&cli, &cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    init_colors(settings.color);
    init_logging(cli.verbose, settings.log.as_deref());
    for w in &cfg.warnings {
        tracing::warn!("{w}");
    }
    for path in &cfg.sources {
        tracing::debug!(path = %path.display(), "configuration in use");
    }
    mpt::config::install(cfg);
    mpt::init_crypto();
    match run(cli, settings).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            anstream::eprintln!("{FAIL}error:{FAIL:#} {e:#}");
            // 130 is the conventional "terminated by Ctrl-C".
            if e.chain().any(|c| c.is::<Interrupted>()) {
                ExitCode::from(130)
            } else {
                ExitCode::FAILURE
            }
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

fn init_logging(verbosity: u8, configured: Option<&str>) {
    let level = match verbosity {
        0 => configured.unwrap_or("warn"),
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

/// Read a password from a file or from standard input, without keeping the
/// trailing newline an editor or `echo` leaves behind.
fn read_password(cli: &Cli) -> anyhow::Result<Option<secrecy::SecretString>> {
    if let Some(path) = &cli.password_file {
        warn_if_world_readable(path);
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading the password from {}", path.display()))?;
        return Ok(Some(first_line(&text).into()));
    }
    if cli.password_stdin {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
            .context("reading the password from stdin")?;
        return Ok(Some(first_line(&text).into()));
    }
    Ok(cli.password.clone().map(secrecy::SecretString::from))
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

/// A password file that others can read is a password everyone has.
fn warn_if_world_readable(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path) {
            let mode = md.permissions().mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    "{} is readable by others (mode {:o}); chmod 600 it",
                    path.display(),
                    md.permissions().mode() & 0o777
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

async fn run(cli: Cli, settings: Settings) -> anyhow::Result<()> {
    if cli.refuse_plaintext_auth {
        mpt::policy::set_refuse_plaintext_auth(true);
    }
    if cli.insecure {
        tracing::warn!(
            "--insecure disables certificate checks for every endpoint and is deprecated; \
             put ?insecure=true on the URL that needs it"
        );
    }
    let password = read_password(&cli)?;
    let timeout = (settings.timeout > 0).then(|| Duration::from_secs(settings.timeout));
    // Ctrl-C stops the transfer, removes partial files and leaves the rest alone.
    let cancel = tokio_util::sync::CancellationToken::new();
    {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                anstream::eprintln!("{WARN}interrupted{WARN:#}, stopping and cleaning up…");
                cancel.cancel();
            }
        });
    }
    let open = |url: &str| -> anyhow::Result<Box<dyn mpt::Endpoint>> {
        let mut loc = Location::parse(url)?;
        if cli.insecure {
            loc.set_option("insecure", "true");
        }
        // --timeout is the default; ?timeout= in the URL wins.
        if loc.opt("timeout").is_none() {
            loc.set_option("timeout", settings.timeout.to_string());
        }
        if settings.retries > 0 && loc.opt("connect_retries").is_none() {
            loc.set_option("connect_retries", settings.retries.to_string());
        }
        if let Some(pw) = &password
            && loc.password().is_none()
            && loc.scheme() != Scheme::File
        {
            use secrecy::ExposeSecret;
            loc.set_password(pw.expose_secret());
        }
        Ok(mpt::protocols::open(loc)?)
    };

    let sign = match &cli.sign {
        Some(spec) => Some(sign_spec(spec)?),
        None => None,
    };
    let verify = verify_spec(&cli)?;
    let check = cli.check || verify.is_some();
    if check && verify.is_none() && mpt::policy::policy().require_signature {
        anyhow::bail!(
            "policy.require_signature is set, but no trusted keys are given: \
             use --verify-signers/--verify-keyring or [verify] in the configuration"
        );
    }
    let opts = CopyOptions {
        cache: if settings.cache {
            CacheMode::Memory {
                limit: settings.cache_limit,
            }
        } else {
            CacheMode::Stream
        },
        retries: settings.retries,
        tee: TeeOptions {
            chunk_size: settings.chunk as usize,
            capacity: settings.queue,
            send_timeout: timeout,
        },
        atomic: settings.atomic,
        cancel: Some(cancel.clone()),
        hash: settings.hash.or(sign.as_ref().map(|_| HashAlgo::Sha256)),
        check,
        sign: match &sign {
            Some(spec) => Some(mpt::sign::load_signer(spec).await?),
            None => None,
        },
        verify: match &verify {
            Some(spec) => Some(mpt::sign::load_verifier(spec)?),
            None => None,
        },
    };
    if let Some(s) = &opts.sign {
        tracing::info!(signer = %s.identity(), "signing checksum files");
    }

    match &cli.cmd {
        Cmd::Cp { src, dst } => {
            let targets = dst
                .iter()
                .map(|d| open(d))
                .collect::<anyhow::Result<Vec<_>>>()?;
            do_copy(open(src)?, targets, &opts).await
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
        Cmd::Config { action } => {
            let ConfigCmd::Check = action;
            show_config(mpt::config::global());
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
    let cancelled = report
        .targets
        .iter()
        .any(|t| matches!(t.result, Err(mpt::Error::Cancelled)));
    if report.targets.len() == 1 {
        let t = &report.targets[0];
        if let Err(e) = &t.result {
            if cancelled {
                return Err(anyhow::Error::new(Interrupted));
            }
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
    if cancelled {
        return Err(anyhow::Error::new(Interrupted).context(format!(
            "{failed} of {} targets unfinished",
            report.targets.len()
        )));
    }
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
    mpt::config::parse_size(s)
}

/// The signing key: the `--sign` value, with the key file from `[signing] key`
/// filled in when the flag only names a format (`--sign ssh`).
fn sign_spec(raw: &str) -> anyhow::Result<SignSpec> {
    let mut raw = raw.to_string();
    if !raw.contains(':')
        && let Some((fmt, key)) = mpt::config::global()
            .signing
            .key
            .as_deref()
            .and_then(|c| c.split_once(':'))
        && mpt::SignFormat::parse(fmt).ok() == mpt::SignFormat::parse(&raw).ok()
    {
        raw = format!("{raw}:{}", mpt::config::expand_tilde(key));
    }
    Ok(SignSpec::parse(&raw)?)
}

/// The trusted keys for `--check`: the flags, else the `[verify]` section.
fn verify_spec(cli: &Cli) -> anyhow::Result<Option<VerifySpec>> {
    if let Some(p) = &cli.verify_signers {
        return Ok(Some(VerifySpec::SshAllowedSigners(p.clone())));
    }
    if let Some(p) = &cli.verify_keyring {
        return Ok(Some(VerifySpec::PgpKeyring(p.clone())));
    }
    if !cli.check {
        return Ok(None);
    }
    let v = &mpt::config::global().verify;
    Ok(
        match (
            mpt::config::path(&v.allowed_signers),
            mpt::config::path(&v.keyring),
        ) {
            (Some(p), _) => Some(VerifySpec::SshAllowedSigners(p)),
            (_, Some(p)) => Some(VerifySpec::PgpKeyring(p)),
            _ => None,
        },
    )
}

/// `mpt config check`: where the configuration came from and what it sets.
/// Reaching this point already means it parsed and every key is known.
fn show_config(cfg: &mpt::Config) {
    if cfg.sources.is_empty() {
        anstream::println!(
            "{WARN}no configuration file{WARN:#} (looked for {})",
            mpt::config::Config::default_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "~/.config/mpt/config.toml".into())
        );
    } else {
        for p in &cfg.sources {
            anstream::println!("{OK}ok{OK:#} {}", p.display());
        }
    }
    for w in &cfg.warnings {
        anstream::println!("{WARN}warning{WARN:#} {w}");
    }

    let mut rows: Vec<(String, String)> = Vec::new();
    macro_rules! rows {
        ($($section:literal . $field:ident = $value:expr),* $(,)?) => {
            $(if let Some(v) = &$value {
                rows.push((format!("[{}] {}", $section, stringify!($field)), v.to_string()));
            })*
        };
    }
    let (d, p) = (&cfg.defaults, &cfg.policy);
    rows!(
        "defaults".color = d.color,
        "defaults".hash = d.hash,
        "defaults".cache = d.cache,
        "defaults".cache_limit = d.cache_limit,
        "defaults".retries = d.retries,
        "defaults".chunk = d.chunk,
        "defaults".queue = d.queue,
        "defaults".timeout = d.timeout,
        "defaults".atomic = d.atomic,
        "defaults".log = d.log,
        "policy".known_hosts = p.known_hosts,
        "policy".refuse_plaintext_auth = p.refuse_plaintext_auth,
        "policy".refuse_insecure_tls = p.refuse_insecure_tls,
        "policy".require_signature = p.require_signature,
        "signing".key = cfg.signing.key,
        "signing".agent_fingerprint = cfg.signing.agent_fingerprint,
        "verify".allowed_signers = cfg.verify.allowed_signers,
        "verify".keyring = cfg.verify.keyring,
        "ssh".user = cfg.ssh.user,
        "ssh".key = cfg.ssh.key,
        "ssh".known_hosts_file = cfg.ssh.known_hosts_file,
        "mail".smtp = cfg.mail.smtp,
        "mail".from = cfg.mail.from,
        "mail".max_attachment = cfg.mail.max_attachment,
        "s3".endpoint = cfg.s3.endpoint,
        "s3".region = cfg.s3.region,
        "s3".path_style = cfg.s3.path_style,
    );
    if !cfg.ssh.hostkey.is_empty() {
        rows.push(("[ssh] hostkey".into(), cfg.ssh.hostkey.join(", ")));
    }
    let width = rows.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in &rows {
        anstream::println!("{HEAD}{k:<width$}{HEAD:#}  {NUM}{v}{NUM:#}");
    }
    if rows.is_empty() {
        anstream::println!("{DIM}nothing set; built-in defaults are in use{DIM:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        let mut all = vec!["mpt"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["cp", "a", "b"]);
        Cli::parse_from(all)
    }

    fn config(text: &str) -> mpt::Config {
        mpt::Config::parse(text).unwrap()
    }

    #[test]
    fn the_command_line_wins_over_the_configuration() {
        let cfg = config("[defaults]\ntimeout = 60\nqueue = 4\ncache_limit = \"1G\"\n");
        let s = Settings::resolve(&cli(&["--timeout", "5"]), &cfg).unwrap();
        assert_eq!(s.timeout, 5, "the flag wins");
        assert_eq!(s.queue, 4, "the configuration fills in the rest");
        assert_eq!(s.cache_limit, 1 << 30);
        assert_eq!(s.chunk, 64 << 10, "and the built-in value the rest");
    }

    #[test]
    fn built_in_defaults_without_a_configuration() {
        let s = Settings::resolve(&cli(&[]), &mpt::Config::default()).unwrap();
        assert_eq!((s.timeout, s.queue, s.retries), (30, 16, 0));
        assert!(s.atomic && !s.cache);
        assert!(s.hash.is_none());
    }

    #[test]
    fn switches_can_be_set_by_either_side() {
        let cfg = config("[defaults]\ncache = true\natomic = false\nhash = \"blake3\"\n");
        let s = Settings::resolve(&cli(&[]), &cfg).unwrap();
        assert!(s.cache && !s.atomic);
        assert_eq!(s.hash, Some(HashAlgo::Blake3));
        // --no-atomic cannot be undone by the configuration, and --hash wins.
        let s = Settings::resolve(&cli(&["--no-atomic", "--hash", "sha512"]), &config("")).unwrap();
        assert!(!s.atomic);
        assert_eq!(s.hash, Some(HashAlgo::Sha512));
    }

    #[test]
    fn a_bad_default_names_its_key() {
        let err = Settings::resolve(&cli(&[]), &config("[defaults]\nhash = \"md5\"\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("[defaults] hash"), "{err}");
        let err = Settings::resolve(&cli(&[]), &config("[defaults]\nchunk = \"lots\"\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("[defaults] chunk"), "{err}");
    }
}
