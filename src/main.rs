use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anstyle::{AnsiColor, Style};
use anyhow::Context;
use clap::{ColorChoice, Parser, Subcommand};
use mpft::batch::jobs::{Format, JobSpec};
use mpft::sign::{SignSpec, VerifySpec};
use mpft::{CacheMode, CopyOptions, HashAlgo, Scheme, TeeOptions};

/// Send and receive files over many protocols, addressed by URL prefix.
#[derive(Parser)]
#[command(name = "mpft", version, about, long_about = None)]
struct Cli {
    /// Verbose logging (-v info, -vv debug, -vvv trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Disable TLS certificate verification for all endpoints. Deprecated:
    /// use ?insecure=true on the one URL that needs it.
    #[arg(long, global = true)]
    insecure: bool,

    /// Configuration file (default: $MPFT_CONFIG, else ~/.config/mpft/config.toml,
    /// plus ./mpft.toml for [defaults] and [policy])
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Colored output: auto (only on a terminal, honours NO_COLOR), always, never
    #[arg(long, global = true, value_name = "WHEN")]
    color: Option<ColorChoice>,

    /// Password for sftp, scp, ftp(s), http(s) and webdav(s) endpoints whose
    /// URL has none. A password in the URL or in argv is visible to every
    /// other process; prefer MPFT_PASSWORD, --password-file or
    /// --password-stdin.
    #[arg(long, global = true)]
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
    /// settable with MPFT_REFUSE_PLAINTEXT_AUTH=1.
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

    /// Print the result as JSON on stdout; the human-readable lines stay on
    /// stderr, so a script can read one and a person the other
    #[arg(long, global = true)]
    json: bool,

    /// Progress line while copying: auto (only on a terminal, and only with
    /// --json off), always, never
    #[arg(long, global = true, value_name = "WHEN")]
    progress: Option<ColorChoice>,

    /// Write straight to the target name instead of uploading to
    /// <name>.mpft-part and renaming it into place when the transfer is done
    #[arg(long, global = true)]
    no_atomic: bool,

    /// Continue an interrupted transfer: keep what is already in
    /// <name>.mpft-part on the target and send only the rest
    #[arg(long, global = true, conflicts_with = "no_atomic")]
    resume: bool,

    /// Leave a target alone when it already holds a file of the same name
    /// and size, so a repeated run (a tree, a pattern) sends only what is new
    #[arg(long, global = true)]
    skip_existing: bool,

    /// Delete the source once every target has it (a move, in effect).
    /// Nothing is deleted while a target is missing the file
    #[arg(long, global = true)]
    delete_source: bool,

    /// Compute a checksum while copying and write <name>.sha256|.sha512|.b3
    /// next to every target (sha256sum/b3sum format; mail gets it as attachment)
    #[arg(long, global = true, value_name = "ALGO")]
    hash: Option<HashAlgo>,

    /// Verify the content against a checksum file next to the source
    /// (<name>.b3, .sha256 or .sha512); fails if none exists or it mismatches
    #[arg(long, global = true)]
    check: bool,

    /// Sign the checksum file: `ssh` (ssh-agent or default key), `ssh:<key>`
    /// or `pgp:<secret-key.asc>`; passphrase via MPFT_SIGN_KEY_PASSPHRASE.
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
    /// Copy from one URL to one or more targets (the source is read once),
    /// or with -t: copy every URL given into the target directory
    #[command(alias = "copy")]
    Cp {
        /// Copy every positional URL into this directory target (repeat for
        /// a fan-out). Without it, the first URL is the source and the rest
        /// are its targets
        #[arg(short = 't', long = "target", value_name = "URL")]
        target: Vec<String>,
        #[arg(required = true, num_args = 1.., value_name = "URL")]
        urls: Vec<String>,
        #[command(flatten)]
        batch: BatchArgs,
    },
    /// Run a list of jobs from a file or standard input: `SRC DST…` per line
    /// with shell quoting, JSON Lines, or CSV with `src` and `dst` columns
    Batch {
        /// The job list; `-` reads standard input
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// lines, jsonl or csv; guessed from the file name or the first
        /// line when not given
        #[arg(long, value_name = "FORMAT")]
        format: Option<Format>,
        /// Run each job as its line arrives instead of reading the whole
        /// list first (only from stdin); the batch ends with the input
        #[arg(long)]
        follow: bool,
        #[command(flatten)]
        batch: BatchArgs,
    },
    /// List a directory; one whose profile names a relay is listed by it
    Ls {
        url: String,
        /// List from here even though the profile names a relay
        #[cfg(feature = "relay")]
        #[arg(long)]
        no_via: bool,
    },
    /// Show supported URL schemes and their options
    Schemes,
    /// Print a completion script for a shell (bash, zsh, fish, elvish, powershell)
    Completions { shell: clap_complete::Shell },
    /// Print the manual page in roff format (`mpft man | man -l -`)
    Man,
    /// List the profiles the configuration defines
    Profiles,
    /// Manage secrets in the OS key store, for { keyring = "<service>/<user>" }
    #[cfg(feature = "keyring")]
    Credentials {
        #[command(subcommand)]
        action: CredentialCmd,
    },
    /// Inspect the configuration file
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Take jobs over HTTP and run them; progress by GET or WebSocket
    #[cfg(feature = "server")]
    Serve(ServeArgs),
    /// Take one upload on stdin and deliver it to the targets its header
    /// names; with --listen, as an SSH server of its own (see `cp --via`)
    #[cfg(feature = "relay")]
    Relay(RelayArgs),
}

/// Flags of `mpft relay`; each one wins over its `[relay]` key.
#[cfg(feature = "relay")]
#[derive(clap::Args, Debug, Clone)]
struct RelayArgs {
    /// Listen as an SSH server on this address (0.0.0.0:2222 when the
    /// flag has no value) instead of reading one upload from stdin
    #[arg(long, value_name = "ADDR", num_args = 0..=1, default_missing_value = "0.0.0.0:2222")]
    listen: Option<String>,
    /// The server's host key; generated when the file is missing
    /// (~/.local/state/mpft/relay_host_key on Linux, ~/Library/Application
    /// Support/mpft/relay_host_key on macOS, %LOCALAPPDATA%\mpft\relay_host_key on Windows)
    #[arg(long, value_name = "PATH")]
    host_key: Option<PathBuf>,
    /// Who may connect, in OpenSSH format (~/.config/mpft/authorized_keys)
    #[arg(long, value_name = "PATH")]
    authorized_keys: Option<PathBuf>,
    /// Relays running at once; further sessions wait (4)
    #[arg(long, value_name = "N")]
    parallel: Option<usize>,
    /// Seconds a shutdown waits for running relays before cancelling them (30)
    #[arg(long, value_name = "SECONDS")]
    grace: Option<u64>,
    /// Refuse uploads larger than this, e.g. 10G; 0 for no limit
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    max_size: Option<u64>,
    /// Refuse to list a directory with more entries than this (100000);
    /// 0 for no limit
    #[arg(long, value_name = "N")]
    max_entries: Option<usize>,
    /// How clients may send the targets' passwords: header (in the URLs,
    /// the default), on-demand (asked of the client at every login, never
    /// held here) or any
    #[arg(long, value_name = "MODE", value_parser = parse_relay_credentials)]
    credentials: Option<mpft::relay::RelayCredentials>,
    /// Refuse the client's forwarded ssh-agent (with --listen); the SSH
    /// targets then authenticate with this side's keys and passwords only
    #[arg(long)]
    no_agent_forwarding: bool,
    /// Let a client have the source deleted that the relay read for it
    /// (delete_source); never a file on this host. Off unless given
    #[arg(long)]
    allow_delete: bool,
    /// Log in to the SSH hosts a client names with this side's own identity
    /// too: its ssh-agent, ~/.ssh/id_*, [ssh] key and MPFT_SSH_KEY. Off unless
    /// given: then only the client's forwarded agent and the passwords it
    /// sends serve such a host
    #[arg(long)]
    own_keys: bool,
    /// Let a client name files on this host: a local path as a source, a
    /// target or a directory to list or make. Off unless given: then only
    /// a profile of this side's configuration reaches its disk
    #[arg(long)]
    allow_local: bool,
    /// Write the port actually bound to this file (for --listen 127.0.0.1:0)
    #[arg(long, value_name = "PATH")]
    port_file: Option<PathBuf>,
}

/// Flags of `mpft serve`; each one wins over its `[server]` key.
#[cfg(feature = "server")]
#[derive(clap::Args, Debug, Clone)]
struct ServeArgs {
    /// Address to listen on (127.0.0.1:7788). Anything but loopback needs
    /// a token
    #[arg(long, value_name = "ADDR")]
    bind: Option<String>,
    /// Take any URL in a job, not only mpft://<profile>/ ones
    #[arg(long)]
    allow_any_url: bool,
    /// Environment variable that holds the bearer token clients must send
    #[arg(long, value_name = "VAR")]
    token_env: Option<String>,
    /// JSONL journal of jobs; those left open are run again after a restart
    #[arg(long, value_name = "PATH")]
    journal: Option<PathBuf>,
    /// How long finished jobs stay available (24h; 0 keeps them until the
    /// server stops)
    #[arg(long, value_name = "SPAN")]
    retention: Option<String>,
    /// Transfers in flight at once, over all jobs (4)
    #[arg(long, value_name = "N")]
    parallel: Option<usize>,
    /// Write the port actually bound to this file (for --bind 127.0.0.1:0)
    #[arg(long, value_name = "PATH")]
    port_file: Option<PathBuf>,
    /// Seconds a shutdown waits for running jobs before cancelling them (30)
    #[arg(long, value_name = "SECONDS")]
    grace: Option<u64>,
    /// Let jobs delete their source (delete_source); off unless given
    #[arg(long)]
    allow_delete: bool,
    /// Transfers one job may hold after patterns and trees are expanded (10000)
    #[arg(long, value_name = "N")]
    max_transfers: Option<usize>,
    /// Jobs not yet finished before new ones are refused with 429 (1000)
    #[arg(long, value_name = "N")]
    max_queued: Option<usize>,
}

/// Options shared by `cp -t` and `batch`.
#[derive(clap::Args, Debug, Clone, Default)]
struct BatchArgs {
    /// Jobs in flight at once (4 by default). Every job opens its own
    /// connections, and with --cache holds its own copy of the payload
    #[arg(long, value_name = "N")]
    parallel: Option<usize>,
    /// Stop after the first failed job and cancel the running ones
    #[arg(long)]
    fail_fast: bool,
    /// Print the jobs that would run, and run nothing
    #[arg(long)]
    dry_run: bool,
    /// A source pattern (`*.csv`) that matches nothing is not an error
    #[arg(long)]
    allow_empty: bool,
    /// Copy directories with everything below them: `dir/` copies its
    /// contents into the target, `dir` the directory itself
    #[arg(short = 'r', long)]
    recursive: bool,
    /// Send the source once to this SSH host running `mpft relay` (an
    /// ssh:// URL or a profile with one) and let it deliver to the targets
    #[cfg(feature = "relay")]
    #[arg(long, value_name = "URL", conflicts_with = "no_via")]
    via: Option<String>,
    /// Copy from here even though [defaults] via names a relay
    #[cfg(feature = "relay")]
    #[arg(long)]
    no_via: bool,
    /// How the relay gets the targets' passwords: header (in the URLs it
    /// is sent, the default) or on-demand (asked of this side at every
    /// login, never held by the relay; the relay has to allow it)
    #[cfg(feature = "relay")]
    #[arg(long, value_name = "MODE", value_parser = parse_credentials)]
    via_credentials: Option<mpft::relay::Credentials>,
    /// Do not forward an ssh-agent to the relay; SSH targets then need a
    /// password, or a key on the relay (by default the relay signs with
    /// this side's keys and certificates through the forwarded agent)
    #[cfg(feature = "relay")]
    #[arg(long)]
    no_via_agent: bool,
    /// Let a relay forward the agent on to the second relay of a chained
    /// target, for the SSH targets behind it (by default it only logs in
    /// to that relay with it)
    #[cfg(feature = "relay")]
    #[arg(long, conflicts_with = "no_via_agent")]
    via_agent_onward: bool,
}

impl BatchArgs {
    /// The relay to send through: the flag, else the configured default,
    /// unless `--no-via` says none.
    fn via<'a>(&'a self, configured: Option<&'a str>) -> Option<&'a str> {
        #[cfg(feature = "relay")]
        {
            if self.no_via {
                return None;
            }
            self.via.as_deref().or(configured)
        }
        #[cfg(not(feature = "relay"))]
        {
            let _ = configured;
            None
        }
    }
}

/// What the command is going to touch, worked out before anything connects
/// so the credentials of every endpoint can be fetched in one go.
#[derive(Debug)]
enum Work {
    /// One source, its targets: the plain `cp`.
    Single { src: String, dsts: Vec<String> },
    /// A list of jobs: `cp -t` or `batch`.
    Many(Vec<JobSpec>),
    /// Jobs read from stdin as they come: `batch - --follow`.
    Follow,
    /// Any other URLs the command names.
    Urls(Vec<String>),
}

impl Work {
    /// The endpoint URLs the command works on, and the relay if there is one.
    fn urls<'a>(&'a self, via: Option<&'a str>) -> Vec<&'a str> {
        let mut urls = self.endpoint_urls();
        urls.extend(via);
        urls
    }

    fn endpoint_urls(&self) -> Vec<&str> {
        match self {
            Work::Single { src, dsts } => std::iter::once(src.as_str())
                .chain(dsts.iter().map(String::as_str))
                .collect(),
            Work::Many(jobs) => jobs
                .iter()
                .flat_map(|j| {
                    std::iter::once(j.src.as_str()).chain(j.dsts.iter().map(String::as_str))
                })
                .collect(),
            Work::Urls(urls) => urls.iter().map(String::as_str).collect(),
            Work::Follow => Vec::new(),
        }
    }
}

impl Cmd {
    /// Read the job list, if the command has one, and sort out what `cp`
    /// was given.
    fn work(&self) -> anyhow::Result<Work> {
        Ok(match self {
            Cmd::Cp { target, urls, .. } if target.is_empty() => {
                if urls.len() < 2 {
                    anyhow::bail!(
                        "cp needs a source and at least one target \
                         (or -t <URL> to copy every URL into one directory)"
                    );
                }
                Work::Single {
                    src: urls[0].clone(),
                    dsts: urls[1..].to_vec(),
                }
            }
            Cmd::Cp { target, urls, .. } => Work::Many(
                urls.iter()
                    .map(|u| JobSpec {
                        src: u.clone(),
                        dsts: target.clone(),
                    })
                    .collect(),
            ),
            Cmd::Batch { file, follow, .. } if *follow => {
                if file.as_os_str() != "-" {
                    anyhow::bail!("--follow reads standard input: use `batch - --follow`");
                }
                Work::Follow
            }
            Cmd::Batch { file, format, .. } => {
                let (text, name) = if file.as_os_str() == "-" {
                    let mut text = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                        .context("reading the job list from stdin")?;
                    (text, None)
                } else {
                    let text = std::fs::read_to_string(file)
                        .with_context(|| format!("reading the job list {}", file.display()))?;
                    (text, file.file_name().and_then(|n| n.to_str()))
                };
                let format = format.unwrap_or_else(|| mpft::batch::jobs::detect(name, &text));
                tracing::debug!(%format, "job list");
                Work::Many(mpft::batch::jobs::parse(&text, format)?)
            }
            Cmd::Ls { url, .. } => Work::Urls(vec![url.clone()]),
            _ => Work::Urls(Vec::new()),
        })
    }

    /// What the command reads from standard input itself, if anything:
    /// `--password-stdin` cannot have it then.
    fn reads_stdin(&self) -> Option<&'static str> {
        match self {
            Cmd::Batch { file, .. } if file.as_os_str() == "-" => Some("job list"),
            #[cfg(feature = "relay")]
            Cmd::Relay(a) if a.listen.is_none() => Some("upload"),
            #[cfg(feature = "keyring")]
            Cmd::Credentials {
                action: CredentialCmd::Set { .. },
            } => Some("secret"),
            _ => None,
        }
    }

    fn batch_args(&self) -> Option<&BatchArgs> {
        match self {
            Cmd::Cp { batch, .. } | Cmd::Batch { batch, .. } => Some(batch),
            _ => None,
        }
    }

    /// `mpft serve` and `mpft relay --listen`: Ctrl-C drains rather than stops.
    fn is_serve(&self) -> bool {
        #[cfg(feature = "server")]
        if matches!(self, Cmd::Serve(_)) {
            return true;
        }
        #[cfg(feature = "relay")]
        if matches!(self, Cmd::Relay(a) if a.listen.is_some()) {
            return true;
        }
        false
    }
}

/// `mpft credentials …`, only with the `keyring` feature.
#[cfg(feature = "keyring")]
#[derive(Subcommand)]
enum CredentialCmd {
    /// Store a secret read from standard input (first line)
    Set { entry: String },
    /// Print the stored secret
    Get { entry: String },
    /// Delete the stored secret
    Delete { entry: String },
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
    resume: bool,
    skip_existing: bool,
    delete_source: bool,
    hash: Option<HashAlgo>,
    json: bool,
    parallel: usize,
    /// The relay `cp` and `batch` send through, if any.
    via: Option<String>,
    /// How that relay gets the targets' passwords.
    #[cfg(feature = "relay")]
    via_credentials: mpft::relay::Credentials,
    /// Whether that relay gets this side's ssh-agent forwarded.
    #[cfg(feature = "relay")]
    via_agent: bool,
    /// Whether it may forward that agent on to a second relay.
    #[cfg(feature = "relay")]
    via_agent_onward: bool,
}

impl Settings {
    /// What the relays are told besides the copy's options.
    #[cfg(feature = "relay")]
    fn via_settings(&self) -> mpft::relay::via::ViaSettings {
        mpft::relay::via::ViaSettings {
            credentials: self.via_credentials,
            agent: self.via_agent,
            agent_onward: self.via_agent_onward,
            timeout: self.timeout,
        }
    }

    fn resolve(cli: &Cli, cfg: &mpft::Config) -> anyhow::Result<Settings> {
        let d = &cfg.defaults;
        let size = |v: &Option<String>, what: &str| -> anyhow::Result<Option<u64>> {
            match v {
                None => Ok(None),
                Some(v) => Some(mpft::config::parse_size(v))
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
            resume: cli.resume || d.resume.unwrap_or(false),
            skip_existing: cli.skip_existing || d.skip_existing.unwrap_or(false),
            delete_source: cli.delete_source || d.delete_source.unwrap_or(false),
            json: cli.json || d.json.unwrap_or(false),
            via: cli
                .cmd
                .batch_args()
                .and_then(|b| b.via(d.via.as_deref()))
                .map(String::from),
            #[cfg(feature = "relay")]
            via_credentials: match cli.cmd.batch_args().and_then(|b| b.via_credentials) {
                Some(mode) => mode,
                None => match &d.via_credentials {
                    Some(v) => v
                        .parse()
                        .map_err(|e| anyhow::anyhow!("[defaults] via_credentials: {e}"))?,
                    None => mpft::relay::Credentials::Header,
                },
            },
            #[cfg(feature = "relay")]
            via_agent: !cli.cmd.batch_args().is_some_and(|b| b.no_via_agent)
                && d.via_agent.unwrap_or(true),
            #[cfg(feature = "relay")]
            via_agent_onward: cli.cmd.batch_args().is_some_and(|b| b.via_agent_onward),
            parallel: match cli
                .cmd
                .batch_args()
                .and_then(|b| b.parallel)
                .or(d.parallel)
                .unwrap_or(4)
            {
                0 => anyhow::bail!("parallel must be at least 1"),
                n => n,
            },
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

// Exit codes, so a script can tell the cases apart without reading messages.
// clap already uses 2 for a malformed command line, which is why a bad URL or
// configuration joins it there. `mpft::Error::exit_code` maps the library's
// errors onto them.
/// At least one target failed.
const FAILED: u8 = 1;
/// The command, a URL or the configuration is wrong.
const USAGE: u8 = 2;
/// A checksum did not match, or a signature was missing or not trusted.
#[cfg(test)]
const UNTRUSTED: u8 = 3;
/// Authentication failed.
#[cfg(test)]
const DENIED: u8 = 4;
/// Terminated by Ctrl-C, as the shell convention has it.
const INTERRUPTED: u8 = 130;

/// Which of the codes above an error stands for.
fn exit_code(err: &anyhow::Error) -> u8 {
    if err.chain().any(|c| c.is::<Interrupted>()) {
        return INTERRUPTED;
    }
    for cause in err.chain() {
        if let Some(e) = cause.downcast_ref::<ExitWith>() {
            return e.code;
        }
        if let Some(e) = cause.downcast_ref::<mpft::Error>() {
            return code_of(e);
        }
    }
    FAILED
}

/// The exit code a library error stands for.
fn code_of(e: &mpft::Error) -> u8 {
    e.exit_code()
}

/// The exit code of a batch: what every failed job agrees on, else 1.
fn batch_code(codes: &[u8]) -> u8 {
    match codes {
        [] => 0,
        [first, rest @ ..] if rest.iter().all(|c| c == first) => *first,
        _ => FAILED,
    }
}

/// A failure whose exit code is already decided, with the message to print.
#[derive(Debug)]
struct ExitWith {
    code: u8,
    msg: String,
}

impl std::fmt::Display for ExitWith {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ExitWith {}

/// A wrong command line or setting, told with exit code 2 like clap's own
/// complaints.
fn usage(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(ExitWith {
        code: USAGE,
        msg: msg.into(),
    })
}

/// An exit code whose reason was already told (a relay's JSON line).
#[derive(Debug)]
struct Silent(u8);

impl std::fmt::Display for Silent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "exit {}", self.0)
    }
}

impl std::error::Error for Silent {}

/// Marks a run that was stopped with Ctrl-C or SIGTERM, so `main` can exit
/// with 130. A batch that `--fail-fast` stopped is not marked: it exits
/// with the code of the failure that stopped it.
#[derive(Debug)]
struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interrupted")
    }
}

impl std::error::Error for Interrupted {}

fn main() -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: starting the runtime: {e}");
            return ExitCode::from(FAILED);
        }
    };
    let code = rt.block_on(start());
    // Work on the blocking pool that a cancelled copy left behind (a read
    // from a pipe that never ends) gets a moment, then the process exits
    // without it rather than hang where no signal reaches it any more.
    rt.shutdown_timeout(Duration::from_secs(1));
    code
}

async fn start() -> ExitCode {
    let cli = Cli::parse();
    if cli.password_stdin
        && let Some(what) = cli.cmd.reads_stdin()
    {
        eprintln!("error: the {what} and the password cannot both come from stdin");
        return ExitCode::from(USAGE);
    }
    // The job list is read first: its endpoints decide which credentials
    // are needed.
    let work = match cli.cmd.work() {
        Ok(w) => w,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::from(USAGE);
        }
    };
    // The configuration decides the log level and the colors, so it is read
    // before either is set up; its own complaints are logged afterwards.
    let mut cfg = match mpft::Config::load(cli.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(USAGE);
        }
    };
    let settings = match Settings::resolve(&cli, &cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::from(USAGE);
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
    // Credentials are fetched before anything connects, and only those the
    // endpoints of this command actually need.
    if let Err(e) = cfg
        .resolve_secrets(&work.urls(settings.via.as_deref()), cli.sign.is_some())
        .await
    {
        anstream::eprintln!("{FAIL}error:{FAIL:#} {e}");
        return ExitCode::from(exit_code(&anyhow::Error::new(e)));
    }
    mpft::config::install(cfg);
    mpft::init_crypto();
    match run(cli, settings, work).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if let Some(Silent(code)) = e.downcast_ref::<Silent>() {
                return ExitCode::from(*code);
            }
            anstream::eprintln!("{FAIL}error:{FAIL:#} {e:#}");
            ExitCode::from(exit_code(&e))
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
    use mpft::credentials::{check_secret_file, first_line};
    if let Some(path) = &cli.password_file {
        check_secret_file(path, mpft::policy::policy().strict_permissions)?;
        // A file the flag names that cannot be read is a wrong command line.
        let text = std::fs::read_to_string(path).map_err(|e| {
            usage(format!(
                "--password-file: reading the password from {}: {e}",
                path.display()
            ))
        })?;
        return Ok(Some(first_line(&text).into()));
    }
    if cli.password_stdin {
        // The first line and no more: what follows is not the password's.
        let mut text = String::new();
        std::io::stdin()
            .read_line(&mut text)
            .context("reading the password from stdin")?;
        return Ok(Some(first_line(&text).into()));
    }
    Ok(cli.password.clone().map(secrecy::SecretString::from))
}

/// What the command adds to every URL it opens: the flags that apply to
/// all endpoints, and the password when the URL has none.
#[derive(Clone)]
struct LocateRules {
    insecure: bool,
    timeout: u64,
    retries: u32,
    password: Option<secrecy::SecretString>,
}

impl LocateRules {
    /// A URL as a location, `mpft://` profiles resolved. `timeout` is a
    /// per-job override of the flag (the server's jobs and a relay's
    /// clients may set one), held to the flag's own limit.
    fn locate(&self, url: &str, timeout: Option<u64>) -> mpft::Result<mpft::Location> {
        let mut loc = mpft::config::locate(url)?;
        if self.insecure {
            loc.set_option("insecure", "true");
        }
        // --timeout is the default; ?timeout= in the URL wins.
        if loc.opt("timeout").is_none() {
            let timeout = timeout.map_or(self.timeout, |t| {
                mpft::options::hold_timeout(t, self.timeout)
            });
            loc.set_option("timeout", timeout.to_string());
        }
        if self.retries > 0 && loc.opt("connect_retries").is_none() {
            loc.set_option("connect_retries", self.retries.to_string());
        }
        // A password in the URL stays; one from a profile gives way to the
        // flag. The flag is for the schemes MPFT_PASSWORD is for: not the key
        // of an S3 bucket, not a relay, not a mail server.
        if let Some(pw) = &self.password
            && !loc.password_in_url()
            && loc.scheme().takes_default_password()
        {
            use secrecy::ExposeSecret;
            loc.set_password(pw.expose_secret());
        }
        Ok(loc)
    }

    /// [`LocateRules::locate`] for a relay, which opens the URLs its
    /// clients name. Such a URL gets nothing of this side's credentials:
    /// not `--password` and its siblings, not `MPFT_PASSWORD` or
    /// `MPFT_SMTP_PASSWORD` — those are for the hosts this side picks, not
    /// for whichever host a client names. The same goes for this side's SSH
    /// identity — its agent, `~/.ssh/id_*`, `[ssh] key` — unless the relay
    /// runs with `--own-keys`; and a client's URL may not name a key file on
    /// this host. A profile of the relay's own configuration (`mpft://`) is
    /// one of those hosts and keeps them all.
    #[cfg(feature = "relay")]
    fn locate_relayed(
        &self,
        url: &str,
        timeout: Option<u64>,
        own_keys: bool,
    ) -> mpft::Result<mpft::Location> {
        if mpft::config::is_profile_ref(url) {
            return self.locate(url, timeout);
        }
        let rules = LocateRules {
            password: None,
            ..self.clone()
        };
        let mut loc = rules.locate(url, timeout)?;
        // `?timeout=` in the URL wins over the header's, but is held to
        // this side's limit all the same: a client may not pin a slot.
        if let Some(t) = loc.opt("timeout").and_then(|t| t.parse::<u64>().ok()) {
            loc.set_option(
                "timeout",
                mpft::options::hold_timeout(t, self.timeout).to_string(),
            );
        }
        loc.set_env_password(false);
        loc.set_client_named(own_keys);
        Ok(loc)
    }
}

async fn run(cli: Cli, settings: Settings, work: Work) -> anyhow::Result<()> {
    // Listening starts before anything else does, so that a signal that
    // comes early (as soon as a server's port file is there) is not missed.
    let mut signals = Interrupts::install().context("listening for Ctrl-C")?;
    if cli.refuse_plaintext_auth {
        mpft::policy::set_refuse_plaintext_auth(true);
    }
    if cli.insecure {
        tracing::warn!(
            "--insecure disables certificate checks for every endpoint and is deprecated; \
             put ?insecure=true on the URL that needs it"
        );
    }
    let password = read_password(&cli)?;
    // A profile can ask for signing and a checksum of its own; the flags win.
    let profiles: Vec<mpft::config::Profile> = work
        .endpoint_urls()
        .iter()
        .filter_map(|u| mpft::config::profile_of(u))
        .collect();
    let mut settings = settings;
    if cli.hash.is_none()
        && let Some(h) = profiles.iter().find_map(|p| p.hash.as_deref())
    {
        settings.hash = Some(HashAlgo::parse(h).map_err(|e| usage(format!("profile hash: {e}")))?);
    }
    // A profile may switch atomic finishing off, but cannot switch it back on
    // against --no-atomic.
    if profiles.iter().any(|p| p.atomic == Some(false)) {
        settings.atomic = false;
    }
    let settings = settings;
    let timeout = (settings.timeout > 0).then(|| Duration::from_secs(settings.timeout));
    // Ctrl-C stops the transfer, removes partial files and leaves the rest
    // alone. A server finishes its running jobs first; a second Ctrl-C
    // cancels them too. One more exits without waiting for the cleanup,
    // in case that is what hangs.
    let cancel = tokio_util::sync::CancellationToken::new();
    let abort = tokio_util::sync::CancellationToken::new();
    {
        let cancel = cancel.clone();
        let abort = abort.clone();
        let serving = cli.cmd.is_serve();
        tokio::spawn(async move {
            if !signals.next().await {
                return;
            }
            if serving {
                anstream::eprintln!(
                    "{WARN}interrupted{WARN:#}, finishing the running jobs (Ctrl-C again cancels them)…"
                );
            } else {
                anstream::eprintln!(
                    "{WARN}interrupted{WARN:#}, stopping and cleaning up (Ctrl-C again exits immediately)…"
                );
            }
            cancel.cancel();
            if serving {
                if !signals.next().await {
                    return;
                }
                anstream::eprintln!(
                    "{WARN}interrupted again{WARN:#}, cancelling the jobs (Ctrl-C again exits immediately)…"
                );
                abort.cancel();
            }
            if signals.next().await {
                anstream::eprintln!("{WARN}interrupted again{WARN:#}, exiting without cleaning up");
                std::process::exit(INTERRUPTED.into());
            }
        });
    }
    let rules = LocateRules {
        insecure: cli.insecure,
        timeout: settings.timeout,
        retries: settings.retries,
        password,
    };
    let locate = |url: &str| -> anyhow::Result<mpft::Location> { Ok(rules.locate(url, None)?) };
    let open = |url: &str| -> anyhow::Result<Box<dyn mpft::Endpoint>> {
        Ok(mpft::protocols::open(locate(url)?)?)
    };

    let sign = match cli.sign.as_deref().or_else(|| {
        profiles
            .iter()
            .find_map(|p| p.sign.as_deref())
            .inspect(|spec| tracing::info!(%spec, "signing, as the profile asks"))
    }) {
        Some(spec) => Some(sign_spec(spec)?),
        None => None,
    };
    let verify = verify_spec(&cli)?;
    let check = cli.check || verify.is_some();
    if check && verify.is_none() && mpft::policy::policy().require_signature {
        return Err(usage(
            "policy.require_signature is set, but no trusted keys are given: \
             use --verify-signers/--verify-keyring or [verify] in the configuration",
        ));
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
        resume: settings.resume,
        skip_existing: settings.skip_existing,
        delete_source: settings.delete_source,
        cancel: Some(cancel.clone()),
        progress: show_progress(&cli, &settings).then(mpft::transfer::Progress::new),
        hash: settings.hash.or(sign.as_ref().map(|_| HashAlgo::Sha256)),
        check,
        sign: match &sign {
            Some(spec) => Some(mpft::sign::load_signer(spec).await?),
            None => None,
        },
        verify: match &verify {
            Some(spec) => Some(mpft::sign::load_verifier(spec)?),
            None => None,
        },
    };
    if let Some(s) = &opts.sign {
        tracing::info!(signer = %s.identity(), "signing checksum files");
    }

    // A relay does the copying for `--via` and for the profiles that name
    // one. Only `cp` and `batch` go through relays, and only the profiles
    // the command uses count: a relay elsewhere in the configuration
    // changes nothing here. A job list read as it arrives may use any.
    #[cfg(feature = "relay")]
    let via = match cli.cmd.batch_args() {
        Some(b) if !b.no_via => {
            let used = match &work {
                Work::Follow => None,
                w => Some(
                    w.endpoint_urls()
                        .into_iter()
                        .filter_map(|u| locate(u).ok()?.profile().map(String::from))
                        .collect::<std::collections::BTreeSet<_>>(),
                ),
            };
            let locate = |url: &str| rules.locate(url, None);
            via_table(settings.via.as_deref(), used.as_ref(), &locate)?
                .map(|table| std::sync::Arc::new(Via::new(table, &opts, &settings.via_settings())))
        }
        _ => None,
    };
    #[cfg(not(feature = "relay"))]
    let via: Option<()> = None;
    let open_loc = |loc: &mpft::Location| mpft::protocols::open(loc.clone());
    let runner = match &via {
        #[cfg(feature = "relay")]
        Some(v) => JobRunner::Via(v),
        _ => JobRunner::Local(&open_loc),
    };

    // A pattern as the source of a plain `cp` is a batch of one line, and so
    // is any source with -r, since it may turn out to be a directory. A dry
    // run goes the same way, so that it prints the job the batch would run
    // and runs nothing, and so does a copy that a relay takes part in.
    let recursive = cli.cmd.batch_args().is_some_and(|b| b.recursive);
    let dry_run = cli.cmd.batch_args().is_some_and(|b| b.dry_run);
    let work = match work {
        Work::Single { src, dsts }
            if recursive
                || dry_run
                || mpft::batch::expand::has_pattern(&locate(&src)?)
                || runner.relays(&locate_job(
                    &JobSpec {
                        src: src.clone(),
                        dsts: dsts.clone(),
                    },
                    &locate,
                )?) =>
        {
            Work::Many(vec![JobSpec { src, dsts }])
        }
        w => w,
    };
    match &cli.cmd {
        Cmd::Cp { batch, .. } | Cmd::Batch { batch, .. } => match work {
            Work::Single { src, dsts } => {
                let opened = dsts
                    .iter()
                    .map(|d| open(d))
                    .collect::<anyhow::Result<Vec<_>>>()
                    .and_then(|targets| Ok((open(&src)?, targets)));
                let (source, targets) = match opened {
                    Ok(o) => o,
                    Err(e) => {
                        if settings.json {
                            let shown = locate(&src)
                                .map(|l| l.to_string())
                                .unwrap_or_else(|_| mpft::location::mask_url(&src));
                            print_json_failure(&shown, &e);
                        }
                        return Err(e);
                    }
                };
                // The bar watches the counters the copy fills in; it draws
                // only while the copy runs and wipes its line when it is done.
                let bar = opts.progress.clone().map(spawn_progress);
                let outcome = do_copy(source, targets, &opts, settings.json).await;
                clear_progress(bar);
                outcome
            }
            Work::Many(jobs) => {
                // The batch shares one byte counter across its jobs, so the
                // single-copy progress is switched off.
                let mut opts = opts;
                let progress = opts
                    .progress
                    .take()
                    .map(|_| mpft::batch::BatchProgress::new());
                do_batch(jobs, &locate, &runner, opts, &settings, batch, progress).await
            }
            Work::Follow => {
                let Cmd::Batch { format, .. } = &cli.cmd else {
                    unreachable!("only batch follows");
                };
                let mut opts = opts;
                let progress = opts
                    .progress
                    .take()
                    .map(|_| mpft::batch::BatchProgress::new());
                do_follow(
                    &locate,
                    &runner,
                    opts,
                    &settings,
                    batch,
                    *format,
                    cli.sign.is_some(),
                    progress,
                )
                .await
            }
            Work::Urls(_) => unreachable!("cp and batch always have work"),
        },
        Cmd::Ls { url, .. } => {
            let dir = locate(url)?;
            // A directory whose profile names a relay is the relay's to
            // read, as it would be as a source.
            #[cfg(feature = "relay")]
            let via = match &cli.cmd {
                Cmd::Ls { no_via: false, .. } => {
                    let used = dir.profile().map(String::from).into_iter().collect();
                    let locate = |url: &str| rules.locate(url, None);
                    via_table(None, Some(&used), &locate)?
                        .map(|table| Via::new(table, &opts, &settings.via_settings()))
                }
                _ => None,
            };
            #[cfg(feature = "relay")]
            let through = via
                .as_ref()
                .and_then(|v| Some((v, v.source_relay(&dir)?.clone())));
            #[cfg(not(feature = "relay"))]
            let through: Option<((), ())> = None;
            let entries = match through {
                #[cfg(feature = "relay")]
                Some((via, relay)) => via.list(&relay, &dir, &cancel).await,
                _ => {
                    async {
                        let ep = mpft::protocols::open(dir.clone())?;
                        ep.receiver()?.list().await
                    }
                    .await
                }
            }
            .with_context(|| format!("listing {dir}"))?;
            if settings.json {
                let rows: Vec<serde_json::Value> =
                    entries.iter().map(mpft::report::entry_json).collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
                return Ok(());
            }
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
        #[cfg(feature = "keyring")]
        Cmd::Credentials { action } => {
            use mpft::credentials as cred;
            match action {
                CredentialCmd::Set { entry } => {
                    let mut text = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                        .context("reading the secret from stdin")?;
                    cred::keyring_set(entry, &cred::first_line(&text).into())?;
                    anstream::eprintln!("{OK}stored{OK:#} {entry}");
                }
                CredentialCmd::Get { entry } => {
                    use secrecy::ExposeSecret;
                    let secret = cred::keyring_get(entry).await?;
                    anstream::println!("{}", secret.expose_secret());
                }
                CredentialCmd::Delete { entry } => {
                    cred::keyring_delete(entry)?;
                    anstream::eprintln!("{OK}deleted{OK:#} {entry}");
                }
            }
            Ok(())
        }
        Cmd::Completions { shell } => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(*shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Cmd::Man => {
            clap_mangen::Man::new(<Cli as clap::CommandFactory>::command())
                .render(&mut std::io::stdout())
                .context("writing the manual page")?;
            Ok(())
        }
        Cmd::Profiles => {
            show_profiles(&mpft::config::global());
            Ok(())
        }
        Cmd::Config { action } => {
            let ConfigCmd::Check = action;
            show_config(&mpft::config::global());
            Ok(())
        }
        #[cfg(feature = "server")]
        Cmd::Serve(args) => {
            let server = server_config(args, &mpft::config::global()).await?;
            // Ctrl-C is the drain signal here, not the copies' cancel: a
            // running job finishes (or is cancelled by the server's grace
            // timer), and there is no terminal to draw progress on.
            let mut base = opts;
            base.cancel = None;
            base.progress = None;
            if base.delete_source && !server.allow_delete {
                return Err(usage(
                    "--delete-source would make every job delete its source; \
                     add --allow-delete (or [server] allow_delete) if that is meant",
                ));
            }
            // Jobs come later and may name any profile: every profile's
            // relay is in play. `--via` and `[defaults] via` are not.
            #[cfg(feature = "relay")]
            let via = {
                let locate = |url: &str| rules.locate(url, None);
                via_table(None, None, &locate)?.map(|table| {
                    std::sync::Arc::new(Via::new(table, &base, &settings.via_settings()))
                })
            };
            let rules = rules.clone();
            let rt = mpft::server::Runtime {
                #[cfg(feature = "relay")]
                via,
                copy: base,
                locate: std::sync::Arc::new(move |url, o: &mpft::server::model::JobOptions| {
                    rules.locate(url, o.timeout)
                }),
                signing: cli.sign.is_some(),
                parallel: settings.parallel,
            };
            mpft::server::serve(server, rt, cancel, abort).await?;
            Ok(())
        }
        #[cfg(feature = "relay")]
        Cmd::Relay(args) => {
            // The relay's own flags for what only the client can mean are
            // refused: its source is the upload. A header's delete_source
            // is judged per session, against --allow-delete.
            for (flag, set) in [
                ("--check", opts.check),
                ("--delete-source", opts.delete_source),
                ("--resume", opts.resume),
            ] {
                if set {
                    return Err(usage(format!(
                        "{flag} has no meaning for a relay: its source is the upload"
                    )));
                }
            }
            let mut base = opts;
            base.cancel = None;
            base.progress = None;
            let section = &mpft::config::global().relay;
            let rules = rules.clone();
            let own_keys = args.own_keys || section.own_keys.unwrap_or(false);
            let relay = mpft::relay::Relay {
                copy: base,
                locate: std::sync::Arc::new(move |url, o: &mpft::options::JobOptions| {
                    rules.locate_relayed(url, o.timeout, own_keys)
                }),
                max_size: match (args.max_size, &section.max_size) {
                    (Some(n), _) => n,
                    (None, Some(v)) => mpft::config::parse_size(v)
                        .map_err(|e| usage(format!("[relay] max_size: {e}")))?,
                    (None, None) => 0,
                },
                max_entries: args
                    .max_entries
                    .or(section.max_entries)
                    .unwrap_or(mpft::relay::DEFAULT_MAX_ENTRIES),
                credentials: match (args.credentials, &section.credentials) {
                    (Some(mode), _) => mode,
                    (None, Some(v)) => v
                        .parse()
                        .map_err(|e| usage(format!("[relay] credentials: {e}")))?,
                    (None, None) => mpft::relay::RelayCredentials::Header,
                },
                allow_delete: args.allow_delete || section.allow_delete.unwrap_or(false),
                local_files: args.allow_local || section.local_files.unwrap_or(false),
                cancel: cancel.clone(),
            };
            match &args.listen {
                Some(addr) => {
                    let listener = relay_listener(addr, args, section)?;
                    mpft::relay::sshd::serve(listener, std::sync::Arc::new(relay), cancel, abort)
                        .await?;
                    Ok(())
                }
                None => {
                    let code =
                        mpft::relay::run(&relay, tokio::io::stdin(), tokio::io::stdout()).await;
                    if code == 0 {
                        Ok(())
                    } else {
                        // The outcome went to stdout as JSON already.
                        Err(anyhow::Error::new(Silent(code)))
                    }
                }
            }
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
                "\n{HEAD}Credentials:{HEAD:#} user[:password]@ in the URL, else MPFT_PASSWORD / MPFT_SMTP_PASSWORD."
            );
            anstream::println!(
                "{HEAD}SSH keys:{HEAD:#} MPFT_SSH_KEY, else ssh-agent (SSH_AUTH_SOCK), else ~/.ssh/id_ed25519, id_rsa."
            );
            anstream::println!(
                "{HEAD}Mail:{HEAD:#} MPFT_SMTP_URL (for mailto:), MPFT_MAIL_FROM.  {HEAD}S3:{HEAD:#} AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_ENDPOINT_URL."
            );
            Ok(())
        }
    }
}

async fn do_copy(
    src: Box<dyn mpft::Endpoint>,
    targets: Vec<Box<dyn mpft::Endpoint>>,
    opts: &CopyOptions,
    json: bool,
) -> anyhow::Result<()> {
    let refs: Vec<&dyn mpft::Endpoint> = targets.iter().map(|t| t.as_ref()).collect();
    let report = match mpft::copy_many(src.as_ref(), &refs, opts).await {
        Ok(report) => report,
        Err(e) => {
            let e = anyhow::Error::new(e).context(format!("copy {}", src.location()));
            if json {
                print_json_failure(&src.location().to_string(), &e);
            }
            return Err(e);
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&mpft::report::fanout_json(&report))?
        );
    }
    match print_report(&report, opts, "") {
        None => Ok(()),
        Some((INTERRUPTED, msg)) => Err(anyhow::Error::new(Interrupted).context(msg)),
        Some((code, msg)) => Err(anyhow::Error::new(ExitWith { code, msg })),
    }
}

/// A copy that failed before there was a report, as JSON: what a batch
/// prints for such a job, without the job number.
fn print_json_failure(source: &str, err: &anyhow::Error) {
    let lib = err.chain().find_map(|c| c.downcast_ref::<mpft::Error>());
    let line = serde_json::json!({
        "source": source,
        "ok": false,
        "error": lib.map(|e| e.to_string()).unwrap_or_else(|| format!("{err:#}")),
        "cancelled": matches!(lib, Some(mpft::Error::Cancelled)),
    });
    if let Ok(text) = serde_json::to_string_pretty(&line) {
        println!("{text}");
    }
}

/// Print the outcome of one copy the way a person reads it, every line
/// starting with `prefix`. Returns the exit code and the message of a
/// failure, if there was one; 130 means the copy was cancelled.
fn print_report(
    report: &mpft::FanoutReport,
    opts: &CopyOptions,
    prefix: &str,
) -> Option<(u8, String)> {
    let cancelled = report
        .targets
        .iter()
        .any(|t| matches!(t.result, Err(mpft::Error::Cancelled)));
    if report.targets.len() == 1 {
        let t = &report.targets[0];
        if let Err(e) = &t.result {
            // A mismatch shows the digests and the verdict, as in a fan-out.
            if matches!(e, mpft::Error::ChecksumMismatch { .. })
                && let Some(failure) = print_checksums(report, opts, prefix)
            {
                return Some(failure);
            }
            let what = format!("copy {} -> {}: {e}", report.source, t.target);
            let code = if cancelled { INTERRUPTED } else { code_of(e) };
            return Some((code, what));
        }
        if t.skipped {
            anstream::eprintln!(
                "{prefix}{DIM}{}{DIM:#} -> {DIM}{}{DIM:#}: {DIM}already there, skipped{DIM:#}",
                report.source,
                t.target
            );
            return print_removed(report, prefix);
        }
        anstream::eprintln!(
            "{prefix}{DIM}{}{DIM:#} -> {DIM}{}{DIM:#}: {NUM}{}{NUM:#} bytes in {NUM}{:.2?}{NUM:#}",
            report.source,
            t.target,
            t.bytes,
            report.elapsed
        );
        if let Some(sc) = &t.sidecar {
            anstream::eprintln!("{prefix}{DIM}+ {sc}{DIM:#}");
        }
        if let Some(sg) = &t.signature {
            anstream::eprintln!("{prefix}{DIM}+ {sg}{DIM:#}");
        }
        return print_checksums(report, opts, prefix).or_else(|| print_removed(report, prefix));
    }
    for t in &report.targets {
        match &t.result {
            Ok(()) if t.skipped => {
                anstream::eprintln!(
                    "{prefix}{DIM}skip  {:>14}  {:>9}  {}{DIM:#}",
                    "already there",
                    "",
                    t.target
                );
            }
            Ok(()) => {
                anstream::eprintln!(
                    "{prefix}{OK}ok    {OK:#}  {NUM}{:>12}{NUM:#} bytes  {NUM}{:>9.2?}{NUM:#}  {DIM}{}{DIM:#}",
                    t.bytes,
                    t.elapsed,
                    t.target
                );
                if let Some(sc) = &t.sidecar {
                    anstream::eprintln!("{prefix}{DIM}        + {sc}{DIM:#}");
                }
                if let Some(sg) = &t.signature {
                    anstream::eprintln!("{prefix}{DIM}        + {sg}{DIM:#}");
                }
            }
            Err(e) => anstream::eprintln!(
                "{prefix}{FAIL}FAILED{FAIL:#}  {NUM}{:>12}{NUM:#} bytes  {NUM}{:>9.2?}{NUM:#}  {DIM}{}{DIM:#}: {FAIL}{e}{FAIL:#}",
                t.bytes,
                t.elapsed,
                t.target
            ),
        }
    }
    let failed = report.failures().count();
    let summary = if failed == 0 { OK } else { WARN };
    anstream::eprintln!(
        "{prefix}{DIM}{}{DIM:#}: {NUM}{}{NUM:#} bytes read, {summary}{}/{} targets ok{summary:#} in {NUM}{:.2?}{NUM:#}",
        report.source,
        report.bytes_read,
        report.targets.len() - failed,
        report.targets.len(),
        report.elapsed
    );
    if let Some(failure) = print_checksums(report, opts, prefix) {
        return Some(failure);
    }
    if let Some(failure) = print_removed(report, prefix) {
        return Some(failure);
    }
    if cancelled {
        return Some((
            INTERRUPTED,
            format!("{failed} of {} targets unfinished", report.targets.len()),
        ));
    }
    if failed > 0 {
        // What the failed targets agree on, else a plain failure.
        let codes: Vec<u8> = report
            .failures()
            .map(|t| t.result.as_ref().err().map(code_of).unwrap_or(FAILED))
            .collect();
        return Some((
            batch_code(&codes),
            format!("{failed} of {} targets failed", report.targets.len()),
        ));
    }
    None
}

/// Run a list of jobs, `settings.parallel` at a time, and print each as it
/// finishes.
async fn do_batch(
    specs: Vec<JobSpec>,
    locate: &dyn Fn(&str) -> anyhow::Result<mpft::Location>,
    runner: &JobRunner<'_>,
    opts: CopyOptions,
    settings: &Settings,
    args: &BatchArgs,
    progress: Option<std::sync::Arc<mpft::batch::BatchProgress>>,
) -> anyhow::Result<()> {
    let jobs = specs
        .iter()
        .enumerate()
        .map(|(i, spec)| locate_job(spec, locate).with_context(|| format!("job {}", i + 1)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let cancel = opts.cancel.clone().unwrap_or_default();
    let open = |loc: &mpft::Location| runner.open(loc, &cancel);
    let jobs = prepare_jobs(jobs, &open, args).await?;
    let n = jobs.len();
    if n == 0 {
        anstream::eprintln!("{WARN}nothing to do{WARN:#}: the job list is empty");
        return Ok(());
    }
    mpft::batch::check_collisions(&jobs)?;
    for job in &jobs {
        runner.check(job)?;
    }
    if args.dry_run {
        for (i, job) in jobs.iter().enumerate() {
            print_dry_run(job, i + 1, Some(n), settings.json);
        }
        return Ok(());
    }
    let bar = progress.clone().map(spawn_batch_progress);
    let batch_opts = mpft::BatchOptions {
        parallel: settings.parallel,
        fail_fast: args.fail_fast,
        progress,
    };
    let mut out = BatchOutput::new(Some(n), settings.json);
    let report = mpft::batch::run_with(
        jobs,
        |job, copy| runner.run(job, copy),
        &opts,
        &batch_opts,
        |r| out.job_done(r, &opts),
    )
    .await;
    clear_progress(bar);
    out.finish(&report)
}

/// Who copies a job: this process, or a relay it sends the source to.
enum JobRunner<'a> {
    Local(&'a (dyn Fn(&mpft::Location) -> mpft::Result<Box<dyn mpft::Endpoint>> + Sync)),
    #[cfg(feature = "relay")]
    Via(&'a std::sync::Arc<Via>),
}

#[cfg(feature = "relay")]
use mpft::relay::via::Via;

/// The relays in play (see [`Via::table`]), with a relay that is not an
/// SSH URL told as a wrong setting.
#[cfg(feature = "relay")]
fn via_table(
    default: Option<&str>,
    used: Option<&std::collections::BTreeSet<String>>,
    locate: &dyn Fn(&str) -> mpft::Result<mpft::Location>,
) -> anyhow::Result<Option<mpft::relay::plan::ViaTable>> {
    Via::table(default, used, locate).map_err(|e| match e {
        mpft::Error::InvalidOption { name, reason } if name == "via" => usage(reason),
        e => e.into(),
    })
}

impl JobRunner<'_> {
    /// Whether a relay takes part in `job`.
    fn relays(&self, job: &mpft::Job) -> bool {
        match self {
            JobRunner::Local(_) => {
                let _ = job;
                false
            }
            #[cfg(feature = "relay")]
            JobRunner::Via(via) => via.relays(job),
        }
    }

    /// Refuse `job` when a flag asks for what its relay cannot do.
    fn check(&self, job: &mpft::Job) -> anyhow::Result<()> {
        match self {
            JobRunner::Local(_) => {
                let _ = job;
                Ok(())
            }
            // Told with the flag that asked for it.
            #[cfg(feature = "relay")]
            JobRunner::Via(via) => via.check(job).map_err(|e| match e {
                mpft::Error::InvalidOption { name, reason } => {
                    usage(format!("--{name} is {reason}"))
                }
                e => e.into(),
            }),
        }
    }

    /// An endpoint for the expansion of patterns and trees: listed, and
    /// created as a directory, by the relay that reads or writes it.
    fn open(
        &self,
        loc: &mpft::Location,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> mpft::Result<Box<dyn mpft::Endpoint>> {
        match self {
            JobRunner::Local(open) => {
                let _ = cancel;
                open(loc)
            }
            #[cfg(feature = "relay")]
            JobRunner::Via(via) => via.open(loc, cancel),
        }
    }

    fn run(&self, job: mpft::Job, copy: CopyOptions) -> mpft::batch::JobFuture<'_> {
        match self {
            JobRunner::Local(open) => Box::pin(async move {
                let result = mpft::batch::run_job(&job, *open, &copy).await;
                (job, result)
            }),
            #[cfg(feature = "relay")]
            JobRunner::Via(via) => Box::pin(via.run(job, copy)),
        }
    }
}

/// The URLs of a job list entry as locations.
fn locate_job(
    spec: &JobSpec,
    locate: &dyn Fn(&str) -> anyhow::Result<mpft::Location>,
) -> anyhow::Result<mpft::Job> {
    Ok(mpft::Job {
        src: locate(&spec.src)?,
        dsts: spec
            .dsts
            .iter()
            .map(|d| locate(d))
            .collect::<anyhow::Result<Vec<_>>>()?,
    })
}

/// Patterns and trees turned into file jobs, directories created on the
/// way (not on a dry run).
async fn prepare_jobs(
    jobs: Vec<mpft::Job>,
    open: &(dyn Fn(&mpft::Location) -> mpft::Result<Box<dyn mpft::Endpoint>> + Sync),
    args: &BatchArgs,
) -> anyhow::Result<Vec<mpft::Job>> {
    let opts = mpft::batch::PrepareOptions {
        allow_empty: args.allow_empty,
        recursive: args.recursive,
        no_mkdir: args.dry_run,
        limit: None,
    };
    Ok(mpft::batch::prepare(jobs, open, &opts).await?)
}

fn print_dry_run(job: &mpft::Job, index: usize, total: Option<usize>, json: bool) {
    let dsts: Vec<String> = job.dsts.iter().map(|d| d.to_string()).collect();
    if json {
        println!(
            "{}",
            serde_json::json!({ "job": index, "src": job.src.to_string(), "dst": dsts })
        );
    } else {
        anstream::println!(
            "{DIM}[{}]{DIM:#} {} -> {}",
            counter(index, total),
            job.src,
            dsts.join(", ")
        );
    }
}

/// `3/120`, or just `3` when the total is not known yet.
fn counter(index: usize, total: Option<usize>) -> String {
    match total {
        Some(n) => format!("{index}/{n}"),
        None => index.to_string(),
    }
}

/// What the batch prints as jobs finish, and the verdict at the end.
struct BatchOutput {
    total: Option<usize>,
    json: bool,
    /// Exit code of every failed job (and every line that never became one).
    codes: Vec<u8>,
    cancelled: bool,
    /// Lines that were not run at all: unreadable, or a target already taken.
    rejected: usize,
}

impl BatchOutput {
    fn new(total: Option<usize>, json: bool) -> Self {
        BatchOutput {
            total,
            json,
            codes: Vec::new(),
            cancelled: false,
            rejected: 0,
        }
    }

    fn job_done(&mut self, r: &mpft::JobReport, opts: &CopyOptions) {
        let prefix = format!("[{}] ", counter(r.index + 1, self.total));
        if self.json {
            let mut line = match &r.result {
                Ok(rep) => mpft::report::fanout_json(rep),
                Err(e) => serde_json::json!({
                    "source": r.job.src.to_string(),
                    "ok": false,
                    "error": e.to_string(),
                    "cancelled": matches!(e, mpft::Error::Cancelled),
                }),
            };
            line["job"] = serde_json::Value::from(r.index + 1);
            println!("{line}");
        }
        match &r.result {
            Ok(rep) => {
                if let Some((code, msg)) = print_report(rep, opts, &prefix) {
                    if rep.targets.len() == 1 {
                        anstream::eprintln!("{prefix}{FAIL}FAILED{FAIL:#} {msg}");
                    }
                    self.codes.push(code);
                }
            }
            Err(e) => {
                anstream::eprintln!(
                    "{prefix}{FAIL}FAILED{FAIL:#} {}: {FAIL}{e}{FAIL:#}",
                    r.job.src
                );
                self.codes.push(code_of(e));
            }
        }
        self.cancelled |= r.cancelled();
    }

    /// A line of input that never became a job.
    fn rejected(&mut self, line: usize, err: &anyhow::Error) {
        anstream::eprintln!("{FAIL}line {line}:{FAIL:#} {err:#}");
        if self.json {
            println!(
                "{}",
                serde_json::json!({ "line": line, "ok": false, "error": format!("{err:#}") })
            );
        }
        self.codes.push(exit_code(err));
        self.rejected += 1;
    }

    fn finish(self, report: &mpft::BatchReport) -> anyhow::Result<()> {
        let n = report.jobs.len() + self.rejected;
        let failed = report.failures().count() + self.rejected;
        let summary = if failed == 0 { OK } else { WARN };
        anstream::eprintln!(
            "{summary}{}/{n} jobs ok{summary:#} in {NUM}{:.2?}{NUM:#}{}",
            n - failed,
            report.elapsed,
            if report.stopped_early {
                " (stopped after the first failure)"
            } else {
                ""
            }
        );
        // A batch that --fail-fast stopped was not interrupted by anyone:
        // the jobs it cancelled are consequences, and the code is that of
        // the failure which stopped it. 130 stays for Ctrl-C and SIGTERM.
        if self.cancelled && !report.stopped_early {
            return Err(
                anyhow::Error::new(Interrupted).context(format!("{failed} of {n} jobs unfinished"))
            );
        }
        if failed > 0 {
            let codes: Vec<u8> = if report.stopped_early {
                self.codes
                    .iter()
                    .copied()
                    .filter(|c| *c != INTERRUPTED)
                    .collect()
            } else {
                self.codes.clone()
            };
            return Err(anyhow::Error::new(ExitWith {
                code: batch_code(&codes),
                msg: format!("{failed} of {n} jobs failed"),
            }));
        }
        Ok(())
    }
}

/// Jobs from standard input, each run as soon as its line is complete.
/// Credentials for endpoints that turn up along the way are fetched then.
/// A line that cannot be read, resolved or would write a file an earlier
/// job writes is reported and skipped; the rest carry on.
#[allow(clippy::too_many_arguments)]
async fn do_follow(
    locate: &dyn Fn(&str) -> anyhow::Result<mpft::Location>,
    runner: &JobRunner<'_>,
    opts: CopyOptions,
    settings: &Settings,
    args: &BatchArgs,
    format: Option<Format>,
    signing: bool,
    progress: Option<std::sync::Arc<mpft::batch::BatchProgress>>,
) -> anyhow::Result<()> {
    use futures::StreamExt;
    use tokio::io::AsyncBufReadExt;

    let cancelled = opts.cancel.clone().unwrap_or_default();
    let open = |loc: &mpft::Location| runner.open(loc, &cancelled);
    let out = std::sync::Mutex::new(BatchOutput::new(None, settings.json));
    // Jobs a dry run printed instead of running them.
    let printed = std::sync::atomic::AtomicUsize::new(0);
    let cancel = opts.cancel.clone();
    let bar = progress.clone().map(spawn_batch_progress);
    let batch_opts = mpft::BatchOptions {
        parallel: settings.parallel,
        fail_fast: args.fail_fast,
        progress,
    };

    struct Reader {
        lines: tokio::io::Lines<tokio::io::BufReader<tokio::io::Stdin>>,
        format: Option<Format>,
        /// The header row of a CSV list, put in front of every later row.
        header: Option<String>,
        line: usize,
        index: usize,
        targets: mpft::batch::Targets,
    }
    let reader = Reader {
        lines: tokio::io::BufReader::new(tokio::io::stdin()).lines(),
        format,
        header: None,
        line: 0,
        index: 0,
        targets: mpft::batch::Targets::default(),
    };
    // One line in, zero or more jobs out (a pattern or a tree makes several).
    let report = {
        let jobs = futures::stream::unfold(reader, |mut r| async {
            loop {
                let next = match &cancel {
                    Some(c) => tokio::select! {
                        biased;
                        () = c.cancelled() => return None,
                        l = r.lines.next_line() => l,
                    },
                    None => r.lines.next_line().await,
                };
                let text = match next {
                    Ok(Some(l)) => l,
                    Ok(None) => return None,
                    Err(e) => {
                        out.lock()
                            .unwrap()
                            .rejected(r.line + 1, &anyhow::Error::new(e).context("reading stdin"));
                        return None;
                    }
                };
                r.line += 1;
                if text.trim().is_empty() {
                    continue;
                }
                let format = *r
                    .format
                    .get_or_insert_with(|| mpft::batch::jobs::detect(None, &text));
                let text = match (format, &r.header) {
                    (Format::Csv, None) => {
                        r.header = Some(text);
                        continue;
                    }
                    (Format::Csv, Some(h)) => format!("{h}\n{text}"),
                    _ => text,
                };
                let line = r.line;
                let before = r.index;
                let jobs = async {
                    let specs = mpft::batch::jobs::parse_entry(&text, format)?;
                    let urls: Vec<&str> = specs
                        .iter()
                        .flat_map(|j| {
                            std::iter::once(j.src.as_str()).chain(j.dsts.iter().map(String::as_str))
                        })
                        .collect();
                    mpft::config::resolve_more(&urls, signing).await?;
                    let jobs = specs
                        .iter()
                        .map(|s| locate_job(s, locate))
                        .collect::<anyhow::Result<Vec<_>>>()?;
                    let jobs = prepare_jobs(jobs, &open, args).await?;
                    for job in &jobs {
                        runner.check(job)?;
                    }
                    // All of the line's jobs or none: a rejected line
                    // leaves no target claimed.
                    r.targets.note_all(&jobs, r.index + 1)?;
                    r.index += jobs.len();
                    anyhow::Ok(jobs)
                }
                .await;
                match jobs {
                    Ok(jobs) if args.dry_run => {
                        for (i, job) in jobs.iter().enumerate() {
                            print_dry_run(job, before + i + 1, None, settings.json);
                        }
                        printed.fetch_add(jobs.len(), std::sync::atomic::Ordering::Relaxed);
                    }
                    Ok(jobs) => return Some((futures::stream::iter(jobs), r)),
                    Err(e) => {
                        // A rejected line takes no job numbers with it.
                        r.index = before;
                        out.lock().unwrap().rejected(line, &e);
                    }
                }
            }
        })
        .flatten();
        futures::pin_mut!(jobs);
        mpft::batch::run_stream_with(
            jobs,
            |job, copy| runner.run(job, copy),
            &opts,
            &batch_opts,
            |r| out.lock().unwrap().job_done(r, &opts),
        )
        .await
    };
    clear_progress(bar);
    let out = out.into_inner().unwrap();
    let printed = printed.into_inner();
    if report.jobs.is_empty() && printed == 0 && out.rejected == 0 {
        anstream::eprintln!("{WARN}nothing to do{WARN:#}: no jobs arrived");
        return Ok(());
    }
    if args.dry_run {
        // Nothing ran: the lines that were rejected are all there is to say.
        return match out.rejected {
            0 => Ok(()),
            n => Err(anyhow::Error::new(ExitWith {
                code: batch_code(&out.codes),
                msg: match n {
                    1 => "1 line rejected".to_string(),
                    n => format!("{n} lines rejected"),
                },
            })),
        };
    }
    out.finish(&report)
}

/// Stop a progress task and wipe its line.
fn clear_progress(bar: Option<tokio::task::JoinHandle<()>>) {
    if let Some(bar) = bar {
        bar.abort();
        if std::io::IsTerminal::is_terminal(&std::io::stderr()) {
            anstream::eprint!("\r\u{1b}[2K");
        }
    }
}

/// Whether to draw a progress line: `auto` means a terminal on stderr and no
/// JSON on stdout, because a progress line is for a person to watch.
fn show_progress(cli: &Cli, settings: &Settings) -> bool {
    match cli.progress.unwrap_or(ColorChoice::Auto) {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => !settings.json && std::io::IsTerminal::is_terminal(&std::io::stderr()),
    }
}

/// Redraw the progress line four times a second until the task is dropped.
fn spawn_progress(
    progress: std::sync::Arc<mpft::transfer::Progress>,
) -> tokio::task::JoinHandle<()> {
    spawn_progress_line(move |secs| {
        let read = progress.read();
        let rate = format!("{}/s", human_size((read as f64 / secs) as u64));
        match progress.total() {
            Some(total) if total > 0 => format!(
                "{} / {} ({:>3.0}%)  {rate}",
                human_size(read),
                human_size(total),
                read as f64 * 100.0 / total as f64
            ),
            _ => format!("{}  {rate}", human_size(read)),
        }
    })
}

/// The progress line of a batch: jobs done, jobs failed, bytes so far.
fn spawn_batch_progress(
    progress: std::sync::Arc<mpft::batch::BatchProgress>,
) -> tokio::task::JoinHandle<()> {
    spawn_progress_line(move |secs| {
        let bytes = progress.bytes();
        let rate = format!("{}/s", human_size((bytes as f64 / secs) as u64));
        let failed = match progress.failed() {
            0 => String::new(),
            n => format!(", {n} failed"),
        };
        format!(
            "{} jobs{failed}, {}  {rate}",
            counter(progress.done(), Some(progress.total()).filter(|t| *t > 0)),
            human_size(bytes)
        )
    })
}

/// Draw whatever `line` renders, given the seconds elapsed, four times a
/// second until the task is dropped.
fn spawn_progress_line(
    line: impl Fn(f64) -> String + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    // Redrawing in place needs a terminal; anywhere else (a log file, because
    // --progress always was asked for) each reading gets its own line.
    let tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tick.tick().await;
            let line = line(started.elapsed().as_secs_f64().max(0.001));
            if tty {
                // \r and "erase to end of line": one line, redrawn in place.
                anstream::eprint!("\r\u{1b}[2K{DIM}{line}{DIM:#}");
            } else {
                anstream::eprintln!("{line}");
            }
        }
    })
}

/// Sizes as a person reads them: 1.4 MiB rather than 1468006.
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Print computed digests and the `--check` verdict; a mismatch is an error.
fn print_checksums(
    report: &mpft::FanoutReport,
    opts: &CopyOptions,
    prefix: &str,
) -> Option<(u8, String)> {
    for (algo, hex) in &report.digests {
        anstream::eprintln!(
            "{prefix}{HEAD}{:<7}{HEAD:#} {NUM}{hex}{NUM:#}",
            algo.to_string()
        );
    }
    if let Some(s) = &opts.sign
        && report
            .targets
            .iter()
            .any(|t| t.signature.is_some() || t.result.is_ok())
    {
        anstream::eprintln!(
            "{prefix}{HEAD}signed {HEAD:#} {DIM}{} ({}){DIM:#}",
            s.identity(),
            s.format().label()
        );
    }
    if let Some(c) = &report.checked {
        if let Some(who) = &c.signer {
            anstream::eprintln!("{prefix}{OK}signature ok{OK:#} {DIM}{who}{DIM:#}");
        }
        if c.ok() {
            anstream::eprintln!("{prefix}{OK}check ok{OK:#} ({})", c.algo.label());
        } else {
            anstream::eprintln!(
                "{prefix}{FAIL}CHECK FAILED{FAIL:#} ({}): expected {NUM}{}{NUM:#}, got {NUM}{}{NUM:#}",
                c.algo.label(),
                c.expected,
                c.actual
            );
            let e = c.error();
            return Some((code_of(&e), e.to_string()));
        }
    }
    None
}

/// What became of the source under `--delete-source`: a line either way,
/// and a failure when it could not be deleted (the copy itself succeeded).
fn print_removed(report: &mpft::FanoutReport, prefix: &str) -> Option<(u8, String)> {
    match &report.source_removed {
        None => None,
        Some(Ok(())) => {
            anstream::eprintln!("{prefix}{DIM}source deleted{DIM:#}");
            None
        }
        Some(Err(e)) => Some((
            FAILED,
            format!(
                "copied, but deleting the source {} failed: {e}",
                report.source
            ),
        )),
    }
}

/// Parse sizes like `512`, `64K`, `256M`, `2G` (binary units).
#[cfg(feature = "relay")]
fn parse_credentials(s: &str) -> Result<mpft::relay::Credentials, String> {
    s.parse().map_err(|e: mpft::Error| e.to_string())
}

#[cfg(feature = "relay")]
fn parse_relay_credentials(s: &str) -> Result<mpft::relay::RelayCredentials, String> {
    s.parse().map_err(|e: mpft::Error| e.to_string())
}

fn parse_size(s: &str) -> Result<u64, String> {
    mpft::config::parse_size(s)
}

/// The signing key: the `--sign` value, with the key file from `[signing] key`
/// filled in when the flag only names a format (`--sign ssh`).
fn sign_spec(raw: &str) -> anyhow::Result<SignSpec> {
    let mut raw = raw.to_string();
    if !raw.contains(':')
        && let Some((fmt, key)) = mpft::config::global()
            .signing
            .key
            .as_deref()
            .and_then(|c| c.split_once(':'))
        && mpft::SignFormat::parse(fmt).ok() == mpft::SignFormat::parse(&raw).ok()
    {
        raw = format!("{raw}:{}", mpft::config::expand_tilde(key));
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
    let v = &mpft::config::global().verify;
    Ok(
        match (
            mpft::config::path(&v.allowed_signers),
            mpft::config::path(&v.keyring),
        ) {
            (Some(p), _) => Some(VerifySpec::SshAllowedSigners(p)),
            (_, Some(p)) => Some(VerifySpec::PgpKeyring(p)),
            _ => None,
        },
    )
}

/// The server's settings: the flags of `mpft serve`, then `[server]`, then
/// the built-in values. The token is fetched here, once.
#[cfg(feature = "server")]
async fn server_config(
    args: &ServeArgs,
    cfg: &mpft::Config,
) -> anyhow::Result<mpft::server::ServerConfig> {
    use mpft::credentials::{Secret, SecretRef, Source};
    let s = &cfg.server;
    let mut out = mpft::server::ServerConfig::default();
    if let Some(bind) = args.bind.as_deref().or(s.bind.as_deref()) {
        out.bind = bind
            .parse()
            .map_err(|e| usage(format!("bind address '{bind}' (expected host:port): {e}")))?;
    }
    let token = match &args.token_env {
        Some(var) => Some(Secret::Reference(SecretRef::from(Source::Env(var.clone())))),
        None => s.token.clone(),
    };
    if let Some(t) = token {
        out.token = Some(t.resolve("[server] token").await?);
    }
    out.journal = args
        .journal
        .clone()
        .or_else(|| mpft::config::path(&s.journal));
    if let Some(v) = args.retention.as_deref().or(s.retention.as_deref()) {
        out.retention =
            mpft::config::parse_duration(v).map_err(|e| usage(format!("retention: {e}")))?;
    }
    if let Some(n) = args.parallel.or(s.parallel) {
        out.parallel = n;
    }
    if let Some(v) = &s.max_body {
        out.max_body = mpft::config::parse_size(v)
            .map_err(|e| usage(format!("[server] max_body: {e}")))? as usize;
    }
    match (args.grace, s.grace.as_deref()) {
        (Some(secs), _) => out.grace = Duration::from_secs(secs),
        (None, Some(v)) => {
            out.grace = mpft::config::parse_duration(v)
                .map_err(|e| usage(format!("[server] grace: {e}")))?;
        }
        (None, None) => {}
    }
    out.port_file = args.port_file.clone();
    out.allow_delete = args.allow_delete || s.allow_delete.unwrap_or(false);
    if let Some(n) = args.max_transfers.or(s.max_transfers) {
        out.max_transfers = n;
    }
    if let Some(n) = args.max_queued.or(s.max_queued) {
        out.max_queued = n;
    }
    out.urls = if args.allow_any_url {
        mpft::config::UrlRule::Any
    } else {
        s.urls.unwrap_or_default()
    };
    out.profiles = s.profiles.clone();
    Ok(out)
}

/// What `mpft relay --listen` needs, from the flags and `[relay]`.
#[cfg(feature = "relay")]
fn relay_listener(
    addr: &str,
    args: &RelayArgs,
    section: &mpft::config::RelaySection,
) -> anyhow::Result<mpft::relay::sshd::Listener> {
    let listen = addr
        .parse()
        .map_err(|e| usage(format!("listen address '{addr}' (expected host:port): {e}")))?;
    let host_key = args
        .host_key
        .clone()
        .or_else(|| mpft::config::path(&section.host_key))
        .unwrap_or_else(|| {
            dirs::state_dir()
                .or_else(dirs::data_local_dir)
                .unwrap_or_else(|| PathBuf::from("."))
                .join("mpft")
                .join("relay_host_key")
        });
    let authorized_keys = args
        .authorized_keys
        .clone()
        .or_else(|| mpft::config::path(&section.authorized_keys))
        .or_else(|| {
            mpft::config::Config::default_path().map(|p| p.with_file_name("authorized_keys"))
        })
        .ok_or_else(|| {
            usage("no home directory to look for authorized_keys in: give --authorized-keys")
        })?;
    let parallel = match args.parallel.or(section.parallel).unwrap_or(4) {
        0 => return Err(usage("parallel must be at least 1")),
        n => n,
    };
    let grace = match (args.grace, section.grace.as_deref()) {
        (Some(secs), _) => Duration::from_secs(secs),
        (None, Some(v)) => {
            mpft::config::parse_duration(v).map_err(|e| usage(format!("[relay] grace: {e}")))?
        }
        (None, None) => Duration::from_secs(30),
    };
    Ok(mpft::relay::sshd::Listener {
        listen,
        host_key,
        authorized_keys,
        parallel,
        grace,
        port_file: args.port_file.clone(),
        agent_forwarding: !args.no_agent_forwarding && section.agent_forwarding.unwrap_or(true),
    })
}

/// Ctrl-C, or SIGTERM where there is one: what systemd's `stop` and
/// `docker stop` send. Both mean the same here, so a service is drained
/// rather than killed. The listeners live as long as the process: a signal
/// that comes while nobody waits for it is kept for the next wait, not
/// swallowed.
struct Interrupts {
    #[cfg(unix)]
    int: tokio::signal::unix::Signal,
    #[cfg(unix)]
    term: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl Interrupts {
    fn install() -> std::io::Result<Interrupts> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Interrupts {
                int: signal(SignalKind::interrupt())?,
                term: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Interrupts {
                ctrl_c: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    /// The next signal; `false` once none can come any more.
    async fn next(&mut self) -> bool {
        #[cfg(unix)]
        {
            tokio::select! {
                r = self.int.recv() => r.is_some(),
                r = self.term.recv() => r.is_some(),
            }
        }
        #[cfg(windows)]
        {
            self.ctrl_c.recv().await.is_some()
        }
    }
}

/// `mpft profiles`: the named targets and what they resolve to.
fn show_profiles(cfg: &mpft::Config) {
    if cfg.profiles.is_empty() {
        anstream::println!(
            "{DIM}no profiles; add [profiles.<name>] with url = \"…\" to the configuration{DIM:#}"
        );
        return;
    }
    for (name, profile) in &cfg.profiles {
        // Resolving masks the password and shows the options as they will be used.
        let resolved = match cfg.resolve(&format!("{}{name}", mpft::config::PROFILE_PREFIX)) {
            Ok(Some(loc)) => loc.masked(),
            Ok(None) | Err(_) => profile.url.clone(),
        };
        anstream::println!("{HEAD}mpft://{name}{HEAD:#}  {DIM}{resolved}{DIM:#}");
        for (what, v) in [
            ("sign", profile.sign.as_deref()),
            ("hash", profile.hash.as_deref()),
            ("via", profile.via.as_deref()),
        ] {
            if let Some(v) = v {
                anstream::println!("    {what:<6} {NUM}{v}{NUM:#}");
            }
        }
        if let Some(a) = profile.atomic {
            anstream::println!("    {:<6} {NUM}{a}{NUM:#}", "atomic");
        }
    }
}

/// `mpft config check`: where the configuration came from and what it sets.
/// Reaching this point already means it parsed and every key is known.
fn show_config(cfg: &mpft::Config) {
    if cfg.sources.is_empty() {
        anstream::println!(
            "{WARN}no configuration file{WARN:#} (looked for {})",
            mpft::config::Config::default_path()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "~/.config/mpft/config.toml".into())
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
    // A secret is not shown, only whether it is written out or fetched.
    let secret = |s: &Option<mpft::credentials::Secret>| {
        s.as_ref().map(|s| match s {
            mpft::credentials::Secret::Literal(_) => "*** (in the file)",
            mpft::credentials::Secret::Reference(_) => "(reference)",
        })
    };
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
        "defaults".resume = d.resume,
        "defaults".skip_existing = d.skip_existing,
        "defaults".delete_source = d.delete_source,
        "defaults".log = d.log,
        "defaults".json = d.json,
        "defaults".parallel = d.parallel,
        "defaults".via = d.via,
        "defaults".via_credentials = d.via_credentials,
        "defaults".via_agent = d.via_agent,
        "policy".known_hosts = p.known_hosts,
        "policy".refuse_plaintext_auth = p.refuse_plaintext_auth,
        "policy".refuse_insecure_tls = p.refuse_insecure_tls,
        "policy".require_signature = p.require_signature,
        "policy".strict_permissions = p.strict_permissions,
        "policy".max_signature_age = p.max_signature_age,
        "signing".key = cfg.signing.key,
        "signing".agent_fingerprint = cfg.signing.agent_fingerprint,
        "signing".passphrase = secret(&cfg.signing.passphrase),
        "verify".allowed_signers = cfg.verify.allowed_signers,
        "verify".keyring = cfg.verify.keyring,
        "ssh".user = cfg.ssh.user,
        "ssh".key = cfg.ssh.key,
        "ssh".cert = cfg.ssh.cert,
        "ssh".passphrase = secret(&cfg.ssh.passphrase),
        "ssh".known_hosts_file = cfg.ssh.known_hosts_file,
        "mail".smtp = cfg.mail.smtp.as_deref().map(mpft::location::mask_url),
        "mail".password = secret(&cfg.mail.password),
        "mail".auth = cfg.mail.auth,
        "mail".from = cfg.mail.from,
        "mail".max_attachment = cfg.mail.max_attachment,
        "http".token = secret(&cfg.http.token),
        "s3".endpoint = cfg.s3.endpoint,
        "s3".region = cfg.s3.region,
        "s3".path_style = cfg.s3.path_style,
        "s3".access_key_id = secret(&cfg.s3.access_key_id),
        "s3".secret_access_key = secret(&cfg.s3.secret_access_key),
        "s3".profile = cfg.s3.profile,
        "server".bind = cfg.server.bind,
        "server".token = secret(&cfg.server.token),
        "server".journal = cfg.server.journal,
        "server".retention = cfg.server.retention,
        "server".parallel = cfg.server.parallel,
        "server".max_body = cfg.server.max_body,
        "server".grace = cfg.server.grace,
        "server".urls = cfg.server.urls,
        "server".allow_delete = cfg.server.allow_delete,
        "server".max_transfers = cfg.server.max_transfers,
        "server".max_queued = cfg.server.max_queued,
        "relay".host_key = cfg.relay.host_key,
        "relay".authorized_keys = cfg.relay.authorized_keys,
        "relay".parallel = cfg.relay.parallel,
        "relay".grace = cfg.relay.grace,
        "relay".max_size = cfg.relay.max_size,
        "relay".max_entries = cfg.relay.max_entries,
        "relay".credentials = cfg.relay.credentials,
        "relay".agent_forwarding = cfg.relay.agent_forwarding,
        "relay".allow_delete = cfg.relay.allow_delete,
        "relay".own_keys = cfg.relay.own_keys,
        "relay".local_files = cfg.relay.local_files,
    );
    if !cfg.server.profiles.is_empty() {
        rows.push(("[server] profiles".into(), cfg.server.profiles.join(", ")));
    }
    if !cfg.ssh.hostkey.is_empty() {
        rows.push(("[ssh] hostkey".into(), cfg.ssh.hostkey.join(", ")));
    }
    if !cfg.http.hosts.is_empty() {
        rows.push(("[http] hosts".into(), cfg.http.hosts.join(", ")));
    }
    // The profiles by name; `mpft profiles` shows what they hold.
    if !cfg.profiles.is_empty() {
        rows.push((
            "[profiles]".into(),
            cfg.profiles.keys().cloned().collect::<Vec<_>>().join(", "),
        ));
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
        let mut all = vec!["mpft"];
        all.extend_from_slice(args);
        all.extend_from_slice(&["cp", "a", "b"]);
        Cli::parse_from(all)
    }

    fn config(text: &str) -> mpft::Config {
        mpft::Config::parse(text).unwrap()
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
        let s = Settings::resolve(&cli(&[]), &mpft::Config::default()).unwrap();
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
    fn sizes_are_readable() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(40_000_000), "38.1 MiB");
        assert_eq!(human_size(5 << 30), "5.0 GiB");
    }

    #[test]
    fn a_batch_exits_with_what_its_failures_agree_on() {
        assert_eq!(batch_code(&[]), 0);
        assert_eq!(batch_code(&[DENIED]), DENIED);
        assert_eq!(batch_code(&[DENIED, DENIED]), DENIED);
        assert_eq!(batch_code(&[UNTRUSTED, UNTRUSTED]), UNTRUSTED);
        assert_eq!(batch_code(&[DENIED, FAILED]), FAILED);
        assert_eq!(batch_code(&[UNTRUSTED, DENIED]), FAILED);
        let e = anyhow::Error::new(ExitWith {
            code: DENIED,
            msg: "2 of 3 jobs failed".into(),
        });
        assert_eq!(exit_code(&e), DENIED);
        assert_eq!(format!("{e:#}"), "2 of 3 jobs failed");
    }

    #[test]
    fn cp_with_a_target_flag_makes_a_job_per_source() {
        let cli = Cli::parse_from([
            "mpft",
            "cp",
            "-t",
            "sftp://h/in/",
            "-t",
            "s3://b/",
            "a",
            "b",
            "c",
        ]);
        let Work::Many(jobs) = cli.cmd.work().unwrap() else {
            panic!("expected a job list");
        };
        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[2].src, "c");
        assert_eq!(jobs[2].dsts, vec!["sftp://h/in/", "s3://b/"]);
        assert_eq!(
            cli.cmd.work().unwrap().urls(None),
            vec![
                "a",
                "sftp://h/in/",
                "s3://b/",
                "b",
                "sftp://h/in/",
                "s3://b/",
                "c",
                "sftp://h/in/",
                "s3://b/"
            ]
        );

        let cli = Cli::parse_from(["mpft", "cp", "a", "b", "c"]);
        let Work::Single { src, dsts, .. } = cli.cmd.work().unwrap() else {
            panic!("expected a single copy");
        };
        assert_eq!(src, "a");
        assert_eq!(dsts, vec!["b", "c"]);

        let cli = Cli::parse_from(["mpft", "cp", "a"]);
        let err = cli.cmd.work().unwrap_err().to_string();
        assert!(err.contains("-t"), "{err}");
    }

    #[test]
    fn parallel_comes_from_the_flag_then_the_configuration() {
        let cli = Cli::parse_from(["mpft", "batch", "jobs.txt"]);
        let s = Settings::resolve(&cli, &config("")).unwrap();
        assert_eq!(s.parallel, 4);
        let s = Settings::resolve(&cli, &config("[defaults]\nparallel = 8")).unwrap();
        assert_eq!(s.parallel, 8);
        let cli = Cli::parse_from(["mpft", "batch", "--parallel", "2", "jobs.txt"]);
        let s = Settings::resolve(&cli, &config("[defaults]\nparallel = 8")).unwrap();
        assert_eq!(s.parallel, 2);
        let cli = Cli::parse_from(["mpft", "batch", "--parallel", "0", "jobs.txt"]);
        assert!(Settings::resolve(&cli, &config("")).is_err());
    }

    #[test]
    fn errors_map_to_exit_codes() {
        let code = |e: mpft::Error| exit_code(&anyhow::Error::new(e));
        assert_eq!(code(mpft::Error::Auth("no".into())), DENIED);
        assert_eq!(code(mpft::Error::Signature("bad key".into())), UNTRUSTED);
        assert_eq!(
            code(mpft::Error::ChecksumMismatch {
                algo: "SHA-256",
                expected: "a".into(),
                actual: "b".into()
            }),
            UNTRUSTED
        );
        assert_eq!(code(mpft::Error::InvalidUrl("x".into())), USAGE);
        assert_eq!(code(mpft::Error::Config("x".into())), USAGE);
        assert_eq!(code(mpft::Error::Remote("server said no".into())), FAILED);
        // The type is found through the context a caller wrapped it in.
        let wrapped = anyhow::Error::new(mpft::Error::Auth("no".into())).context("copy a -> b");
        assert_eq!(exit_code(&wrapped), DENIED);
        // Ctrl-C beats whatever else went wrong.
        let interrupted = anyhow::Error::new(Interrupted).context("2 of 3 targets unfinished");
        assert_eq!(exit_code(&interrupted), INTERRUPTED);
        assert_eq!(exit_code(&anyhow::anyhow!("something else")), FAILED);
    }

    /// A batch stopped by --fail-fast exits with the code of the failure
    /// that stopped it, not with 130: the cancelled jobs after it are a
    /// consequence, not an interruption.
    #[test]
    fn a_batch_stopped_by_fail_fast_keeps_the_failures_code() {
        let job = |index: usize, result: mpft::Result<mpft::FanoutReport>| mpft::JobReport {
            index,
            job: mpft::Job {
                src: mpft::Location::parse("a.txt").unwrap(),
                dsts: vec![mpft::Location::parse("out/").unwrap()],
            },
            result,
        };
        let report = |stopped_early: bool| mpft::BatchReport {
            jobs: vec![
                job(0, Err(mpft::Error::Auth("refused".into()))),
                job(1, Err(mpft::Error::Cancelled)),
                job(2, Err(mpft::Error::Cancelled)),
            ],
            elapsed: std::time::Duration::from_millis(3),
            stopped_early,
        };
        let opts = CopyOptions::default();
        let outcome = |stopped_early: bool| {
            let mut out = BatchOutput::new(Some(3), false);
            for j in &report(stopped_early).jobs {
                out.job_done(j, &opts);
            }
            exit_code(&out.finish(&report(stopped_early)).unwrap_err())
        };
        assert_eq!(outcome(true), DENIED);
        assert_eq!(outcome(false), INTERRUPTED);
    }

    #[test]
    fn the_json_report_says_what_happened() {
        let report = mpft::FanoutReport {
            source: "a.txt".into(),
            bytes_read: 8,
            elapsed: std::time::Duration::from_millis(1200),
            targets: vec![
                mpft::TargetReport {
                    target: "sftp://h/in/".into(),
                    bytes: 8,
                    elapsed: std::time::Duration::from_millis(30),
                    attempts: 1,
                    result: Ok(()),
                    sidecar: Some("sftp://h/in/a.txt.sha256".into()),
                    signature: None,
                    skipped: false,
                },
                mpft::TargetReport {
                    target: "ftp://h/in/".into(),
                    bytes: 0,
                    elapsed: std::time::Duration::from_millis(5),
                    attempts: 3,
                    result: Err(mpft::Error::Auth("wrong password".into())),
                    sidecar: None,
                    signature: None,
                    skipped: false,
                },
            ],
            digests: vec![(HashAlgo::Sha256, "abc".into())],
            checked: None,
            source_removed: None,
        };
        let j = mpft::report::fanout_json(&report);
        assert_eq!(j["ok"], false, "one target failed");
        assert_eq!(j["bytes_read"], 8);
        assert_eq!(j["elapsed_ms"], 1200);
        assert_eq!(j["digests"]["sha256"], "abc");
        assert_eq!(j["targets"][0]["ok"], true);
        assert_eq!(j["targets"][0]["sidecar"], "sftp://h/in/a.txt.sha256");
        assert_eq!(j["targets"][1]["ok"], false);
        assert_eq!(j["targets"][1]["attempts"], 3);
        assert!(
            j["targets"][1]["error"]
                .as_str()
                .unwrap()
                .contains("wrong password")
        );
        assert_eq!(j["check"], serde_json::Value::Null);
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
