use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand};
use mpt::{Location, Scheme};

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

    /// Password for the source and target if not given in the URL
    #[arg(long, env = "MPT_PASSWORD", global = true, hide_env_values = true)]
    password: Option<String>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Copy from one URL to another
    Copy { src: String, dst: String },
    /// List a directory
    Ls { url: String },
    /// Send a local file to a URL (shorthand for copy <file> <url>)
    Send { file: PathBuf, dst: String },
    /// Receive a URL into a local path (default: current directory)
    Recv { src: String, dst: Option<PathBuf> },
    /// Show supported URL schemes and their options
    Schemes,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    mpt::init_crypto();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
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

    match &cli.cmd {
        Cmd::Copy { src, dst } => do_copy(open(src)?, open(dst)?).await,
        Cmd::Send { file, dst } => do_copy(open(&file.to_string_lossy())?, open(dst)?).await,
        Cmd::Recv { src, dst } => {
            let target = match dst {
                Some(p) => p.to_string_lossy().into_owned(),
                None => "./".to_string(),
            };
            do_copy(open(src)?, open(&target)?).await
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
                println!("{kind} {size:>12}  {}", e.name);
            }
            Ok(())
        }
        Cmd::Schemes => {
            println!(
                "{:<11} {:<5} {:<5} {:<7} {:<9} options",
                "prefix", "recv", "send", "port", "feature"
            );
            for i in Scheme::ALL {
                let yn = |b: bool| if b { "yes" } else { "no" };
                let port = i
                    .default_port
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into());
                println!(
                    "{:<11} {:<5} {:<5} {:<7} {:<9} {}",
                    i.prefix,
                    yn(i.can_receive),
                    yn(i.can_send),
                    port,
                    i.feature,
                    i.options
                );
                println!("{:<11} {}", "", i.description);
            }
            println!(
                "\nCredentials: user[:password]@ in the URL, else MPT_PASSWORD / MPT_SMTP_PASSWORD."
            );
            println!(
                "SSH keys: MPT_SSH_KEY, else ssh-agent (SSH_AUTH_SOCK), else ~/.ssh/id_ed25519, id_rsa."
            );
            println!(
                "Mail: MPT_SMTP_URL (for mailto:), MPT_MAIL_FROM.  S3: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_ENDPOINT_URL."
            );
            Ok(())
        }
    }
}

async fn do_copy(src: Box<dyn mpt::Endpoint>, dst: Box<dyn mpt::Endpoint>) -> anyhow::Result<()> {
    let report = mpt::copy(src.as_ref(), dst.as_ref())
        .await
        .with_context(|| format!("copy {} -> {}", src.location(), dst.location()))?;
    eprintln!(
        "{} -> {}: {} bytes in {:.2?}",
        report.source, report.target, report.bytes, report.elapsed
    );
    Ok(())
}
