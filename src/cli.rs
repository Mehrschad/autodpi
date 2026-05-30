//! Hand-rolled command-line parsing — no external arg-parser dependency.

use anyhow::{anyhow, bail, Result};

pub const USAGE: &str = "\
autodpi — automatic DPI bypass strategy finder & transparent forwarder

USAGE:
    autodpi <COMMAND> [OPTIONS]

COMMANDS:
    probe   Test every strategy once against one target, print verdicts
    tune    Sweep + rank strategies (with retries), recommend the best
    run     Start forwarder(s) from a config file
    help    Show this help

PROBE / TUNE OPTIONS:
    --sni <HOST>        SNI / hostname to test (the thing that may be blocked)
    --ip <ADDR>         Upstream IP address
    --port <PORT>       Upstream port [default: 443]
    --timeout-ms <MS>   Per-attempt timeout [default: 4000]
    --rounds <N>        (tune only) retries per strategy [default: 3]

RUN OPTIONS:
    --config <PATH>     Path to config.json [default: config.json]

GLOBAL:
    -v, -vv             Increase log verbosity
    -h, --help          Show this help
    -V, --version       Show version

EXAMPLES:
    autodpi probe --sni www.youtube.com --ip 142.250.185.78
    autodpi tune  --sni example.com --ip 93.184.216.34 --rounds 5
    autodpi run   --config config.json -v
";

#[derive(Debug, Clone)]
pub struct Target {
    pub sni: String,
    pub ip: String,
    pub port: u16,
    pub timeout_ms: u64,
}

#[derive(Debug)]
pub enum Command {
    Probe(Target),
    Tune { target: Target, rounds: u32 },
    Run { config: String },
    Help,
    Version,
}

pub struct Parsed {
    pub command: Command,
    pub verbose: u8,
}

/// Parse `std::env::args()` (without the program name).
pub fn parse<I: Iterator<Item = String>>(mut args: I) -> Result<Parsed> {
    let sub = match args.next() {
        Some(s) => s,
        None => return Ok(Parsed { command: Command::Help, verbose: 0 }),
    };

    if matches!(sub.as_str(), "-h" | "--help" | "help") {
        return Ok(Parsed { command: Command::Help, verbose: 0 });
    }
    if matches!(sub.as_str(), "-V" | "--version") {
        return Ok(Parsed { command: Command::Version, verbose: 0 });
    }

    // Collect remaining flags into a simple map / counters.
    let mut opts: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut verbose: u8 = 0;
    let rest: Vec<String> = args.collect();
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        match a.as_str() {
            "-v" => verbose += 1,
            "-vv" => verbose += 2,
            "--verbose" => verbose += 1,
            "-h" | "--help" => return Ok(Parsed { command: Command::Help, verbose }),
            s if s.starts_with("--") => {
                let key = s.trim_start_matches("--").to_string();
                let val = rest
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| anyhow!("option --{key} needs a value"))?;
                opts.insert(key, val);
                i += 1;
            }
            other => bail!("unexpected argument: {other}"),
        }
        i += 1;
    }

    let command = match sub.as_str() {
        "probe" => Command::Probe(target_from(&opts)?),
        "tune" => {
            let rounds = opts
                .get("rounds")
                .map(|s| s.parse::<u32>())
                .transpose()?
                .unwrap_or(3);
            Command::Tune { target: target_from(&opts)?, rounds }
        }
        "run" => Command::Run {
            config: opts.get("config").cloned().unwrap_or_else(|| "config.json".into()),
        },
        other => bail!("unknown command: {other} (try `autodpi help`)"),
    };

    Ok(Parsed { command, verbose })
}

fn target_from(opts: &std::collections::HashMap<String, String>) -> Result<Target> {
    let sni = opts
        .get("sni")
        .cloned()
        .ok_or_else(|| anyhow!("--sni is required"))?;
    let ip = opts
        .get("ip")
        .cloned()
        .ok_or_else(|| anyhow!("--ip is required"))?;
    let port = opts.get("port").map(|s| s.parse::<u16>()).transpose()?.unwrap_or(443);
    let timeout_ms = opts
        .get("timeout-ms")
        .map(|s| s.parse::<u64>())
        .transpose()?
        .unwrap_or(4000);
    Ok(Target { sni, ip, port, timeout_ms })
}
