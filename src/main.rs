//! autodpi — automatic DPI bypass strategy finder & transparent forwarder.
//!
//! Subcommands:
//!   probe  — test every strategy once against one target
//!   tune   — sweep + rank strategies, recommend the best
//!   run    — start forwarder(s) from config.json

mod clienthello;
mod cli;
mod config;
mod forwarder;
mod logging;
mod probe;
mod strategy;
mod tuner;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::warn;

use cli::Command;
use config::Config;

fn main() -> Result<()> {
    let parsed = cli::parse(std::env::args().skip(1))?;
    logging::init(parsed.verbose);

    match parsed.command {
        Command::Help => {
            print!("{}", cli::USAGE);
            Ok(())
        }
        Command::Version => {
            println!("autodpi {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }

        Command::Probe(t) => {
            let timeout = Duration::from_millis(t.timeout_ms);
            println!("probing {} via {}:{}", t.sni, t.ip, t.port);
            println!();
            println!("{:<20} {:>16}", "strategy", "verdict");
            println!("{}", "-".repeat(38));
            for strat in strategy::default_catalogue() {
                let r = probe::probe(strat.as_ref(), &t.ip, t.port, &t.sni, timeout);
                let extra = r
                    .latency
                    .map(|d| format!("  ({} ms)", d.as_millis()))
                    .unwrap_or_default();
                println!("{:<20} {:>16}{}", r.strategy, r.verdict.label(), extra);
            }
            Ok(())
        }

        Command::Tune { target, rounds } => {
            let timeout = Duration::from_millis(target.timeout_ms);
            println!(
                "tuning {} via {}:{} ({} rounds each)",
                target.sni, target.ip, target.port, rounds
            );
            let entries = tuner::tune(&target.ip, target.port, &target.sni, timeout, rounds);
            if let Some(best) = tuner::report(&entries) {
                println!();
                println!("add this to a listener in config.json:");
                println!("  \"strategy\": \"{best}\"");
            }
            Ok(())
        }

        Command::Run { config } => {
            let cfg = Config::load(Path::new(&config))?;
            if cfg.listeners.is_empty() {
                return Err(anyhow!("config has no listeners"));
            }
            let mut jobs: Vec<(String, String, Arc<dyn strategy::Strategy>)> = Vec::new();
            for l in cfg.listeners {
                let name = l.strategy.as_deref().unwrap_or("split-sni");
                let strat = strategy::by_name(name).unwrap_or_else(|| {
                    warn!("unknown strategy \"{name}\", falling back to split-sni");
                    strategy::by_name("split-sni").expect("split-sni exists")
                });
                jobs.push((l.listen, l.connect, Arc::from(strat)));
            }
            forwarder::run_many(jobs)
        }
    }
}
