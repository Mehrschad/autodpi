//! Auto-tuner: sweep the strategy catalogue against a target, repeat each a few
//! times for stability, then rank by (success rate, latency).

use std::time::Duration;

use crate::probe::{probe, ProbeResult, Verdict};
use crate::strategy::{default_catalogue, Strategy};

/// Aggregated score for one strategy across several attempts.
#[derive(Debug, Clone)]
pub struct TuneEntry {
    pub strategy: String,
    pub passes: u32,
    pub attempts: u32,
    pub best_latency: Option<Duration>,
    pub last_verdict: Verdict,
}

impl TuneEntry {
    pub fn pass_rate(&self) -> f64 {
        if self.attempts == 0 {
            0.0
        } else {
            self.passes as f64 / self.attempts as f64
        }
    }
}

/// Run the full sweep. `rounds` is how many times each strategy is retried.
pub fn tune(ip: &str, port: u16, sni: &str, timeout: Duration, rounds: u32) -> Vec<TuneEntry> {
    let catalogue = default_catalogue();
    let mut entries: Vec<TuneEntry> = Vec::with_capacity(catalogue.len());

    for strat in &catalogue {
        let mut passes = 0u32;
        let mut best: Option<Duration> = None;
        let mut last = Verdict::Timeout;
        for _ in 0..rounds.max(1) {
            let ProbeResult {
                verdict, latency, ..
            } = probe(strat.as_ref(), ip, port, sni, timeout);
            if verdict.is_pass() {
                passes += 1;
                if let Some(l) = latency {
                    best = Some(best.map_or(l, |b| b.min(l)));
                }
            }
            last = verdict;
        }
        entries.push(TuneEntry {
            strategy: strat.name().to_string(),
            passes,
            attempts: rounds.max(1),
            best_latency: best,
            last_verdict: last,
        });
    }

    // Rank: higher pass-rate first, then lower latency, then name for stability.
    entries.sort_by(|a, b| {
        b.pass_rate()
            .partial_cmp(&a.pass_rate())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| match (a.best_latency, b.best_latency) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            })
            .then_with(|| a.strategy.cmp(&b.strategy))
    });
    entries
}

/// Pretty-print a ranked table and return the name of the recommended strategy.
pub fn report(entries: &[TuneEntry]) -> Option<String> {
    println!();
    println!("{:<20} {:>8} {:>12} {:>16}", "strategy", "pass", "latency", "last verdict");
    println!("{}", "-".repeat(58));
    for e in entries {
        let lat = e
            .best_latency
            .map(|d| format!("{} ms", d.as_millis()))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<20} {:>5}/{:<2} {:>12} {:>16}",
            e.strategy,
            e.passes,
            e.attempts,
            lat,
            e.last_verdict.label()
        );
    }
    println!();

    let best = entries.iter().find(|e| e.passes > 0);
    match best {
        Some(e) => {
            println!("recommended strategy: \"{}\"", e.strategy);
            Some(e.strategy.clone())
        }
        None => {
            println!("no strategy got through — the block may be IP-level, or needs the");
            println!("raw-socket backend (fake ClientHello injection — see roadmap).");
            None
        }
    }
}

/// Convenience used by callers that just want the winning [`Strategy`].
#[allow(dead_code)] // public API convenience for library users
pub fn best_strategy(entries: &[TuneEntry]) -> Option<Box<dyn Strategy>> {
    entries
        .iter()
        .find(|e| e.passes > 0)
        .and_then(|e| crate::strategy::by_name(&e.strategy))
}
