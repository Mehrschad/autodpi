//! Bypass strategies.
//!
//! A [`Strategy`] decides *how* the first chunk of client traffic (the TLS
//! ClientHello) is written to the upstream socket. All strategies in this module
//! are **userspace-only**: they need no root/raw-sockets and work by controlling
//! TCP segmentation and timing. That covers a large fraction of real-world DPI.
//!
//! More invasive techniques (out-of-window fake ClientHello injection, fake
//! packets with a low TTL, etc.) require a raw-socket backend and are tracked in
//! the project roadmap — they plug in here by implementing the same trait.

use std::io::{self, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use crate::clienthello::find_sni_split_offset;

/// How the initial ClientHello is delivered to the upstream server.
pub trait Strategy: Send + Sync {
    /// Short stable identifier, used in config files and CLI output.
    fn name(&self) -> &str;
    /// One-line human description.
    fn description(&self) -> &str;
    /// Write `data` (the first client payload) to `upstream`.
    fn send_initial(&self, upstream: &mut TcpStream, data: &[u8]) -> io::Result<()>;
}

fn write_segments(upstream: &mut TcpStream, parts: &[&[u8]], delay: Duration) -> io::Result<()> {
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        upstream.write_all(part)?;
        upstream.flush()?;
        if i + 1 < parts.len() && !delay.is_zero() {
            thread::sleep(delay);
        }
    }
    Ok(())
}

/// Baseline: write everything in one go. Used as the control in tuning.
pub struct Direct;

impl Strategy for Direct {
    fn name(&self) -> &str {
        "direct"
    }
    fn description(&self) -> &str {
        "No manipulation (baseline / control)"
    }
    fn send_initial(&self, upstream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        upstream.write_all(data)?;
        upstream.flush()
    }
}

/// Split the ClientHello at a fixed byte offset into two TCP segments.
pub struct SplitAtOffset {
    pub id: String,
    pub offset: usize,
    pub delay: Duration,
}

impl Strategy for SplitAtOffset {
    fn name(&self) -> &str {
        &self.id
    }
    fn description(&self) -> &str {
        "Split ClientHello at a fixed byte offset"
    }
    fn send_initial(&self, upstream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        let off = self.offset.min(data.len());
        write_segments(upstream, &[&data[..off], &data[off..]], self.delay)
    }
}

/// Split the ClientHello *inside* the SNI hostname, so DPI cannot reassemble the
/// SNI from a single segment. Falls back to a mid-buffer split if no SNI found.
pub struct SplitAtSni {
    pub id: String,
    pub delay: Duration,
}

impl Strategy for SplitAtSni {
    fn name(&self) -> &str {
        &self.id
    }
    fn description(&self) -> &str {
        "Split inside the SNI hostname"
    }
    fn send_initial(&self, upstream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        let off = find_sni_split_offset(data).unwrap_or(data.len() / 2).min(data.len());
        write_segments(upstream, &[&data[..off], &data[off..]], self.delay)
    }
}

/// Split the ClientHello into `parts` roughly equal segments.
pub struct MultiSplit {
    pub id: String,
    pub parts: usize,
    pub delay: Duration,
}

impl Strategy for MultiSplit {
    fn name(&self) -> &str {
        &self.id
    }
    fn description(&self) -> &str {
        "Split ClientHello into several small segments"
    }
    fn send_initial(&self, upstream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        let n = self.parts.max(1);
        let step = (data.len() + n - 1) / n;
        let mut segs: Vec<&[u8]> = Vec::with_capacity(n);
        let mut i = 0;
        while i < data.len() {
            let end = (i + step).min(data.len());
            segs.push(&data[i..end]);
            i = end;
        }
        write_segments(upstream, &segs, self.delay)
    }
}

/// The default catalogue of strategies that the tuner sweeps over.
pub fn default_catalogue() -> Vec<Box<dyn Strategy>> {
    let d = Duration::from_millis(0);
    let slow = Duration::from_millis(40);
    vec![
        Box::new(Direct),
        Box::new(SplitAtSni {
            id: "split-sni".into(),
            delay: d,
        }),
        Box::new(SplitAtSni {
            id: "split-sni-slow".into(),
            delay: slow,
        }),
        Box::new(SplitAtOffset {
            id: "split-1".into(),
            offset: 1,
            delay: d,
        }),
        Box::new(SplitAtOffset {
            id: "split-5".into(),
            offset: 5,
            delay: d,
        }),
        Box::new(MultiSplit {
            id: "multisplit-4".into(),
            parts: 4,
            delay: d,
        }),
        Box::new(MultiSplit {
            id: "multisplit-8-slow".into(),
            parts: 8,
            delay: slow,
        }),
    ]
}

/// Resolve a strategy by its config name. Returns `None` for unknown names.
pub fn by_name(name: &str) -> Option<Box<dyn Strategy>> {
    default_catalogue().into_iter().find(|s| s.name() == name)
}
