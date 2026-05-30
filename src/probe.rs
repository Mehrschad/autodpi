//! Active probing: does a given strategy get a TLS handshake past the DPI?
//!
//! We open a TCP connection to the upstream IP, send a ClientHello carrying the
//! (potentially blocked) SNI using the strategy under test, and observe what
//! comes back. A genuine `ServerHello` (TLS handshake record, type 0x16) means
//! the flow survived. A reset or silence is the signature of active DPI.

use std::io::{ErrorKind, Read};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::clienthello::build_client_hello;
use crate::strategy::Strategy;

/// The classified outcome of a single probe attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Server replied with a TLS handshake record — the flow got through.
    Pass,
    /// Connection was reset, almost certainly by DPI after seeing the SNI.
    Reset,
    /// No data before timeout — silent drop or throttling.
    Timeout,
    /// We could not even establish the TCP connection (often IP-level block).
    ConnectFailed,
    /// Got data, but not a TLS handshake (possible block page / hijack).
    Unexpected,
}

impl Verdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Reset => "reset (DPI)",
            Verdict::Timeout => "timeout",
            Verdict::ConnectFailed => "connect failed",
            Verdict::Unexpected => "unexpected reply",
        }
    }
}

/// Result of probing one strategy.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub strategy: String,
    pub verdict: Verdict,
    pub latency: Option<Duration>,
}

/// Probe a single strategy against `ip:port` using `sni`.
pub fn probe(
    strategy: &dyn Strategy,
    ip: &str,
    port: u16,
    sni: &str,
    timeout: Duration,
) -> ProbeResult {
    let name = strategy.name().to_string();
    let addr: SocketAddr = match format!("{ip}:{port}").to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return fail(name, Verdict::ConnectFailed),
        },
        Err(_) => return fail(name, Verdict::ConnectFailed),
    };

    let start = Instant::now();
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return fail(name, Verdict::ConnectFailed),
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let hello = build_client_hello(sni);
    if strategy.send_initial(&mut stream, &hello).is_err() {
        // A write error immediately after the hello is itself a reset signature.
        return fail(name, Verdict::Reset);
    }

    let mut buf = [0u8; 16];
    let verdict = match stream.read(&mut buf) {
        Ok(0) => Verdict::Timeout, // clean EOF without data ~ silent drop
        Ok(_) if buf[0] == 0x16 => Verdict::Pass,
        Ok(_) => Verdict::Unexpected,
        Err(e) => match e.kind() {
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => Verdict::Reset,
            ErrorKind::WouldBlock | ErrorKind::TimedOut => Verdict::Timeout,
            _ => Verdict::Timeout,
        },
    };
    let latency = verdict.is_pass().then(|| start.elapsed());

    ProbeResult {
        strategy: name,
        verdict,
        latency,
    }
}

fn fail(strategy: String, verdict: Verdict) -> ProbeResult {
    ProbeResult {
        strategy,
        verdict,
        latency: None,
    }
}
