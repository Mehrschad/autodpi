//! Transparent TCP forwarder.
//!
//! For each accepted client connection we open an upstream connection, read the
//! first chunk (the real TLS ClientHello produced by the user's own client),
//! deliver it using the chosen [`Strategy`], and then relay bytes in both
//! directions untouched. We never terminate or decrypt TLS — the client's real
//! handshake flows through after the initial segment trick.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};

use crate::strategy::Strategy;

/// Start a blocking forwarder on `listen`, dialing `connect` for each client.
pub fn run(listen: &str, connect: String, strategy: Arc<dyn Strategy>) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .with_context(|| format!("failed to bind listener on {listen}"))?;
    info!(
        "listening on {listen} -> {connect} using strategy \"{}\"",
        strategy.name()
    );

    for incoming in listener.incoming() {
        match incoming {
            Ok(client) => {
                let connect = connect.clone();
                let strategy = Arc::clone(&strategy);
                thread::spawn(move || {
                    if let Err(e) = handle(client, &connect, strategy) {
                        debug!("connection closed: {e}");
                    }
                });
            }
            Err(e) => warn!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(mut client: TcpStream, connect: &str, strategy: Arc<dyn Strategy>) -> Result<()> {
    client.set_nodelay(true).ok();
    let mut upstream = TcpStream::connect(connect)
        .with_context(|| format!("failed to connect upstream {connect}"))?;
    upstream.set_nodelay(true).ok();

    // Read the first chunk from the client (expected: the TLS ClientHello).
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    let mut first = vec![0u8; 16 * 1024];
    let n = client.read(&mut first).context("reading client hello")?;
    if n == 0 {
        return Ok(()); // client closed immediately
    }
    first.truncate(n);
    client.set_read_timeout(None).ok();

    // Apply the bypass technique to the very first payload.
    strategy
        .send_initial(&mut upstream, &first)
        .context("sending initial payload upstream")?;

    // From here on, relay raw bytes both ways.
    let mut client_rx = client.try_clone().context("clone client")?;
    let mut upstream_tx = upstream.try_clone().context("clone upstream")?;

    let up = thread::spawn(move || {
        let _ = copy_loop(&mut client_rx, &mut upstream_tx);
        // half-close so the peer learns we are done
        let _ = upstream_tx.shutdown(std::net::Shutdown::Write);
    });

    let _ = copy_loop(&mut upstream, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

fn copy_loop(from: &mut TcpStream, to: &mut TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        to.write_all(&buf[..n])?;
        to.flush()?;
    }
}

/// Run several listeners at once, one thread per listener.
pub fn run_many(
    listeners: Vec<(String, String, Arc<dyn Strategy>)>,
) -> Result<()> {
    let mut handles = Vec::new();
    for (listen, connect, strategy) in listeners {
        handles.push(thread::spawn(move || {
            if let Err(e) = run(&listen, connect, strategy) {
                error!("listener {listen} stopped: {e}");
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}
