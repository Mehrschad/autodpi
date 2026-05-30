# autodpi


**Automatic DPI bypass strategy finder & transparent forwarder.**
For Persian guid click : [Persian Guid](docs/README.fa.md)
Most anti-censorship tools implement *one* evasion technique and leave you to
hand-tune dozens of parameters until something works on your ISP. `autodpi`
flips that around: it **probes how your network's DPI blocks a target, sweeps a
catalogue of evasion strategies, ranks them, and runs a local forwarder that
applies the winner.** Point your existing client (xray / v2ray / a browser) at
the local listener and you are done.

> Inspired by the SNI-Spoofing idea of [@patterniha](https://github.com/patterniha/SNI-Spoofing)
> and its Rust port by [@therealaleph](https://github.com/therealaleph/sni-spoofing-rust),
> plus the wider DPI-bypass ecosystem (GoodbyeDPI, zapret, byedpi, SpoofDPI).
> `autodpi`'s contribution is the **automatic discovery layer** on top.

---

## Why

DPI (Deep Packet Inspection) censorship varies enormously between ISPs and
countries. A config that works for one person fails for another, so people
resort to copy-pasting settings and trial-and-error. The hard part is **finding
the strategy that works on _your_ network** — that is exactly what `autodpi`
automates.

## How it works

```
 probe  ──►  measure how the DPI reacts to each evasion technique
   │
 tune   ──►  retry + rank strategies by (success rate, latency)
   │
 run    ──►  transparent local forwarder applies the winning strategy
```

1. **Probe** — opens a TCP connection to the upstream IP, sends a TLS
   ClientHello carrying the (possibly blocked) SNI using the technique under
   test, and classifies what comes back:
   `PASS` (got a ServerHello), `reset` (DPI killed it), `timeout`, etc.
2. **Tune** — repeats every strategy a few times for stability and ranks them.
3. **Run** — a transparent TCP forwarder. It reads the first chunk from your
   client (the real ClientHello), delivers it with the chosen strategy, then
   relays bytes both ways untouched. **It never decrypts your traffic.**

## Strategy catalogue (current)

All of these are **userspace-only** — no root, no raw sockets, no kernel driver.
They work by controlling TCP segmentation and timing of the ClientHello.

| name                | technique                                            |
|---------------------|------------------------------------------------------|
| `direct`            | no manipulation (control / baseline)                 |
| `split-sni`         | split the stream *inside* the SNI hostname           |
| `split-sni-slow`    | same, with a small inter-segment delay               |
| `split-1`           | split after the first byte                           |
| `split-5`           | split after the TLS record header                    |
| `multisplit-4`      | break the ClientHello into 4 small segments          |
| `multisplit-8-slow` | 8 segments with delay (against reassembling DPI)     |

More invasive techniques (out-of-window **fake ClientHello injection** à la
patterniha, low-TTL fake packets, TCP disorder) need a raw-socket backend and
are on the [roadmap](#roadmap) — they plug in by implementing the same
`Strategy` trait.

## Build

```sh
cargo build --release
# binary at ./target/release/autodpi
```

Requires a recent stable Rust toolchain. No system dependencies.

## Usage

```sh
# 1. See how each strategy fares against a target (resolve the host's IP first)
autodpi probe --sni www.example.com --ip 93.184.216.34

# 2. Let autodpi rank them and recommend one
autodpi tune  --sni www.example.com --ip 93.184.216.34 --rounds 5

# 3. Run the forwarder from a config file
autodpi run   --config config.json -v
```

### config.json

```json
{
  "listeners": [
    {
      "listen": "127.0.0.1:40443",
      "connect": "104.18.4.130:443",
      "sni": "www.example.com",
      "strategy": "split-sni"
    }
  ]
}
```

| field      | description                                              |
|------------|----------------------------------------------------------|
| `listen`   | local address to accept connections on                   |
| `connect`  | upstream `ip:port` (must be an IP, not a hostname)        |
| `sni`      | hostname used when auto-tuning this listener (optional)  |
| `strategy` | chosen strategy name (optional; defaults to `split-sni`) |

Multiple listeners are supported — each maps to one upstream.

### With xray / v2ray

Point your VLESS/VMess client at `127.0.0.1:<listen_port>` instead of the real
server. `autodpi` handles the DPI bypass transparently; your client's real TLS
handshake flows through after the initial segment trick.

## Project layout

```
src/
  main.rs          CLI dispatch
  cli.rs           argument parsing (no external dep)
  logging.rs       minimal log backend
  config.rs        config.json model
  clienthello.rs   build a probe ClientHello + find the SNI split offset
  strategy.rs      Strategy trait + userspace strategies + catalogue
  probe.rs         single-strategy active probe + verdict classification
  tuner.rs         sweep, rank, report
  forwarder.rs     transparent TCP forwarder
```

## Roadmap

- [ ] **Raw-socket backend** (Linux AF_PACKET / macOS BPF / Windows WinDivert)
- [ ] **Fake ClientHello injection** strategy (out-of-window seq, patterniha's method)
- [ ] **Low-TTL fake packet** strategy
- [ ] **QUIC / HTTP3** probing and bypass
- [ ] Persist tuned results back into `config.json`
- [ ] Opt-in, anonymised **strategy-sharing database** ("works on ISP X in country Y")
- [ ] Cross-platform GUI

## Design notes & honest caveats

- DPI evasion is a cat-and-mouse game; **no strategy is permanent**. Re-tune when
  things stop working.
- `autodpi` only manipulates **your own outbound traffic**. It does not attack,
  probe, or exploit the destination server — the bypass relies on segmenting the
  ClientHello, not on harming anyone.
- Userspace splitting defeats a large class of DPI but not all of it. IP-level
  blocks and some stateful DPI need the raw-socket backend (roadmap).

## Credits

- Original SNI-Spoofing idea & Windows implementation: [@patterniha](https://github.com/patterniha/SNI-Spoofing)
- Rust port that inspired this codebase: [@therealaleph](https://github.com/therealaleph/sni-spoofing-rust)
- The broader ecosystem: GoodbyeDPI, zapret, byedpi, SpoofDPI, and others.

## License

[MIT](LICENSE)
