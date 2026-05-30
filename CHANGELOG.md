# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - Unreleased

### Added
- `probe` command: test every strategy once against a target and classify the
  verdict (PASS / reset / timeout / connect-failed / unexpected).
- `tune` command: sweep strategies with retries, rank by success rate then
  latency, and recommend one.
- `run` command: transparent multi-listener TCP forwarder that applies a chosen
  strategy to the initial ClientHello and relays the rest untouched.
- Userspace strategy catalogue: `direct`, `split-sni`, `split-sni-slow`,
  `split-1`, `split-5`, `multisplit-4`, `multisplit-8-slow`.
- Hand-built TLS 1.2 ClientHello generator and tolerant SNI-offset parser.
- `config.json` compatible with the SNI-Spoofing layout, plus per-listener
  `strategy` and `sni` fields.
