# Contributing to autodpi

Thanks for your interest! This project helps people reach the open internet, so
contributions of new evasion strategies, platform support, and test results from
real networks are especially valuable.

## Adding a new strategy

1. Implement the `Strategy` trait in `src/strategy.rs` (or a submodule).
2. Add an instance to `default_catalogue()` with a stable, descriptive `name`.
3. Make sure it is resolvable by `by_name()` (the catalogue handles this).
4. Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test`.

A strategy only decides *how the first ClientHello is written to the upstream
socket*. Userspace strategies (segmentation/timing) need no special privileges.
Raw-socket strategies should live behind a platform-gated module and degrade
gracefully where unavailable.

## Reporting what works

If you find a strategy that beats DPI on a specific ISP/country, open an issue
with: country, ISP/carrier, the winning strategy name, and the target type
(e.g. "YouTube", "VLESS endpoint"). Please do **not** include personal data.

## Ground rules

- Keep the dependency footprint small — this is a security-sensitive tool.
- Never add code that attacks or probes third-party servers beyond a normal
  client connection. We only manipulate the user's own outbound traffic.
- Be kind in reviews and issues.
