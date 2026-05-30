//! A tiny `log` backend so we avoid an external logger dependency.

use log::{Level, LevelFilter, Metadata, Record};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let tag = match record.level() {
                Level::Error => "error",
                Level::Warn => "warn",
                Level::Info => "info",
                Level::Debug => "debug",
                Level::Trace => "trace",
            };
            eprintln!("[{tag}] {}", record.args());
        }
    }
    fn flush(&self) {}
}

static LOGGER: SimpleLogger = SimpleLogger;

/// Initialise logging. `verbose`: 0 = warn, 1 = info, 2+ = debug.
pub fn init(verbose: u8) {
    let level = match verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(level);
}
