//! Look and print the credentials specified on the command line.

use std::env;

use anyhow::Result;
use tracing_subscriber::{
    fmt::{format::FmtSpan, Subscriber},
    prelude::*,
    EnvFilter,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Enable tracing.  To see what's happening, set `RUST_LOG=trace`.
    //
    // This is optional, but very handy for debugging.
    Subscriber::builder()
        .with_writer(std::io::stderr)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_env_filter(EnvFilter::from_default_env())
        .finish()
        .init();

    // Print our each credential specified on the command line.
    for secret in env::args().skip(1) {
        let value = credentials::var(&secret).await?;
        println!("{}={}", &secret, value);
    }

    Ok(())
}
