//! Look and print the credentials specified on the command line.

use std::env;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Enable logging.  To see what's happening, set `RUST_LOG=trace`.  It
    // is recommended that you include and initialie `env_logger` in your
    // programs using credentials.
    env_logger::init();

    // Print our each credential specified on the command line.
    for secret in env::args().skip(1) {
        let value = credentials::var(&secret).await?;
        println!("{}={}", &secret, value);
    }

    Ok(())
}
