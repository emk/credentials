//! Look and print the credentials specified on the command line.

extern crate credentials;
extern crate env_logger;

use std::env;
use std::io::{self, Write};
use std::process;

fn main() {
    // Enable logging.  To see what's happening, set `RUST_LOG=trace`.  It
    // is recommended that you include and initialie `env_logger` in your
    // programs using credentials.
    env_logger::init().unwrap();

    // Print our each credential specified on the command line.
    for secret in env::args().skip(1) {
        match credentials::get(&secret) {
            Ok(ref value) => println!("{}={}", &secret, value),
            Err(err) => {
                writeln!(&mut io::stderr(), "Error: {}", err).unwrap();
                process::exit(1);
            }
        }
    }
}
