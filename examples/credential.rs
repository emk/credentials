//! Look and print the credentials specified on the command line.

extern crate credentials;

use std::env;
use std::io::{self, Write};
use std::process;

fn main() {
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
