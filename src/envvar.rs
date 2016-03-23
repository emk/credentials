//! A backend which reads from environment variables.

use backend::Backend;
use errors::BoxedError;
use std::env;
use std::fs;
use std::io::Read;

/// Fetches credentials from environment variables.
pub struct Client;

impl Client {
    /// Create a new environment variable client.
    pub fn new_default() -> Result<Client, BoxedError> {
        Ok(Client)
    }
}

impl Backend for Client {
    fn var(&mut self, credential: &str) -> Result<String, BoxedError> {
        Ok(try!(env::var(credential)))
    }

    fn file(&mut self, path: &str) -> Result<String, BoxedError> {
        let mut f = try!(fs::File::open(path));
        let mut contents = String::new();
        try!(f.read_to_string(&mut contents));
        Ok(contents)
    }
}

#[test]
fn test_var() {
    let mut client = Client::new_default().unwrap();
    env::set_var("FOO_USERNAME", "user");
    assert_eq!("user", client.var("FOO_USERNAME").unwrap());
    assert!(client.var("NOSUCHVAR").is_err());
}

#[test]
fn test_file() {
    let mut client = Client::new_default().unwrap();

    // Some arbitrary file contents.
    let mut f = fs::File::open("Cargo.toml").unwrap();
    let mut expected = String::new();
    f.read_to_string(&mut expected).unwrap();

    assert_eq!(expected, client.file("Cargo.toml").unwrap());
    assert!(client.file("nosuchfile.txt").is_err());
}
