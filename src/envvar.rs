//! A backend which reads from environment variables.

use backend::Backend;
use errors::*;
use secretfile::Secretfile;
use std::env;
use std::fs;
use std::io::Read;

/// Fetches credentials from environment variables.
pub struct Client;

impl Client {
    /// Create a new environment variable client.
    pub fn default() -> Result<Client> {
        Ok(Client)
    }
}

impl Backend for Client {
    fn name(&self) -> &'static str {
        "env"
    }

    fn var(&mut self, _secretfile: &Secretfile, credential: &str) ->
        Result<String>
    {
        let value = try!(env::var(credential)
            .chain_err(|| {
                ErrorKind::UndefinedEnvironmentVariable(credential.to_owned())
            }));
        debug!("Found credential {} in environment", credential);
        Ok(value)
    }

    fn file(&mut self, _secretfile: &Secretfile, path: &str) ->
        Result<String>
    {
        let mut f = try!(fs::File::open(path));
        let mut contents = String::new();
        try!(f.read_to_string(&mut contents));
        debug!("Found credential in local file {}", path);
        Ok(contents)
    }
}

#[test]
fn test_var() {
    let sf = Secretfile::from_str("").unwrap();
    let mut client = Client::default().unwrap();
    env::set_var("FOO_USERNAME", "user");
    assert_eq!("user", client.var(&sf, "FOO_USERNAME").unwrap());
    assert!(client.var(&sf, "NOSUCHVAR").is_err());
}

#[test]
fn test_file() {
    let sf = Secretfile::from_str("").unwrap();
    let mut client = Client::default().unwrap();

    // Some arbitrary file contents.
    let mut f = fs::File::open("Cargo.toml").unwrap();
    let mut expected = String::new();
    f.read_to_string(&mut expected).unwrap();

    assert_eq!(expected, client.file(&sf, "Cargo.toml").unwrap());
    assert!(client.file(&sf, "nosuchfile.txt").is_err());
}
