//! A backend which reads from environment variables.

use log::debug;
use std::env;
use std::fs;
use std::io::Read;

use crate::backend::Backend;
use crate::errors::*;
use crate::secretfile::Secretfile;

/// Fetches credentials from environment variables.
pub struct Client;

impl Client {
    /// Create a new environment variable client.
    pub fn default() -> Result<Client> {
        Ok(Client)
    }
}

#[async_trait::async_trait]
impl Backend for Client {
    fn name(&self) -> &'static str {
        "env"
    }

    async fn var(
        &mut self,
        _secretfile: &Secretfile,
        credential: &str,
    ) -> Result<String> {
        let value = env::var(credential).map_err(|err| {
            Error::UndefinedEnvironmentVariable {
                name: credential.to_owned(),
                source: err,
            }
        })?;
        debug!("Found credential {} in environment", credential);
        Ok(value)
    }

    async fn file(&mut self, _secretfile: &Secretfile, path: &str) -> Result<String> {
        let mut f = fs::File::open(path)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;
        debug!("Found credential in local file {}", path);
        Ok(contents)
    }
}

#[tokio::test]
async fn test_var() {
    use std::str::FromStr;
    let sf = Secretfile::from_str("").unwrap();
    let mut client = Client::default().unwrap();
    env::set_var("FOO_USERNAME", "user");
    assert_eq!("user", client.var(&sf, "FOO_USERNAME").await.unwrap());
    assert!(client.var(&sf, "NOSUCHVAR").await.is_err());
}

#[tokio::test]
async fn test_file() {
    use std::str::FromStr;
    let sf = Secretfile::from_str("").unwrap();
    let mut client = Client::default().unwrap();

    // Some arbitrary file contents.
    let mut f = fs::File::open("Cargo.toml").unwrap();
    let mut expected = String::new();
    f.read_to_string(&mut expected).unwrap();

    assert_eq!(expected, client.file(&sf, "Cargo.toml").await.unwrap());
    assert!(client.file(&sf, "nosuchfile.txt").await.is_err());
}
