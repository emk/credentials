//! A backend which reads from environment variables.

use backend::{Backend, BoxedError};
use std::env;

/// Fetches credentials from environment variables.
pub struct Client;

impl Client {
    /// Create a new environment variable client.
    pub fn new_default() -> Result<Client, BoxedError> {
        Ok(Client)
    }
}

impl Backend for Client {
    fn get(&mut self, credential: &str) -> Result<String, BoxedError> {
        Ok(try!(env::var(credential)))
    }
}

#[test]
fn test_get() {
    let mut client = Client::new_default().unwrap();
    env::set_var("FOO_USERNAME", "user");
    assert_eq!("user", client.get("FOO_USERNAME").unwrap());
    assert!(client.get("NOSUCHVAR").is_err());
}
