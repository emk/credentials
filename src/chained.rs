//! Backend which tries multiple other backends, in sequence.

use backend::{Backend, BoxedError, err};
use envvar;
use vault;

/// Fetches credentials from various other backends, based on which ones
/// we've been configured to use.
pub struct Client {
    backends: Vec<Box<Backend>>,
}

impl Client {
    /// Create a new environment variable client.
    fn new() -> Client {
        Client { backends: vec!() }
    }

    /// Add a new backend to our list, after the existing ones.
    fn add<B: Backend + 'static>(&mut self, backend: B) {
        self.backends.push(Box::new(backend));
    }

    /// Set up the standard chain, based on what appears to be available.
    pub fn new_default() -> Result<Client, BoxedError> {
        let mut client = Client::new();
        client.add(try!(envvar::Client::new_default()));
        if vault::Client::is_enabled() {
            client.add(try!(vault::Client::new_default()));
        }
        Ok(client)
    }
}

impl Backend for Client {
    fn var(&mut self, credential: &str) -> Result<String, BoxedError> {
        // We want to return either the first success or the last error.
        let mut result = Err(err("No backend available"));
        for backend in self.backends.iter_mut() {
            result = backend.var(credential);
            if result.is_ok() {
                break;
            }
        }
        result
    }

    fn file(&mut self, path: &str) -> Result<String, BoxedError> {
        // We want to return either the first success or the last error.
        let mut result = Err(err("No backend available"));
        for backend in self.backends.iter_mut() {
            result = backend.file(path);
            if result.is_ok() {
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use backend::{Backend, BoxedError, err};
    use envvar;
    use std::env;

    struct DummyClient;

    impl DummyClient {
        pub fn new_default() -> Result<DummyClient, BoxedError> {
            Ok(DummyClient)
        }
    }

    impl Backend for DummyClient {
        fn var(&mut self, credential: &str) -> Result<String, BoxedError> {
            if credential == "DUMMY" {
                Ok("dummy".to_owned())
            } else {
                Err(err("Credential not supported"))
            }
        }

        fn file(&mut self, path: &str) -> Result<String, BoxedError> {
            if path == "dummy.txt" {
                Ok("dummy2".to_owned())
            } else {
                Err(err("Credential not supported"))
            }
        }
    }

    #[test]
    fn test_chaining() {
        let mut client = Client::new();
        client.add(envvar::Client::new_default().unwrap());
        client.add(DummyClient::new_default().unwrap());

        env::set_var("FOO_USERNAME", "user");
        assert_eq!("user", client.var("FOO_USERNAME").unwrap());
        assert_eq!("dummy", client.var("DUMMY").unwrap());
        assert!(client.var("NOSUCHVAR").is_err());

        assert_eq!("dummy2", client.file("dummy.txt").unwrap());
        assert!(client.file("nosuchfile.txt").is_err());
    }
}
