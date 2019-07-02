//! Backend which tries multiple other backends, in sequence.

use log::debug;

use crate::backend::Backend;
use crate::envvar;
use crate::errors::*;
use crate::secretfile::Secretfile;
use crate::vault;

/// Fetches credentials from various other backends, based on which ones
/// we've been configured to use.
pub struct Client {
    backends: Vec<Box<Backend>>,
}

impl Client {
    /// Create a new environment variable client.
    fn new() -> Client {
        Client { backends: vec![] }
    }

    /// Add a new backend to our list, after the existing ones.
    fn add<B: Backend + 'static>(&mut self, backend: B) {
        self.backends.push(Box::new(backend));
    }

    /// Set up the standard chain, based on what appears to be available.
    pub fn with_default_backends(allow_override: bool) -> Result<Client> {
        let mut client = Client::new();
        if vault::Client::is_enabled() {
            if allow_override {
                client.add(envvar::Client::default()?);
            }
            client.add(vault::Client::default()?);
        } else {
            client.add(envvar::Client::default()?);
        }

        let names: Vec<_> = client.backends.iter().map(|b| b.name()).collect();
        debug!("Enabled backends: {}", names.join(", "));

        Ok(client)
    }
}

impl Backend for Client {
    fn name(&self) -> &'static str {
        "chained"
    }

    fn var(&mut self, secretfile: &Secretfile, credential: &str) -> Result<String> {
        // We want to return either the first success or the last error.
        let mut err: Option<Error> = None;
        for backend in self.backends.iter_mut() {
            match backend.var(secretfile, credential) {
                Ok(value) => {
                    return Ok(value);
                }
                Err(e) => {
                    err = Some(e);
                }
            }
        }
        Err(err.unwrap_or(Error::NoBackend))
    }

    fn file(&mut self, secretfile: &Secretfile, path: &str) -> Result<String> {
        // We want to return either the first success or the last error.
        let mut err: Option<Error> = None;
        for backend in self.backends.iter_mut() {
            match backend.file(secretfile, path) {
                Ok(value) => {
                    return Ok(value);
                }
                Err(e) => {
                    err = Some(e);
                }
            }
        }
        Err(err.unwrap_or(Error::NoBackend))
    }
}

#[cfg(test)]
mod tests {
    use failure::format_err;
    use std::env;

    use super::Client;
    use crate::backend::Backend;
    use crate::envvar;
    use crate::errors::*;
    use crate::secretfile::Secretfile;

    struct DummyClient;

    impl DummyClient {
        pub fn default() -> Result<DummyClient> {
            Ok(DummyClient)
        }
    }

    impl Backend for DummyClient {
        fn name(&self) -> &'static str {
            "dummy"
        }

        fn var(
            &mut self,
            _secretfile: &Secretfile,
            credential: &str,
        ) -> Result<String> {
            if credential == "DUMMY" {
                Ok("dummy".to_owned())
            } else {
                Err(format_err!("Credential not supported").into())
            }
        }

        fn file(&mut self, _secretfile: &Secretfile, path: &str) -> Result<String> {
            if path == "dummy.txt" {
                Ok("dummy2".to_owned())
            } else {
                Err(format_err!("Credential not supported").into())
            }
        }
    }

    #[test]
    fn test_chaining() {
        let sf = Secretfile::from_str("").unwrap();
        let mut client = Client::new();
        client.add(envvar::Client::default().unwrap());
        client.add(DummyClient::default().unwrap());

        env::set_var("FOO_USERNAME", "user");
        assert_eq!("user", client.var(&sf, "FOO_USERNAME").unwrap());
        assert_eq!("dummy", client.var(&sf, "DUMMY").unwrap());
        assert!(client.var(&sf, "NOSUCHVAR").is_err());

        assert_eq!("dummy2", client.file(&sf, "dummy.txt").unwrap());
        assert!(client.file(&sf, "nosuchfile.txt").is_err());
    }
}
