//! Generic interface to secret storage backends.

use errors::*;
use secretfile::Secretfile;

/// Generic interface to a secret-storage backend.
pub trait Backend: Send + Sync {
    /// Return the name of this backend.
    fn name(&self) -> &'static str;

    /// Get the value of the specified secret.
    fn var(&mut self, secretfile: &Secretfile, credential: &str) -> Result<String>;

    /// Get the value of the specified credential file.
    fn file(&mut self, secretfile: &Secretfile, path: &str) -> Result<String>;
}
