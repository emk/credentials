//! Generic interface to secret storage backends.

use errors::BoxedError;

/// Generic interface to a secret-storage backend.
pub trait Backend: Send + Sync {
    /// Get the value of the specified secret.
    fn var(&mut self, credential: &str) -> Result<String, BoxedError>;

    /// Get the value of the specified credential file.
    fn file(&mut self, path: &str) -> Result<String, BoxedError>;
}
