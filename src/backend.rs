//! Generic interface to secret storage backends.

use crate::errors::*;
use crate::secretfile::Secretfile;

/// Generic interface to a secret-storage backend.
#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    /// Return the name of this backend.
    fn name(&self) -> &'static str;

    /// Get the value of the specified secret.
    async fn var(
        &mut self,
        secretfile: &Secretfile,
        credential: &str,
    ) -> Result<String>;

    /// Get the value of the specified credential file.
    async fn file(&mut self, secretfile: &Secretfile, path: &str) -> Result<String>;
}
