//! Access secure credentials at runtime with multiple backends.
//!
//! ```
//! use credentials;
//! use std::env;
//!
//! env::set_var("PASSWORD", "secret");
//! assert_eq!("secret", credentials::get("PASSWORD").unwrap());
//! ```

use std::convert::AsRef;
use std::env;

/// An error occurred accessing credentials.
#[derive(Clone, Copy, Debug)]
pub struct CredentialError;

/// Fetch the value of a credential.
pub fn get<K: AsRef<str>>(key: K) -> Result<String, CredentialError> {
    env::var(key.as_ref()).map_err(|_| {
        CredentialError
    })
}
