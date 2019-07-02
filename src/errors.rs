//! Various error types used internally, and in our public APIs.

use failure::{self, Fail};
use reqwest;
use serde_json;
use std::env;
use std::io;
use std::path::PathBuf;
use std::result;

/// A result returned by functions in `Credentials`.
pub type Result<T> = result::Result<T, Error>;

/// An error returned by `credentials`.
#[derive(Debug, Fail)]
pub enum Error {
    /// Could not access a secure credential.
    #[fail(display = "can't access secure credential '{}': {}", name, cause)]
    Credential {
        /// The name of the credential we couldn't access.
        name: String,
        /// The reason why we couldn't access it.
        cause: Box<Error>,
    },

    /// Could not read file.
    #[fail(display = "problem reading file {:?}: {}", path, cause)]
    FileRead {
        /// The file we couldn't access.
        path: PathBuf,
        /// The reason why we couldn't access it.
        cause: Box<Error>,
    },

    /// We encountered an invalid URL.
    #[fail(display = "invalid URL {:?}", url)]
    InvalidUrl {
        /// The invalid URL.
        url: String,
    },

    /// An error occurred doing I/O.
    #[fail(display = "I/O error: {}", _0)]
    Io(#[cause] io::Error),

    /// We failed to parse JSON data.
    #[fail(display = "could not parse JSON: {}", _0)]
    Json(#[cause] serde_json::Error),

    /// Missing entry in Secretfile.
    #[fail(display = "no entry for '{}' in Secretfile", name)]
    MissingEntry {
        /// The name of the entry.
        name: String,
    },

    /// Path is missing a ':key' component.
    #[fail(display = "the path '{}' is missing a ':key' component", path)]
    MissingKeyInPath {
        /// The invalid path.
        path: String,
    },

    /// Secret does not have value for specified key.
    #[fail(display = "the secret '{}' does not have a value for the key '{}'",
           secret, key)]
    MissingKeyInSecret {
        /// The name of the secret.
        secret: String,
        /// The key for which we have no value.
        key: String,
    },

    /// `VAULT_ADDR` not specified.
    #[fail(display = "VAULT_ADDR not specified")]
    MissingVaultAddr,

    /// Cannot get either `VAULT_TOKEN` or `~/.vault_token`.
    #[fail(display = "cannot get VAULT_TOKEN, Kubernetes Vault token or ~/.vault_token: {}", _0)]
    MissingVaultToken(Box<Error>),

    /// No `credentials` backend available.
    #[fail(display = "no credentials backend available")]
    NoBackend,

    /// Can't find home directory.
    #[fail(display = "can't find home directory")]
    NoHomeDirectory,

    /// Path cannot be represented as Unicode.
    #[fail(display = "path '{:?}' cannot be represented as Unicode", path)]
    NonUnicodePath {
        /// The path which cannot be represented as Unicode.
        path: PathBuf,
    },

    /// Parsing error.
    #[fail(display = "could not parse {:?}", input)]
    Parse {
        /// The input we couldn't parse.
        input: String,
    },

    /// An unspecified kind of error occurred.
    #[fail(display = "{}", _0)]
    Other(failure::Error),

    /// Can't read `Secretfile`.
    #[fail(display = "can't read Secretfile: {}", _0)]
    Secretfile(Box<Error>),

    /// Undefined environment variable.
    #[fail(display = "undefined environment variable {:?}: {}", name, cause)]
    UndefinedEnvironmentVariable {
        /// The name of the environment variable.
        name: String,
        /// The error we encountered.
        #[cause]
        cause: env::VarError,
    },

    /// Unexpected HTTP status.
    #[fail(display = "unexpected HTTP status: {} ({})", status, body)]
    UnexpectedHttpStatus {
        /// The status we received.
        status: reqwest::StatusCode,
        /// The HTTP body we received.
        body: String,
    },

    /// We failed to parse a URL.
    #[fail(display = "could not parse URL: {}", _0)]
    UnparseableUrl(#[cause] reqwest::UrlError),

    /// Could not access URL.
    #[fail(display = "could not access URL '{}': {}", url, cause)]
    Url {
        /// The URL we couldn't access.
        url: reqwest::Url,
        /// The reason we couldn't access it.
        cause: Box<Error>,
    },

    /// We reserve the right to add new errors to this `enum` without
    /// considering it a breaking API chance.
    #[doc(hidden)]
    #[fail(display = "this error should never occur (nonexclusive)")]
    __Nonexclusive,
}

impl From<failure::Error> for Error {
    fn from(err: failure::Error) -> Self {
        Error::Other(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<reqwest::UrlError> for Error {
    fn from(err: reqwest::UrlError) -> Self {
        Error::UnparseableUrl(err)
    }
}
