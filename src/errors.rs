//! Various error types used internally, and in our public APIs.

use std::env;
use std::io;
use std::path::PathBuf;
use std::result;

/// A result returned by functions in `Credentials`.
pub type Result<T> = result::Result<T, Error>;

/// An error returned by `credentials`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Could not access a secure credential.
    #[non_exhaustive]
    #[error("can't access secure credential '{name}': {source}")]
    Credential {
        /// The name of the credential we couldn't access.
        name: String,
        /// The reason why we couldn't access it.
        #[source]
        source: Box<Error>,
    },

    /// Could not read file.
    #[non_exhaustive]
    #[error("problem reading file {}: {source}", path.display())]
    FileRead {
        /// The file we couldn't access.
        path: PathBuf,
        /// The reason why we couldn't access it.
        #[source]
        source: Box<Error>,
    },

    /// We encountered an invalid URL.
    #[non_exhaustive]
    #[error("invalid URL {url:?}")]
    InvalidUrl {
        /// The invalid URL.
        url: String,
    },

    /// An error occurred doing I/O.
    #[non_exhaustive]
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// We failed to parse JSON data.
    #[non_exhaustive]
    #[error("could not parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// Missing entry in Secretfile.
    #[non_exhaustive]
    #[error("no entry for '{name}' in Secretfile")]
    MissingEntry {
        /// The name of the entry.
        name: String,
    },

    /// Path is missing a ':key' component.
    #[non_exhaustive]
    #[error("the path '{path}' is missing a ':key' component")]
    MissingKeyInPath {
        /// The invalid path.
        path: String,
    },

    /// Secret does not have value for specified key.
    #[non_exhaustive]
    #[error("the secret '{secret}' does not have a value for the key '{key}'")]
    MissingKeyInSecret {
        /// The name of the secret.
        secret: String,
        /// The key for which we have no value.
        key: String,
    },

    /// `VAULT_ADDR` not specified.
    #[error("VAULT_ADDR not specified")]
    MissingVaultAddr,

    /// Cannot get either `VAULT_TOKEN` or `~/.vault_token`.
    #[error("cannot get VAULT_TOKEN, Kubernetes Vault token or ~/.vault_token: {0}")]
    MissingVaultToken(Box<Error>),

    /// No `credentials` backend available.
    #[error("no credentials backend available")]
    NoBackend,

    /// Can't find home directory.
    #[error("can't find home directory")]
    NoHomeDirectory,

    /// Path cannot be represented as Unicode.
    #[error("path '{path:?}' cannot be represented as Unicode")]
    #[non_exhaustive]
    NonUnicodePath {
        /// The path which cannot be represented as Unicode.
        path: PathBuf,
    },

    /// Parsing error.
    #[error("could not parse {input:?}")]
    #[non_exhaustive]
    Parse {
        /// The input we couldn't parse.
        input: String,
    },

    /// An unspecified kind of error occurred.
    #[error("{0}")]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),

    /// Can't read `Secretfile`.
    #[non_exhaustive]
    #[error("can't read Secretfile: {0}")]
    Secretfile(Box<Error>),

    /// Undefined environment variable.
    #[non_exhaustive]
    #[error("undefined environment variable {name:?}: {source}")]
    UndefinedEnvironmentVariable {
        /// The name of the environment variable.
        name: String,
        /// The error we encountered.
        #[source]
        source: env::VarError,
    },

    /// Unexpected HTTP status.
    #[non_exhaustive]
    #[error("unexpected HTTP status: {status} ({body})")]
    UnexpectedHttpStatus {
        /// The status we received.
        status: reqwest::StatusCode,
        /// The HTTP body we received.
        body: String,
    },

    /// We failed to parse a URL.
    #[error("could not parse URL: {0}")]
    UnparseableUrl(#[from] url::ParseError),

    /// Could not access URL.
    #[non_exhaustive]
    #[error("could not access URL '{url}': {source}")]
    Url {
        /// The URL we couldn't access.
        url: reqwest::Url,
        /// The reason we couldn't access it.
        #[source]
        source: Box<Error>,
    },
}
