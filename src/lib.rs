//! Access secure credentials at runtime with multiple backends.
//!
//! For more information, see [the
//! homepage](https://github.com/emk/credentials).
//!
//! ```
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
//! use std::env;
//!
//! env::set_var("PASSWORD", "secret");
//! assert_eq!("secret", credentials::var("PASSWORD").await?);
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]
#![allow(clippy::redundant_closure)]

use backend::Backend;
use once_cell::sync::Lazy;
use std::convert::AsRef;
use std::default::Default;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use tokio::sync::Mutex;
use tracing::trace;

// Be very careful not to export any more of the Secretfile API than
// strictly necessary, because we don't want to stablize too much at this
// point.
pub use errors::{Error, Result};
pub use secretfile::{Secretfile, SecretfileKeys};

mod backend;
mod chained;
mod envvar;
mod errors;
mod secretfile;
mod vault;

/// Options which can be passed to `Client::new`.
pub struct Options {
    secretfile: Option<Secretfile>,
    allow_override: bool,
}

impl Default for Options {
    /// Create an `Options` object using the default values for each
    /// option.
    fn default() -> Options {
        Options {
            secretfile: None,
            allow_override: true,
        }
    }
}

impl Options {
    /// Specify a `Secretfile` for the `Client` to use.  This takes `self`
    /// by value, so it consumes the `Options` structure it is called on,
    /// and returns a new one.  Defaults to `Secretfile::default()`.
    pub fn secretfile(mut self, secretfile: Secretfile) -> Options {
        self.secretfile = Some(secretfile);
        self
    }

    /// Allow secrets in environment variables and local files to override
    /// the ones specified in our `Secretfile`.  Defaults to true.
    pub fn allow_override(mut self, allow_override: bool) -> Options {
        self.allow_override = allow_override;
        self
    }
}

/// A client which fetches secrets.  Under normal circumstances, it's
/// usually easier to use the static `credentials::var` and
/// `credentials::file` methods instead, but you may need to use this to
/// customize behavior.
pub struct Client {
    secretfile: Secretfile,
    backend: chained::Client,
}

impl Client {
    /// Create a new client using the specified options.
    pub async fn new(options: Options) -> Result<Client> {
        let secretfile = match options.secretfile {
            Some(sf) => sf,
            None => Secretfile::default()?,
        };
        let over = options.allow_override;
        Ok(Client {
            secretfile,
            backend: chained::Client::with_default_backends(over).await?,
        })
    }

    /// Create a new client using the default options.
    pub async fn default() -> Result<Client> {
        Client::new(Default::default()).await
    }

    /// Create a new client using the specified `Secretfile`.
    pub async fn with_secretfile(secretfile: Secretfile) -> Result<Client> {
        Client::new(Options::default().secretfile(secretfile)).await
    }

    /// Provide access to a copy of the Secretfile we're using.
    pub fn secretfile(&self) -> &Secretfile {
        &self.secretfile
    }

    /// Fetch the value of an environment-variable-style credential.
    pub async fn var<S: AsRef<str>>(&mut self, name: S) -> Result<String> {
        let name_ref = name.as_ref();
        trace!("getting secure credential {}", name_ref);
        self.backend
            .var(&self.secretfile, name_ref)
            .await
            .map_err(|err| Error::Credential {
                name: name_ref.to_owned(),
                source: Box::new(err),
            })
    }

    /// Fetch the value of a file-style credential.
    pub async fn file<S: AsRef<Path>>(&mut self, path: S) -> Result<String> {
        let path_ref = path.as_ref();
        let path_str = path_ref.to_str().ok_or_else(|| Error::Credential {
            name: format!("{}", path_ref.display()),
            source: Box::new(Error::NonUnicodePath {
                path: path_ref.to_owned(),
            }),
        })?;
        trace!("getting secure credential {}", path_str);
        self.backend
            .file(&self.secretfile, path_str)
            .await
            .map_err(|err| Error::Credential {
                name: path_str.to_owned(),
                source: Box::new(err),
            })
    }
}

// Our shared global client.
//
// Rust deliberately makes it a nuisance to use mutable global
// variables.  In this case, the `Mutex` provides thread-safe locking
// and write access, and the `Option` makes this optional.  This is a
// message from the language saying, "Really? A mutable global that
// might be null? Have you really thought about this?"  But the global
// default client is only for convenience, so we're OK with it, at least
// so far.
static CLIENT: Lazy<Mutex<Option<Client>>> = Lazy::new(|| Mutex::new(None));

/// Call `body` with the default global client, or return an error if we can't
/// allocate a default global client.
///
/// `F` has a rather horrible type constraint that allows it to hold onto a
/// `&mut` pointing at the contents of `client_cell`. See
/// https://users.rust-lang.org/t/function-that-takes-a-closure-with-mutable-reference-that-returns-a-future/54324.
async fn with_client<F>(body: F) -> Result<String>
where
    F: for<'a> FnOnce(
        &'a mut Client,
    )
        -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>>,
{
    let mut client = CLIENT.lock().await;

    // Try to set up the client if we haven't already.
    if client.is_none() {
        *client = Some(Client::default().await?);
    }

    // Call the provided function.  I have to break out `result` separately
    // for mysterious reasons related to the borrow checker and global
    // mutable state.
    match client.as_mut() {
        Some(client) => body(client).await,
        // We theoretically handed this just above, and exited if we
        // failed.
        None => panic!("Should have a client, but we don't"),
    }
}

/// Fetch the value of an environment-variable-style credential.
pub async fn var<S: AsRef<str>>(name: S) -> Result<String> {
    let name = name.as_ref().to_owned();
    with_client(|client| Box::pin(client.var(name))).await
}

/// Fetch the value of a file-style credential.
pub async fn file<S: AsRef<Path>>(path: S) -> Result<String> {
    let path = path.as_ref().to_owned();
    with_client(|client| Box::pin(client.file(path))).await
}

#[cfg(test)]
mod test {
    use super::file;
    use std::fs;
    use std::io::Read;
    use std::path::Path;

    #[tokio::test]
    async fn test_file() {
        // Some arbitrary file contents.
        let mut f = fs::File::open("Cargo.toml").unwrap();
        let mut expected = String::new();
        f.read_to_string(&mut expected).unwrap();

        assert_eq!(expected, file(&Path::new("Cargo.toml")).await.unwrap());
        assert!(file(&Path::new("nosuchfile.txt")).await.is_err());
    }
}
