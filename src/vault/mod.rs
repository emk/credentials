//! A very basic client for Hashicorp's Vault

use reqwest::{self, Url};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::env;
use std::fs::File;
use std::io::Read;
use tracing::debug;

use crate::backend::Backend;
use crate::errors::*;
use crate::secretfile::{Location, Secretfile, SecretfileLookup};

mod kubernetes;

use self::kubernetes::vault_kubernetes_token;

/// The default vault server address.
fn default_addr() -> Result<String> {
    env::var("VAULT_ADDR").map_err(|_| Error::MissingVaultAddr)
}

/// The default vault token.
async fn default_token(addr: &reqwest::Url) -> Result<String> {
    // Wrap everything in a local async block and await it so that we can wrap
    // all errors in a custom type.
    let fut = async {
        if let Ok(token) = env::var("VAULT_TOKEN") {
            // The env var `VAULT_TOKEN` overrides everything.
            Ok(token)
        } else if let Some(token) = vault_kubernetes_token(addr).await? {
            // We were able to get a token using our Kubernetes JWT
            // token.
            Ok(token)
        } else {
            // Build a path to ~/.vault-token.
            let mut path = dirs::home_dir().ok_or(Error::NoHomeDirectory)?;
            path.push(".vault-token");

            // Read the file.
            let mut f = File::open(path)?;
            let mut token = String::new();
            f.read_to_string(&mut token)?;
            Ok(token)
        }
    };
    fut.await
        .map_err(|err| Error::MissingVaultToken(Box::new(err)))
}

/// Secret data retrieved from Vault.  This has a bunch more fields, but
/// the exact list of fields doesn't seem to be documented anywhere, so
/// let's be conservative.
#[derive(Debug, Deserialize)]
struct Secret {
    /// The contents of this secret. The format of this data is specific
    /// to the secret backend.
    data: SecretData,
    // How long this secret will remain valid for, in seconds.
    #[allow(dead_code)]
    // Defensively default to 0 on backwards-incompatible format changes
    #[serde(default)]
    lease_duration: u64,
}

/// Secret data returned by a secret backend.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SecretData {
    /// A simple key-value map. This is the format returned by the KVv1 and Cubbyhole engines.
    Generic(BTreeMap<String, String>),
    /// A simple key-value map, wrapped as a value of an object with a `data` key. This is the
    /// format returned by the KVv2 engine.
    KVv2 { data: BTreeMap<String, String> },
}

impl SecretData {
    fn get(&self, key: &str) -> Option<&String> {
        match self {
            Self::Generic(map) | Self::KVv2 { data: map } => map.get(key),
        }
    }
}

/// A basic Vault client.
pub struct Client {
    /// Our HTTP client.  This can be configured to mock out the network.
    client: reqwest::Client,
    /// The address of our Vault server.
    addr: reqwest::Url,
    /// The token which we'll use to access Vault.
    token: String,
    /// Local cache of secrets.
    secrets: BTreeMap<String, Secret>,
}

impl Client {
    /// Has the user indicated that they want to enable our Vault backend?
    pub fn is_enabled() -> bool {
        default_addr().is_ok()
    }

    /// Construct a new vault::Client, attempting to use the same
    /// environment variables and files used by the `vault` CLI tool and
    /// the Ruby `vault` gem.
    pub async fn default() -> Result<Client> {
        let client = reqwest::Client::new();
        let addr = default_addr()?.parse()?;
        let token = default_token(&addr).await?;
        Client::new(client, addr, token)
    }

    /// Create a new Vault client.
    fn new<U, S>(client: reqwest::Client, addr: U, token: S) -> Result<Client>
    where
        U: Into<Url>,
        S: Into<String>,
    {
        Ok(Client {
            client,
            addr: addr.into(),
            token: token.into(),
            secrets: BTreeMap::new(),
        })
    }

    /// Fetch a secret from the Vault server.
    async fn get_secret(&self, path: &str) -> Result<Secret> {
        let url = self.addr.join(&format!("v1/{}", path))?;
        debug!("Getting secret {}", url);

        let mkerr = |err| Error::Url {
            url: url.clone(),
            source: Box::new(err),
        };
        let res = self
            .client
            .get(url.clone())
            // Leaving the connection open will cause errors on reconnect
            // after inactivity.
            .header("Connection", "close")
            .header("X-Vault-Token", &self.token[..])
            .send()
            .await
            .map_err(|err| (&mkerr)(Error::Other(err.into())))?;

        if res.status().is_success() {
            Ok(res
                .json()
                .await
                .map_err(|err| (&mkerr)(Error::Other(err.into())))?)
        } else {
            // Generate informative errors for HTTP failures, because these can
            // be caused by everything from bad URLs to overly restrictive vault
            // policies.
            let status = res.status().to_owned();
            let body = res
                .text()
                .await
                .map_err(|err| (&mkerr)(Error::Other(err.into())))?;

            Err(mkerr(Error::UnexpectedHttpStatus {
                status,
                body: body.trim().to_owned(),
            }))
        }
    }

    async fn get_loc(
        &mut self,
        searched_for: &str,
        loc: Option<Location>,
    ) -> Result<String> {
        match loc {
            None => Err(Error::MissingEntry {
                name: searched_for.to_owned(),
            }),
            Some(Location::PathWithKey(ref path, ref key)) => {
                // If we haven't cached this secret, do so.  This is
                // necessary to correctly support dynamic credentials,
                // which may have more than one related key in a single
                // secret, and fetching the secret once per key will result
                // in mismatched username/password pairs or whatever.
                if !self.secrets.contains_key(path) {
                    let secret = self.get_secret(path).await?;
                    self.secrets.insert(path.to_owned(), secret);
                }

                // Get the secret from our cache.  `[]]` is safe here,
                // because if we didn't have it, we grabbed it above.
                let secret = &self.secrets[path];

                // Look up the specified key in our secret's data bag.
                secret
                    .data
                    .get(key)
                    .ok_or_else(|| Error::MissingKeyInSecret {
                        secret: path.to_owned(),
                        key: key.to_owned(),
                    })
                    .map(|v| v.clone())
            }
            Some(Location::Path(ref path)) => Err(Error::MissingKeyInPath {
                path: path.to_owned(),
            }),
        }
    }
}

#[async_trait::async_trait]
impl Backend for Client {
    fn name(&self) -> &'static str {
        "vault"
    }

    #[tracing::instrument(level = "trace", skip(self, secretfile))]
    async fn var(
        &mut self,
        secretfile: &Secretfile,
        credential: &str,
    ) -> Result<String> {
        let loc = secretfile.var(credential).cloned();
        self.get_loc(credential, loc).await
    }

    #[tracing::instrument(level = "trace", skip(self, secretfile))]
    async fn file(&mut self, secretfile: &Secretfile, path: &str) -> Result<String> {
        let loc = secretfile.file(path).cloned();
        self.get_loc(path, loc).await
    }
}

// Tests disabled until we can mock reqwest.
//
//#[cfg(test)]
//mod tests {
//    use backend::Backend;
//    use hyper;
//    use secretfile::Secretfile;
//    use super::Client;
//
//    mock_connector!(MockVault {
//        "http://127.0.0.1" =>
//          "HTTP/1.1 200 OK\r\n\
//           Content-Type: application/json\r\n\
//           \r\n\
//           {\"data\": {\"value\": \"bar\"},\"lease_duration\": 2592000}\r\n\
//           "
//    });
//
//    fn test_client() -> Client {
//        let h = reqwest::Client::with_connector(MockVault::default());
//        Client::new(h, "http://127.0.0.1", "123").unwrap()
//    }
//
//    #[test]
//    fn test_get_secret() {
//        let client = test_client();
//        let secret = client.get_secret("secret/foo").unwrap();
//        assert_eq!("bar", secret.data.get("value").unwrap());
//    }
//
//    #[test]
//    fn test_var() {
//        let sf = Secretfile::from_str("FOO secret/foo:value").unwrap();
//        let mut client = test_client();
//        assert_eq!("bar", client.var(&sf, "FOO").unwrap());
//    }
//}
