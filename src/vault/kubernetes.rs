use reqwest;
use serde::{Deserialize, Serialize};
use serde_json;
use std::env;
use std::fs;
use std::io::prelude::*;
use std::path::Path;

use crate::errors::*;

/// Path to a Kubernetes service account API token (automatically mounted into
/// the container if one is available and `automountServiceAccountToken` is not
/// set).
const KUBERNETES_TOKEN_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Fetch the JWT token associated with the current Kubernetes service account.
fn kubernetes_jwt() -> Result<String> {
    fs::read_to_string(KUBERNETES_TOKEN_PATH)
        .map_err(|err| Error::FileRead {
            path: Path::new(KUBERNETES_TOKEN_PATH).to_owned(),
            cause: Box::new(err.into()),
        })
}

/// Vault login information for a Kubernetes-based service login.
#[derive(Debug, Serialize)]
struct VaultKubernetesLogin<'a> {
    role: &'a str,
    jwt: &'a str,
}

/// Vault authentication response.
#[derive(Debug, Deserialize)]
struct VaultAuthResponse {
    /// Information about the authentication.
    auth: VaultAuth,
}

/// Vault authnetication data.
#[derive(Debug, Deserialize)]
struct VaultAuth {
    /// Our Vault client token.
    client_token: String,
}

/// Authenticate against the specified Kubernetes auth endpoint.
fn auth(
    client: reqwest::Client,
    addr: &reqwest::Url,
    auth_path: &str,
    role: &str,
    jwt: &str,
) -> Result<String> {
    let url = addr.join(&format!("v1/auth/{}/login", auth_path))?;
    let payload = VaultKubernetesLogin { role, jwt };
    let mkerr = |err| Error::Url {
        url: url.to_owned(),
        cause: Box::new(err),
    };
    let mut res = client.post(url.clone())
        // Leaving the connection open will cause errors on reconnect
        // after inactivity.
        //
        // TODO: Is this still true?
        .header("Connection", "close")
        .body(serde_json::to_vec(&payload)?)
        .send()
        .map_err(|err| (&mkerr)(Error::Other(err.into())))?;

    // Read our HTTP body.
    let mut body = String::new();
    res.read_to_string(&mut body)?;

    if res.status().is_success() {
        // Parse our body and get the auth token.
        let auth_res: VaultAuthResponse = serde_json::from_str(&body)?;
        Ok(auth_res.auth.client_token)
    } else {
        // Generate informative errors for HTTP failures.
        let status = res.status().to_owned();
        Err(mkerr(Error::UnexpectedHttpStatus {
            status,
            body: body.trim().to_owned(),
        }))
    }
}

/// If `VAULT_KUBERNETES_ROLE` is set, attempt to get a Vault token by
/// logging into Vault using our Kubernetes credentials.
pub(crate) fn vault_kubernetes_token(addr: &reqwest::Url) -> Result<Option<String>> {
    let role = match env::var("VAULT_KUBERNETES_ROLE") {
        Ok(role) => role,
        Err(_) => return Ok(None),
    };
    let auth_path = env::var("VAULT_KUBERNETES_AUTH_PATH").unwrap_or_else(|_| {
        "kubernetes".to_owned()
    });
    let jwt = kubernetes_jwt()?;
    let client = reqwest::Client::new();
    Ok(Some(auth(client, addr, &auth_path, &role, &jwt)?))
}
