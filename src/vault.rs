//! A very basic client for Hashicorp's Vault

use hyper;
use rustc_serialize::json;
use std::collections::BTreeMap;
use std::io::Read;
use backend::BoxedError;

// Define our custom vault token header for use with hyper.
header! { (XVaultToken, "X-Vault-Token") => [String] }

/// Secret data retrieved from Vault.  This has a bunch more fields, but
/// the exact list of fields doesn't seem to be documented anywhere, so
/// let's be conservative.
#[derive(Debug, RustcDecodable)]
struct Secret {
    /// The key-value pairs associated with this secret.
    data: BTreeMap<String, String>,
    // How long this secret will remain valid for, in seconds.
    lease_duration: u64,
}

/// A basic Vault client.
struct Client {
    /// Our HTTP client.  This can be configured to mock out the network.
    client: hyper::Client,
    /// The address of our Vault server.
    addr: hyper::Url,
    /// The token which we'll use to access Vault.
    token: String,
}

impl Client {
    fn new<U,S>(client: hyper::Client, addr: U, token: S) ->
        Result<Client, BoxedError>
        where U: hyper::client::IntoUrl, S: Into<String>
    {
        Ok(Client {
            client: client,
            addr: try!(addr.into_url()),
            token: token.into(),
        })
    }

    fn get_secret(&self, path: &str) -> Result<Secret, BoxedError> {
        let url = try!(self.addr.join(&format!("v1/{}", path)));

        let req = self.client.get(url)
            .header(XVaultToken(self.token.clone()));
        let mut res = try!(req.send());

        let mut body = String::new();
        try!(res.read_to_string(&mut body));
        Ok(try!(json::decode(&body)))
    }
}

#[cfg(test)]
mod tests {
    use hyper;
    use super::Client;

    mock_connector!(MockVault {
        "http://127.0.0.1" =>
          "HTTP/1.1 200 OK\r\n\
           Content-Type: application/json\r\n\
           \r\n\
           {\"data\": {\"value\": \"bar\"},\"lease_duration\": 2592000}\r\n\
           "
    });

    fn test_client() -> Client {
        let h = hyper::Client::with_connector(MockVault::default());
        Client::new(h, "http://127.0.0.1", "123").unwrap()
    } 

    #[test]
    fn test_get_secret() {
        let client = test_client();
        let secret = client.get_secret("secret/foo").unwrap();
        assert_eq!("bar", secret.data.get("value").unwrap());
    }
}
