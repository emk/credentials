//! Various error types used internally, and in our public APIs.

#![allow(missing_docs)]

use reqwest;
use rustc_serialize;
use std::io;
use std::path::PathBuf;

error_chain! {
    foreign_links {
        io::Error, Io;
        rustc_serialize::json::DecoderError, Json;
        reqwest::UrlError, UnparseableUrl;
    }

    errors {
        Credential(name: String) {
            description("can't access secure credential")
            display("can't access secure credential '{}'", &name)
        }
        FileRead(path: PathBuf) {
            description("problem reading file")
            display("problem reading file '{}'", path.display())
        }
        InvalidUrl(url: String) {
            description("invalid URL")
            display("invalid URL '{}'", &url)
        }
        MissingEntry(name: String) {
            description("missing entry in Secretfile")
            display("no entry for '{}' in Secretfile", &name)
        }
        MissingKeyInPath(path: String) {
            description("path is missing a ':key' component")
            display("the path '{}' is missing a ':key' component", &path)
        }
        MissingKeyInSecret(secret: String, key: String) {
            description("secret does not have value for specified key")
            display("the secret '{}' does not have a value for the key '{}'",
                    &secret, &key)
        }
        MissingVaultAddr {
            description("VAULT_ADDR not specified")
            display("VAULT_ADDR not specified")
        }
        MissingVaultToken {
            description("cannot get either VAULT_TOKEN or ~/.vault_token")
            display("cannot get either VAULT_TOKEN or ~/.vault_token")
        }
        NoBackend {
            description("no credentials backend available")
            display("no credentials backend available")
        }
        NoHomeDirectory {
            description("can't find home directory")
            display("can't find home directory")
        }
        NonUnicodePath(path: PathBuf) {
            description("path cannot be represented as Unicode")
            display("path '{}' cannot be represented as Unicode", path.display())
        }
        Parse(input: String) {
            description("parsing error")
            display("could not parse '{}'", &input)
        }
        Secretfile {
            description("can't read Secretfile")
            display("can't read Secretfile")
        }
        UndefinedEnvironmentVariable(name: String) {
            description("undefined environment variable")
            display("undefined environment variable '{}'", &name)
        }
        UnexpectedHttpStatus(status: reqwest::StatusCode) {
            description("unexpected HTTP status")
            display("unexpected HTTP status: {}", &status)
        }
        Url(url: reqwest::Url) {
            description("could not access URL")
            display("could not access URL '{}'", &url)
        }
    }
}
