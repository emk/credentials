# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta.1] - 2021-12-28

### Changed

- All relevant APIs are now `async`. This includes `credentials::var` and `credentials::file`. We use the `tokio` async runtime.
- `credentials::Error` type now uses `source` instead of `cause`.
- By default, we no longer choose an appropriate `reqwest` backend for `https`. You can enable one using `features = ["default-tls"]`, or you can directly include `reqwest` and pass `features` of your choice.
