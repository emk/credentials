# Work in progress: Accessing secure credential stores in Rust

What we support:

- Environment variables

What we want to support:

- Vault
- KeyWhiz
- Any others which fit the same general model in the future

The basic design is that a single compiled app should be able to fetch
secrets from any of the above secret stores depending on its runtime
configuration.
