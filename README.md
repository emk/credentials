# credentials: Fetch secrets from the environment or from Vault

[![Latest version](https://img.shields.io/crates/v/credentials.svg)](https://crates.io/crates/credentials) [![License](https://img.shields.io/crates/l/credentials.svg)](https://creativecommons.org/publicdomain/zero/1.0/) [![Build Status](https://travis-ci.org/emk/credentials.svg?branch=master)](https://travis-ci.org/emk/credentials)

[API Documentation](http://docs.randomhacks.net/credentials/).

A [twelve-factor app][12factor] (as popularized by Heroku) would normally
store any passwords or other secrets in environment variables.  The
alternative would be to include the passwords directly in the source code,
which would make it much easier to accidentally reveal them to the world.

But once your application deployment becomes more complex, it's much easier
to store passwords in a central, secure store such as Hashicorp's
[Vault][vault] or Square's [Keywhiz][keywhiz].

Wherever you choose to store your secrets, this library is intended to
provide a single, unified API:

```rust
credentials::get("EXAMPLE_USERNAME").unwrap();
credentials::get("EXAMPLE_PASSWORD").unwrap();
```

By default, this will return the values of the `EXAMPLE_USERNAME`
and `EXAMPLE_PASSWORD` environment variables.

## Accessing Vault

To fetch the secrets from Vault, you will first need to set up the same
things you would need to use the `vault` command line tool or the `vault`
Ruby gem:

- You need to set the `VAULT_ADDR` environment variable to the URL of your
  Vault server.
- You can store your Vault token in either the environment variable
  `VAULT_TOKEN` or the file `~/.vault-token`.

Let's assume you have the following secret stored in your vault:

```sh
vault write secret/example username=myuser password=mypass
```

To access it, you'll need to create a `Secretfile` in the directory from
which you run your application:

```
EXAMPLE_USERNAME secret/example:username
EXAMPLE_PASSWORD secret/example:password
```

As before, you can access these secrets using:

```rust
credentials::get("EXAMPLE_USERNAME").unwrap();
credentials::get("EXAMPLE_PASSWORD").unwrap();
```

## Example code

See [the `examples` directory](/examples) for complete, working code.

## TODO

The following features remain to be implemented:

- Environment variable interpolation in `Secretfile`.
- Keywhiz support.

## Contributions

Your feedback and contributions are welcome!  Just file an issue or send a
GitHub pull request.

[12factor]: http://12factor.net/
[vault]: https://www.vaultproject.io/
[keywhiz]: https://square.github.io/keywhiz/
