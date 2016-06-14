# Signify - ED25519 signature tool

[![crates.io](http://meritbadge.herokuapp.com/signify)](https://crates.io/crates/signify)
[![Build Status](https://travis-ci.org/badboy/signify-rs.svg?branch=master)](https://travis-ci.org/badboy/signify-rs)

Create cryptographic signatures for files and verify them.
This is based on [signify][], the OpenBSD tool to sign and verify signatures on files.
It is based on the [Ed25519 public-key signature system][ed25519] by Bernstein et al.

## Installation

```
cargo install signify
```

## Usage

Create a key pair:

```
signify -G -p pubkey -s seckey
```

Sign a file using the secret key:

```
signify -S -s seckey -m README.md
```

Verify the signature:

```
signify -V -p pubkey -m README.md
```

## Limitations

* No embedded signatures
* No password-protection for secret keys

Both things will be implemented eventually.
I also accept PRs.

## License

MIT. See [LICENSE](LICENSE).

[signify]: https://github.com/aperezdc/signify
[ed25519]: https://ed25519.cr.yp.to/
