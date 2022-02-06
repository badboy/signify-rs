# Unreleased

[Full changelog](https://github.com/badboy/signify-rs/compare/v0.5.0...main)

# 0.5.0 (2022-02-06)

[Full changelog](https://github.com/badboy/signify-rs/compare/v0.4.1...v0.5.0)

* Split signify into a standalone library, available as `libsignify`, a `#![no_std]` library that implements the `signify` specification.
  Note: The library API is still unstable and might change in the next release.
* Sweeping dependency updates and replacements, which also increase target compatibility.
* Improved CLI usability
* Complete rewrite of the crate's functionality.

# v0.4.1 (2018-01-11)

* Exclude temporary files from crate

# v0.4.0 (2017-12-12)

* Support embedded signatures
* Auto-build binaries

# v0.3.0 (2016-09-27)

* Switched to *ring* for the crypto part
* Cleaned up error handling
* Prevent overwriting existing files
* Check the keynum on keys
* Ensure compatibility with original signify on CI

# v0.2.0 (2016-06-27)

Now with passphrase-protection for your secret key.

# v0.1.0 (2016-06-14)

The initial working release.
