# iroh-mainline-address-lookup-blinded

Privacy-preserving address lookup for [iroh](https://github.com/n0-computer/iroh),
backed by BEP44 mutable items on the BitTorrent Mainline DHT.

The crate derives rotating, Tor-style blinded lookup keys from an iroh endpoint
identity. Address records are encrypted before publication, allowing peers that
know the endpoint identity and context to resolve them without exposing a stable
public DHT key or plaintext address record.

## License

Copyright 2026 N0, INC.

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
