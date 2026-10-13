# iroh-mainline-address-lookup-blinded

Privacy-preserving address lookup for [iroh](https://github.com/n0-computer/iroh),
backed by BEP44 mutable items on the BitTorrent Mainline DHT.

The crate derives rotating, Tor-style blinded lookup keys from an iroh endpoint
identity. Address records are encrypted before publication, allowing peers that
know the endpoint identity and context to resolve them without exposing a stable
public DHT key or plaintext address record.

## Limitations

This crate is a proof of concept.

While it does provide a significant improvement regarding endpoint secrecy, it also does **not** make an iroh endpoint id *completely* secret.

Other parts of the system can still observe the endpoint id: the *relay* the endpoint is connected to, other address lookup services it *publishes* to, and anyone who can guess the endpoint UDP socket and reach it, since an iroh endpoint currently reveals its key in the handshake to every client.

See [Blinded address lookup] for details.

[Blinded address lookup]: https://www.iroh.computer/blog/blinded-address-lookup

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
