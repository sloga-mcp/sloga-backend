# Apple JWS fixtures

The forged-chain test set for `../apple_jws.rs` is generated at test time (keys derived from fixed
labels, certificates assembled with `x509-cert`, RFC 6979 signatures), so no private key or test
certificate is committed here.

This directory holds only public Apple material:

- `AppleRootCA-G3.cer`: Apple Root CA - G3 (DER), the root `APPLE_ROOT_G3_SHA256_HEX` pins. Taken
  from the Mac mini's system root store on 2026-11-02 (S6 contracts, section 36); the test
  `pinned_root_matches_the_committed_g3_certificate` hashes it against the pin.
- `apple_sandbox_transaction.jws` (not yet captured): the `signedTransactionInfo` of the first
  Sandbox purchase on the test stack (sections 33 and 36). It contains no secret: it is Apple-signed
  public data with a Sandbox transaction id. Once it is in place, run
  `cargo test -p revolt-payments genuine_apple_sandbox_jws -- --ignored`, record and pin the chain's
  (curve, digest) pairs in the `apple_jws.rs` doc comment, and drop the `#[ignore]`. Passing it
  without `#[ignore]` is a ship gate before any store flag goes on.
