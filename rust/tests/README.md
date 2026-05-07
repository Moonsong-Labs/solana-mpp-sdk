# Test layers

Session tests are named by tier: `session_l{0,1,2}_*.rs`. The prefix is a
project-local convention, not a standard Rust or Solana idiom.

- **L0** — pure Rust, no RPC, no SVM. Asserts byte contracts and wire
  shapes (PDA derivation, voucher/precompile layouts, JSON envelopes,
  JCS/base64url roundtrips).
- **L1** — in-process SVM via `litesvm`, with the program `.so` loaded (or
  just the native ed25519 precompile). Proves SDK-built bytes round-trip
  against the actual on-chain runtime without a node. The `.so` is fetched
  by `just fetch-program-binary` and hash-verified against
  `rust/src/program/payment_channels/program_binary.sha256`.
- **L2** — full Surfpool integration (embedded Surfnet, real transactions).
  Asserts observable on-chain state and HTTP-402 error codes end-to-end.
  Not yet written for `session`.

`charge_integration.rs` predates this convention and is the existing L2
suite for the `charge` intent.
