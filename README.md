<p align="center">
  <img src="https://github.com/solana-foundation/mpp-sdk/raw/main/assets/banner.png" alt="MPP" width="100%" />
</p>

# @solana/mpp

Solana payment method for the [Machine Payments Protocol](https://mpp.dev).

**MPP** is [an open protocol proposal](https://paymentauth.org) that lets any HTTP API accept payments using the `402 Payment Required` flow.

## SDK Implementations

The Solana MPP SDK is available in 5 languages. Every implementation follows the same protocol and is tested for cross-language interoperability.

| | TypeScript | Rust | Go | Python | Lua |
|---|:---:|:---:|:---:|:---:|:---:|
| **Package** | [@solana/mpp](https://www.npmjs.com/package/@solana/mpp) | — | — | — | — |
| **Server (charge)** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Client (auto-402)** | ✅ | ✅ | ✅ | ✅ | — |
| **Payment links** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Fee sponsorship** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Split payments** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **SPL tokens** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Token-2022** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Replay protection** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Session (pay-as-you-go)** | — | ✅ | — | — | — |

### Testing

Every implementation is validated at three levels:

1. **Unit tests** — each SDK has its own test suite with coverage enforcement
2. **E2E payment tests** — Playwright browser tests verify the full payment link flow (wallet → transaction → service worker → on-chain verification) against Surfpool
3. **Cross-language interop** — a shared Python test suite runs the same protocol conformance tests against every server implementation, proving that any client can pay any server

The interop matrix tests every client against every server. A shared Python test suite builds real Solana transactions and submits them to each server, verifying on-chain settlement via Surfpool. This catches protocol divergences that per-language unit tests miss.

```
          Clients                          Servers
   ┌────────────────┐              ┌────────────────────┐
   │  TypeScript    │──────┐       │  TypeScript :3000   │
   │  Rust          │──────┤       │  Rust       :3001   │
   │  Go            │──────┼──────▶│  Go         :3002   │
   │  Python        │──────┤       │  Lua        :3003   │
   └────────────────┘      │       │  Python     :3004   │
                           │       └─────────┬──────────┘
                           │                 │
                           │          ┌──────┴───────┐
                           └─────────▶│   Surfpool   │
                                      │    :8899     │
                                      └──────────────┘
```

### Coverage

| Language | Coverage | Tests |
|----------|----------|-------|
| TypeScript | ![TS](https://img.shields.io/badge/coverage-67_tests-blue) | `just ts-test` |
| Rust | ![Rust](https://img.shields.io/badge/coverage-653_tests-blue) | `just rs-test` |
| Go | ![Go](https://img.shields.io/badge/coverage-84%25-green) | `just go-test` |
| Python | ![Python](https://img.shields.io/badge/coverage-87%25-green) | `just py-test` |
| Lua | ![Lua](https://img.shields.io/badge/coverage-41_tests-blue) | `just lua-test` |
| Interop | ![Interop](https://img.shields.io/badge/interop-20_tests_×_4_servers-brightgreen) | `pytest tests/interop/` |

## Install

```bash
# TypeScript
pnpm add @solana/mpp

# Rust
cargo add solana-mpp

# Go
go get github.com/solana-foundation/mpp-sdk/go

# Python
pip install solana-mpp
```

## Quick Start

### Server (charge)

<details>
<summary>TypeScript</summary>

```ts
import { Mppx, solana } from '@solana/mpp/server'

const mppx = Mppx.create({
  secretKey: process.env.MPP_SECRET_KEY,
  methods: [
    solana.charge({
      recipient: 'RecipientPubkey...',
      currency: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      decimals: 6,
      html: true, // enables payment links for browsers
    }),
  ],
})

const result = await mppx.charge({
  amount: '1000000',
  currency: 'USDC',
})(request)

if (result.status === 402) return result.challenge
return result.withReceipt(Response.json({ data: '...' }))
```
</details>

<details>
<summary>Python</summary>

```python
from solana_mpp.server import Mpp, Config

mpp = Mpp(Config(
    recipient="RecipientPubkey...",
    currency="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    decimals=6,
    html=True,
))

challenge = mpp.charge("1.00")  # 1 USDC
receipt = await mpp.verify_credential(credential)
```
</details>

<details>
<summary>Go</summary>

```go
import "github.com/solana-foundation/mpp-sdk/go/server"

m, _ := server.New(server.Config{
    Recipient: "RecipientPubkey...",
    Currency:  "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    Decimals:  6,
    HTML:      true,
})

challenge, _ := m.Charge(ctx, "1.00")
receipt, _ := m.VerifyCredential(ctx, credential)
```
</details>

<details>
<summary>Rust</summary>

```rust
use solana_mpp::server::{Config, Mpp};

let mpp = Mpp::new(Config {
    recipient: "RecipientPubkey...".into(),
    currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
    decimals: 6,
    html: true,
    ..Default::default()
})?;

let challenge = mpp.charge("1.00")?;
let receipt = mpp.verify_credential(&credential).await?;
```
</details>

### Server (session)

Pay-as-you-go over a payment channel. The session intent issues a 402, opens a channel on-chain, accepts vouchers off-chain, and settles cooperatively at close. Rust v1 ships server-co-signed session only (the operator adds the fee-payer signature and broadcasts); pull-mode session is out of v1 scope.

<details>
<summary>Rust</summary>

```rust
use std::sync::Arc;
use solana_client::nonblocking::rpc_client::RpcClient as SolanaRpcClient;
use solana_mpp::{
    session, solana_keychain::{MemorySigner, SolanaSigner}, ChannelStore, FeePayer,
    InMemoryChannelStore, MppRpcClient, Network, PayeeSigner, Pricing, SessionConfig,
};

let mut cfg = SessionConfig::new_with_defaults(
    operator,
    payee,
    mint,
    6, // decimals
    Network::MainnetBeta,
    program_id,
    Pricing { amount_per_unit: 1_000, unit_type: "request".into() },
);

// Wrap your custody (env, KMS, HSM, wallet file) in a SolanaSigner.
// MemorySigner shown for brevity; production deployments use KMS/HSM.
let fee_payer: Arc<dyn SolanaSigner> = Arc::new(MemorySigner::from_bytes(&fee_payer_bytes)?);
let payee_signer: Arc<dyn SolanaSigner> = Arc::new(MemorySigner::from_bytes(&payee_bytes)?);
cfg.fee_payer = Some(FeePayer { signer: fee_payer });
cfg.payee_signer = Some(PayeeSigner { signer: payee_signer });

let store: Arc<dyn ChannelStore> = Arc::new(InMemoryChannelStore::new());
let rpc: Arc<dyn MppRpcClient> = Arc::new(SolanaRpcClient::new(rpc_url));

let method = session(cfg)
    .with_store(store)
    .with_rpc(rpc)
    .recover()
    .await?;

// Issue a 402 challenge for an open or topup, accept vouchers, close.
let challenge = method.build_challenge_for_open(Default::default()).await?;
let receipt   = method.process_open(&open_payload).await?;
let receipt   = method.verify_voucher(&voucher).await?;
let receipt   = method.process_topup(&topup_payload).await?;
let receipt   = method.process_close(&close_payload).await?;
```

`fee_payer` is required: v1 is server-submit, so the operator pays SOL fees on every channel transaction. `payee_signer` is required for `process_close`: the program's `settle_and_finalize` enforces that the merchant transaction signer matches `Channel.payee`, set at open time to the `payee` field on `SessionConfig`. The SDK never persists key material; both signers are facades over your existing custody.
</details>

### Client (session)

The `MppSessionClient` wraps the auto-open / auto-topup / voucher-sign flow behind a single `fetch(url)` call. One client per `(signer, rpc, program, policy)` tuple; the registry inside it holds per-`(payee, mint)` mutexes so concurrent fetches against unrelated merchants don't serialise on each other.

<details>
<summary>Rust</summary>

```rust,ignore
use std::sync::Arc;
use solana_client::nonblocking::rpc_client::RpcClient as SolanaRpcClient;
use solana_mpp::{
    solana_keychain::{MemorySigner, SolanaSigner},
    ClientConfig, ClientPolicy, HttpOptions, MppRpcClient, MppSessionClient,
};
use solana_pubkey::Pubkey;

let signer: Arc<dyn SolanaSigner> = Arc::new(MemorySigner::from_bytes(&keypair_bytes)?);
let rpc: Arc<dyn MppRpcClient> = Arc::new(SolanaRpcClient::new(rpc_url));

let client = MppSessionClient::new(ClientConfig {
    rpc,
    signer,
    program: program_id,
    policy: ClientPolicy::default(),
    http_options: HttpOptions::default(),
    server_base_url: "https://api.example.com".into(),
})?;

// Auto-opens a channel on first fetch, signs vouchers on subsequent ones,
// and tops up when the deposit cap would be exceeded (if `policy.auto_topup` is on).
let response = client.fetch("https://api.example.com/api/expensive").await?;
println!("status {}, body {}", response.status(), response.text()?);
println!("paid for channel {}", response.channel_id());

// Close cooperatively when done. Drops the registry entry; the merchant's
// settle_and_finalize lands on-chain server-side.
let close = client.close(&response.channel_id()).await?;
println!("close receipt: refunded={:?}", close.refunded);
```

`fetch` runs the full `402` decision tree: GET the resource, parse `WWW-Authenticate: Payment`, pick the `solana session` challenge, look up `(payee, mint)` in the in-process single-flight registry, and either sign a voucher (cache hit), submit a topup (cap exceeded, `policy.auto_topup`), or open a new channel (cache miss). One retry on stale-blockhash and stale-challenge errors before the error propagates.

`PaidResponse` pre-buffers the body so `bytes()`, `text()`, `json::<T>()`, `status()`, `headers()`, `channel_id()`, `accepted_cumulative()`, `spent()`, and `receipt()` are all sync and cheap to call repeatedly.
</details>

### Run the local session demo

`rust/examples/local_session_demo.rs` walks the full session lifecycle (open, voucher loop, topup, close) end-to-end against a real validator. The server-side `SessionMethod` and the client-side `SessionClient` both live in the same binary and call each other directly; on-chain traffic still rides real RPC.

First, fetch the program binary fixture:

```bash
just fetch-program-binary
```

In one terminal, start a validator with the program loaded. The program id is the upstream `payment_channels_client::programs::PAYMENT_CHANNELS_ID`:

```bash
solana-test-validator --reset \
  --bpf-program <PAYMENT_CHANNELS_ID> rust/tests/fixtures/payment_channels.so
```

If port 8000 (gossip) is already in use, reassign with `--gossip-port 18000 --dynamic-port-range 18001-18030` and keep `--rpc-port 8899` so the demo still finds the validator at `http://127.0.0.1:8899`.

In another terminal, from `rust/`:

```bash
RUSTFLAGS="-D warnings" cargo run --example local_session_demo --features="server,client"
```

Expected output (truncated):

```
setting up local fixture (rpc=http://127.0.0.1:8899)
airdropped 10 SOL to payer ABC123...
created mint XYZ789... (decimals 6)
opened channel ChAn1d... with deposit 10000000
voucher #1 accepted at cumulative 100000
voucher #2 accepted at cumulative 200000
voucher #3 accepted at cumulative 300000
topped up channel ChAn1d...: deposit 10000000 to 10500000
voucher #1 accepted at cumulative 350000
closed channel ChAn1d...; settled 400000; tombstone confirmed

summary
  channel              ChAn1d...
  signed cumulative    400000
  ...
```

### Payment Links

Set `html: true` on `solana.charge()` and any endpoint becomes a shareable payment link. Browsers see a payment page; API clients get the standard `402` flow.

```
Open http://localhost:3000/api/v1/fortune in a browser
→ Payment page with "Continue with Solana" button
→ Click → wallet signs → transaction confirmed on-chain
→ Page reloads with the paid content
```

See the [payment links guide](https://mpp.dev/guides/payment-links) for framework-specific setup.

### Fee Sponsorship

The server can pay transaction fees on behalf of clients:

```ts
solana.charge({
  recipient: '...',
  signer: feePayerSigner, // KeyPairSigner, Keychain SolanaSigner, etc.
})
```

### Split Payments

Send one charge to multiple recipients in the same asset:

```ts
solana.charge({
  recipient: 'SellerPubkey...',
  currency: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  decimals: 6,
  splits: [
    { recipient: 'PlatformPubkey...', amount: '50000', memo: 'platform fee' },
    { recipient: 'ReferrerPubkey...', amount: '20000', memo: 'referral fee' },
  ],
})
```

## Demo

An interactive playground with a React frontend and Express backend, running against [Surfpool](https://surfpool.run).

```bash
surfpool start
pnpm demo:install
pnpm demo:server
pnpm demo:app
```

See [demo/README.md](demo/README.md) for full details.

## Development

```bash
just build            # Build all SDKs (html → ts → rust → go)
just test             # Test all SDKs
just pre-commit       # Full pre-commit checks

# Per-language
just ts-test          # TypeScript tests
just rs-test          # Rust tests
just go-test          # Go tests
just py-test          # Python tests
just lua-test         # Lua tests

# Integration
just html-build       # Build payment link assets
just html-test-e2e    # Playwright E2E tests
```

## Spec

This SDK implements the [Solana Charge Intent](https://github.com/tempoxyz/mpp-specs/pull/188) for the [HTTP Payment Authentication Scheme](https://paymentauth.org).

## License

MIT
