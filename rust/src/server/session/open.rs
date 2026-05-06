//! `process_open` handler. Validates the open tx against the advertised
//! challenge, co-signs as fee payer, broadcasts, and persists the
//! channel record.
//!
//! Validation rebuilds the canonical `open` ix from the server's view
//! of the args (salt, deposit, splits, grace period) and checks that
//! the submitted tx carries those exact bytes plus only allow-listed
//! programs. Off-list programs, ix-arg drift, or a fee-payer in the
//! wrong slot all trip a typed `MaliciousTx` / `BadFeePayerSlot` /
//! `BlockhashMismatch` rejection before we hit the RPC.

use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use payment_channels_client::instructions::OpenBuilder;
use payment_channels_client::programs::PAYMENT_CHANNELS_ID;
use payment_channels_client::types::{DistributionEntry, DistributionRecipients, OpenArgs};

use crate::error::SessionError;
use crate::program::payment_channels::state::find_channel_pda;
use crate::protocol::intents::session::{OpenPayload, Split};
use crate::server::session::SessionConfig;

/// Validated view of a client-submitted open tx. Carries the raw
/// `Transaction` (so the caller can co-sign and broadcast) plus the
/// typed values pulled out of the open ix args.
#[derive(Debug)]
pub(crate) struct DecodedOpenTx {
    /// The submitted transaction with the fee-payer signature slot
    /// still empty; the caller fills it after co-signing.
    pub tx: Transaction,
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub canonical_bump: u8,
    /// Channel PDA derived from `(payer, payee, mint, authorized_signer,
    /// salt, program_id)`. Matches the address in the `channel` slot of
    /// the canonical open ix.
    pub channel_id: Pubkey,
}

/// Inputs for rebuilding the canonical open ix.
///
/// `salt`, `deposit`, and `grace_period` come from the wire
/// `OpenPayload` (already parsed and bounds-checked); `splits` is the
/// typed form the caller validated against the cached challenge.
pub struct CanonicalOpenInputs<'a> {
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
    pub authorized_signer: Pubkey,
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub program_id: Pubkey,
    pub splits: &'a [Split],
}

/// Convert typed `Split`s to the upstream `DistributionRecipients`
/// `OpenBuilder` wants. Wire shape is always 32 entries; trailing
/// slots are zero-filled.
pub(crate) fn splits_to_recipients(splits: &[Split]) -> DistributionRecipients {
    let zero_entry = DistributionEntry {
        recipient: Address::new_from_array([0u8; 32]),
        bps: 0,
    };
    let mut entries: [DistributionEntry; 32] = std::array::from_fn(|_| zero_entry.clone());
    for (i, s) in splits.iter().take(32).enumerate() {
        entries[i] = DistributionEntry::from(s);
    }
    DistributionRecipients {
        count: splits.len().min(32) as u8,
        entries,
    }
}

pub(crate) fn pk_to_addr(pk: &Pubkey) -> Address {
    Address::new_from_array(pk.to_bytes())
}

pub(crate) fn addr_to_pk(addr: &Address) -> Pubkey {
    Pubkey::new_from_array(addr.to_bytes())
}

/// Bridge a 32-byte program-id constant from 2.x `Pubkey` (what
/// `spl_token`, `spl_associated_token_account_client`, and
/// `solana_compute_budget_interface` re-export) into the SDK's 3.x
/// `Pubkey`. Both are 32-byte newtypes, so this is a no-op byte-wise.
fn id_v2_to_v3(bytes: [u8; 32]) -> Pubkey {
    Pubkey::new_from_array(bytes)
}

/// SPL Token program id as v3 `Pubkey`.
pub fn spl_token_id() -> Pubkey {
    id_v2_to_v3(spl_token::id().to_bytes())
}

/// SPL ATA program id as v3 `Pubkey`.
pub(crate) fn ata_program_id() -> Pubkey {
    id_v2_to_v3(spl_associated_token_account_client::program::ID.to_bytes())
}

/// ComputeBudget program id as v3 `Pubkey`.
pub(crate) fn compute_budget_program_id() -> Pubkey {
    id_v2_to_v3(solana_compute_budget_interface::ID.to_bytes())
}

/// Derive the ATA for `(wallet, mint, token_program)`. Mirrors
/// `spl_associated_token_account_client::address::get_associated_token_address_with_program_id`
/// but stays in v3 `Pubkey` to skip the dual-version crate hop.
pub fn ata_address(wallet: &Pubkey, mint: &Pubkey, token_program_id: &Pubkey) -> Pubkey {
    let (pda, _) = Pubkey::find_program_address(
        &[
            wallet.as_ref(),
            token_program_id.as_ref(),
            mint.as_ref(),
        ],
        &ata_program_id(),
    );
    pda
}

/// Build the canonical `open` ix we expect to find in the client's
/// submitted tx. Same shape an honest client builds via
/// `OpenBuilder`.
pub fn build_canonical_open_ix(inputs: &CanonicalOpenInputs<'_>) -> Instruction {
    // Event authority PDA, single seed `b"event_authority"`. Upstream
    // declares it in `program/payment_channels/src/event_engine.rs`
    // but doesn't re-export it through the Codama client, so derive
    // here.
    let (event_authority_pk, _) =
        Pubkey::find_program_address(&[b"event_authority"], &inputs.program_id);

    let token_program_pk = spl_token_id();
    let token_program = pk_to_addr(&token_program_pk);
    let ata_program = pk_to_addr(&ata_program_id());

    let payer_addr = pk_to_addr(&inputs.payer);
    let payee_addr = pk_to_addr(&inputs.payee);
    let mint_addr = pk_to_addr(&inputs.mint);
    let auth_addr = pk_to_addr(&inputs.authorized_signer);

    let (channel_pda, _bump) = find_channel_pda(
        &inputs.payer,
        &inputs.payee,
        &inputs.mint,
        &inputs.authorized_signer,
        inputs.salt,
        &inputs.program_id,
    );
    let channel_addr = pk_to_addr(&channel_pda);

    // ATAs use the classic SPL Token program only. Token-2022 mints
    // are blocked by the program allow-list; using the wrong token
    // program id here would yield a different ATA.
    let payer_token_account_pk = ata_address(&inputs.payer, &inputs.mint, &token_program_pk);
    let channel_token_account_pk = ata_address(&channel_pda, &inputs.mint, &token_program_pk);
    let payer_token_account_addr = pk_to_addr(&payer_token_account_pk);
    let channel_token_account_addr = pk_to_addr(&channel_token_account_pk);

    let open_args = OpenArgs {
        salt: inputs.salt,
        deposit: inputs.deposit,
        grace_period: inputs.grace_period,
        recipients: splits_to_recipients(inputs.splits),
    };

    OpenBuilder::new()
        .payer(payer_addr)
        .payee(payee_addr)
        .mint(mint_addr)
        .authorized_signer(auth_addr)
        .channel(channel_addr)
        .payer_token_account(payer_token_account_addr)
        .channel_token_account(channel_token_account_addr)
        .token_program(token_program)
        .system_program(pk_to_addr(&solana_sdk_ids::system_program::ID))
        .rent(pk_to_addr(&solana_sdk_ids::sysvar::rent::ID))
        .associated_token_program(ata_program)
        .event_authority(pk_to_addr(&event_authority_pk))
        .self_program(PAYMENT_CHANNELS_ID)
        .open_args(open_args)
        .instruction()
}

/// Programs that may appear in an open tx's `account_keys`. Anything
/// else is a malformed or malicious submission. Token-2022 is left
/// off so v1 rejects Token-2022 mints at the shape boundary.
fn open_program_allow_list() -> [Pubkey; 5] {
    [
        addr_to_pk(&PAYMENT_CHANNELS_ID),
        spl_token_id(),
        ata_program_id(),
        compute_budget_program_id(),
        solana_sdk_ids::system_program::ID,
    ]
}

/// Parsed payload args needed to rebuild the canonical open ix.
struct ParsedOpenPayload {
    payer: Pubkey,
    payee: Pubkey,
    mint: Pubkey,
    authorized_signer: Pubkey,
    salt: u64,
    deposit: u64,
}

fn parse_open_payload(payload: &OpenPayload) -> Result<ParsedOpenPayload, SessionError> {
    fn parse_pubkey(field: &'static str, raw: &str) -> Result<Pubkey, SessionError> {
        let bytes = bs58::decode(raw).into_vec().map_err(|e| {
            SessionError::OnChainStateMismatch {
                field,
                expected: "base58 pubkey".into(),
                got: format!("{raw}: {e}"),
            }
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            SessionError::OnChainStateMismatch {
                field,
                expected: "32-byte pubkey".into(),
                got: raw.to_string(),
            }
        })?;
        Ok(Pubkey::new_from_array(arr))
    }

    let payer = parse_pubkey("payer", &payload.payer)?;
    let payee = parse_pubkey("payee", &payload.payee)?;
    let mint = parse_pubkey("mint", &payload.mint)?;
    let authorized_signer = parse_pubkey("authorizedSigner", &payload.authorized_signer)?;
    let salt: u64 = payload
        .salt
        .parse()
        .map_err(|e| SessionError::InvalidAmount(format!("salt parse: {e}")))?;
    let deposit: u64 = payload
        .deposit_amount
        .parse()
        .map_err(|e| SessionError::InvalidAmount(format!("depositAmount parse: {e}")))?;
    let _advertised_bump = payload.bump; // re-derived below; carried only for the assertion in `process_open`
    Ok(ParsedOpenPayload {
        payer,
        payee,
        mint,
        authorized_signer,
        salt,
        deposit,
    })
}

/// Validate a client-submitted open tx.
///
/// Decodes the base64 partial-signed tx and checks: programs are
/// allow-listed, fee-payer is in slot 0, the required-signatures
/// count matches, and the open ix bytes match what the server would
/// emit for the same args. Rejects with typed errors before any RPC.
///
/// Takes already-typed `splits` so the wire/typed conversion lives
/// at the handler boundary and this helper stays on the byte
/// contract.
pub(crate) fn validate_open_tx_shape(
    payload: &OpenPayload,
    splits: &[Split],
    config: &SessionConfig,
    expected_blockhash: &Hash,
) -> Result<DecodedOpenTx, SessionError> {
    let parsed = parse_open_payload(payload)?;

    let fee_payer = config.fee_payer.as_ref().ok_or_else(|| {
        SessionError::InternalError("session config missing fee_payer; v1 is server-submit".into())
    })?;
    let fee_payer_pk = fee_payer.signer.pubkey();

    let tx_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &payload.transaction,
    )
    .map_err(|e| SessionError::MaliciousTx {
        reason: format!("base64 decode failed: {e}"),
    })?;

    let tx: Transaction = bincode::deserialize(&tx_bytes).map_err(|e| SessionError::MaliciousTx {
        reason: format!("transaction bincode decode failed: {e}"),
    })?;

    // Every program referenced by the message must be on the
    // allow-list.
    let allow = open_program_allow_list();
    let pc_program_pk = addr_to_pk(&PAYMENT_CHANNELS_ID);
    for ix in &tx.message.instructions {
        let idx = ix.program_id_index as usize;
        let key = tx.message.account_keys.get(idx).ok_or_else(|| {
            SessionError::MaliciousTx {
                reason: format!("compiled ix references account index {idx} out of range"),
            }
        })?;
        let key_pk = addr_to_pk(key);
        if !allow.contains(&key_pk) {
            return Err(SessionError::MaliciousTx {
                reason: format!("program {key_pk} not on the open-tx allow list"),
            });
        }
    }

    // Exactly two required signatures: payer + server fee-payer.
    if tx.message.header.num_required_signatures != 2 {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected num_required_signatures == 2, got {}",
                tx.message.header.num_required_signatures
            ),
        });
    }

    // Fee-payer is `account_keys[0]` and must match the configured
    // fee-payer pubkey.
    let slot0 = tx
        .message
        .account_keys
        .first()
        .ok_or_else(|| SessionError::MaliciousTx {
            reason: "transaction has no account keys".into(),
        })?;
    let slot0_pk = addr_to_pk(slot0);
    if slot0_pk != fee_payer_pk {
        return Err(SessionError::BadFeePayerSlot {
            expected: fee_payer_pk,
            got: slot0_pk,
        });
    }

    // Recent blockhash has to match the cached challenge's.
    if tx.message.recent_blockhash != *expected_blockhash {
        return Err(SessionError::BlockhashMismatch {
            expected: expected_blockhash.to_string(),
            got: tx.message.recent_blockhash.to_string(),
        });
    }

    // Re-derive `(channel_pda, bump)` from the parsed payload.
    let (canonical_pda, canonical_bump) = find_channel_pda(
        &parsed.payer,
        &parsed.payee,
        &parsed.mint,
        &parsed.authorized_signer,
        parsed.salt,
        &config.program_id,
    );

    // Rebuild the canonical open ix.
    let canonical_ix = build_canonical_open_ix(&CanonicalOpenInputs {
        payer: parsed.payer,
        payee: parsed.payee,
        mint: parsed.mint,
        authorized_signer: parsed.authorized_signer,
        salt: parsed.salt,
        deposit: parsed.deposit,
        grace_period: config.grace_period_seconds,
        program_id: config.program_id,
        splits,
    });

    // Find the open ix in the submitted message and compare bytes.
    let open_ix_compiled = tx
        .message
        .instructions
        .iter()
        .find(|ix| {
            tx.message
                .account_keys
                .get(ix.program_id_index as usize)
                .map(addr_to_pk)
                == Some(pc_program_pk)
        })
        .ok_or_else(|| SessionError::MaliciousTx {
            reason: "transaction does not invoke the payment-channels program".into(),
        })?;

    if open_ix_compiled.data != canonical_ix.data {
        return Err(SessionError::MaliciousTx {
            reason: "open ix data does not match canonical bytes".into(),
        });
    }

    if open_ix_compiled.accounts.len() != canonical_ix.accounts.len() {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "open ix expects {} accounts, got {}",
                canonical_ix.accounts.len(),
                open_ix_compiled.accounts.len()
            ),
        });
    }
    for (i, (slot_idx, expected_meta)) in open_ix_compiled
        .accounts
        .iter()
        .zip(canonical_ix.accounts.iter())
        .enumerate()
    {
        let got = tx
            .message
            .account_keys
            .get(*slot_idx as usize)
            .ok_or_else(|| SessionError::MaliciousTx {
                reason: format!("open ix account index {slot_idx} out of range"),
            })?;
        let got_pk = addr_to_pk(got);
        let expected_pk = addr_to_pk(&expected_meta.pubkey);
        if got_pk != expected_pk {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "open ix account #{i} mismatch: expected {expected_pk}, got {got_pk}"
                ),
            });
        }
    }

    Ok(DecodedOpenTx {
        tx,
        salt: parsed.salt,
        deposit: parsed.deposit,
        grace_period: config.grace_period_seconds,
        canonical_bump,
        channel_id: canonical_pda,
    })
}

#[cfg(test)]
mod tests {
    //! Unit tests for `validate_open_tx_shape`. Each case fails one
    //! specific check; together they cover every rejection variant.
    //! End-to-end happy-path coverage lives in the L1 oracle.

    use super::*;
    use crate::protocol::intents::session::{typed_to_wire, Split};
    use crate::server::session::Pricing;
    use solana_keychain::MemorySigner;
    use solana_message::Message;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;
    use std::sync::Arc;

    /// `MemorySigner` over a freshly generated keypair.
    fn fresh_memory_signer() -> Arc<dyn solana_keychain::SolanaSigner> {
        let kp = Keypair::new();
        let bytes = kp.to_bytes();
        Arc::new(MemorySigner::from_bytes(&bytes).expect("memory signer accepts keypair bytes"))
    }

    /// Default `SessionConfig` wired with a `MemorySigner`; returns
    /// the signer's pubkey too.
    fn config_with_fresh_fee_payer() -> (SessionConfig, Pubkey) {
        let signer = fresh_memory_signer();
        let fee_payer_pk = signer.pubkey();
        let mut cfg = SessionConfig::new_with_defaults(
            Pubkey::new_from_array([1u8; 32]),
            Pubkey::new_from_array([2u8; 32]),
            Pubkey::new_from_array([3u8; 32]),
            6,
            crate::server::session::Network::Localnet,
            addr_to_pk(&PAYMENT_CHANNELS_ID),
            Pricing {
                amount_per_unit: 1_000,
                unit_type: "request".into(),
            },
        );
        cfg.grace_period_seconds = 60;
        cfg.fee_payer = Some(crate::server::session::FeePayer { signer });
        (cfg, fee_payer_pk)
    }

    fn empty_splits() -> Vec<Split> {
        Vec::new()
    }

    /// Build a payload + canonical tx pair. The returned tx is signed
    /// by the payer only; the fee-payer slot stays empty per the wire
    /// format.
    fn build_payload_and_tx(
        config: &SessionConfig,
        payer: &Keypair,
        authorized_signer: Pubkey,
        salt: u64,
        deposit: u64,
        blockhash: Hash,
    ) -> (OpenPayload, Transaction) {
        let splits = empty_splits();
        let canonical_ix = build_canonical_open_ix(&CanonicalOpenInputs {
            payer: payer.pubkey(),
            payee: config.payee,
            mint: config.mint,
            authorized_signer,
            salt,
            deposit,
            grace_period: config.grace_period_seconds,
            program_id: config.program_id,
            splits: &splits,
        });

        let fee_payer_pk = config.fee_payer.as_ref().unwrap().signer.pubkey();
        let fee_payer_addr = pk_to_addr(&fee_payer_pk);

        // Two-signer message: `account_keys[0]` is the fee-payer,
        // `[1]` is the payer. We build the message manually so the
        // fee-payer signature slot stays empty for the server to fill
        // after validation.
        let message = Message::new_with_blockhash(
            &[canonical_ix],
            Some(&fee_payer_addr),
            &blockhash,
        );

        let mut tx = Transaction::new_unsigned(message);
        // Pad signatures up to `header.num_required_signatures` so
        // the layout matches the wire format. Server overwrites slot 0
        // after co-signing.
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        // Sign the payer slot. Payer is `account_keys[1]`;
        // `partial_sign` locates the slot.
        tx.partial_sign(&[payer], blockhash);

        let (channel_pda, bump) = find_channel_pda(
            &payer.pubkey(),
            &config.payee,
            &config.mint,
            &authorized_signer,
            salt,
            &config.program_id,
        );

        let payload = OpenPayload {
            challenge_id: "challenge-id".into(),
            channel_id: channel_pda.to_string(),
            payer: payer.pubkey().to_string(),
            payee: config.payee.to_string(),
            mint: config.mint.to_string(),
            authorized_signer: authorized_signer.to_string(),
            salt: salt.to_string(),
            bump,
            deposit_amount: deposit.to_string(),
            distribution_splits: typed_to_wire(&splits),
            transaction: encode_tx_b64(&tx),
        };
        (payload, tx)
    }

    fn encode_tx_b64(tx: &Transaction) -> String {
        let bytes = bincode::serialize(tx).expect("bincode serialize Transaction");
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
    }

    #[test]
    fn happy_path_validates_canonical_tx() {
        // A faithfully-rebuilt tx passes every shape check.
        let (cfg, _fee_payer_pk) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);

        let (payload, _tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);
        let decoded = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect("canonical tx must validate");
        assert_eq!(decoded.salt, 42);
        assert_eq!(decoded.deposit, 1_000_000);
        assert_eq!(decoded.grace_period, 60);
    }

    #[test]
    fn extra_program_in_account_keys_rejects_with_malicious_tx() {
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        // Splice an off-list program into `account_keys` and append a
        // no-op ix targeting it, so the allow-list scan reaches the
        // bogus key.
        let bogus = Address::new_from_array([0xAB; 32]);
        tx.message.account_keys.push(bogus);
        let bogus_idx = (tx.message.account_keys.len() - 1) as u8;
        tx.message
            .instructions
            .push(solana_message::compiled_instruction::CompiledInstruction {
                program_id_index: bogus_idx,
                accounts: vec![],
                data: vec![],
            });
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect_err("unknown program must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("not on the open-tx allow list")),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_fee_payer_slot_rejects() {
        // Server's fee-payer is one key; the tx puts a different key
        // in slot 0. Validator should raise
        // `BadFeePayerSlot { expected, got }` with the configured key
        // as `expected` and the slot-0 key as `got`.
        let (cfg, server_fee_payer_pk) = config_with_fresh_fee_payer();
        let attacker_fee_payer = Keypair::new();

        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);

        // Put `attacker_fee_payer` in slot 0 by passing it as the
        // message fee-payer.
        let canonical_ix = build_canonical_open_ix(&CanonicalOpenInputs {
            payer: payer.pubkey(),
            payee: cfg.payee,
            mint: cfg.mint,
            authorized_signer: auth_signer,
            salt: 42,
            deposit: 1_000_000,
            grace_period: cfg.grace_period_seconds,
            program_id: cfg.program_id,
            splits: &empty_splits(),
        });
        let attacker_fp_addr = pk_to_addr(&attacker_fee_payer.pubkey());
        let message = Message::new_with_blockhash(&[canonical_ix], Some(&attacker_fp_addr), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        tx.partial_sign(&[&payer], blockhash);

        let (channel_pda, bump) = find_channel_pda(
            &payer.pubkey(),
            &cfg.payee,
            &cfg.mint,
            &auth_signer,
            42,
            &cfg.program_id,
        );
        let payload = OpenPayload {
            challenge_id: "challenge-id".into(),
            channel_id: channel_pda.to_string(),
            payer: payer.pubkey().to_string(),
            payee: cfg.payee.to_string(),
            mint: cfg.mint.to_string(),
            authorized_signer: auth_signer.to_string(),
            salt: 42.to_string(),
            bump,
            deposit_amount: 1_000_000.to_string(),
            distribution_splits: typed_to_wire(&empty_splits()),
            transaction: encode_tx_b64(&tx),
        };

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect_err("wrong fee-payer slot must reject");
        match err {
            SessionError::BadFeePayerSlot { expected, got } => {
                assert_eq!(expected, server_fee_payer_pk);
                assert_eq!(got, attacker_fee_payer.pubkey());
            }
            other => panic!("expected BadFeePayerSlot, got {other:?}"),
        }
    }

    #[test]
    fn num_required_signatures_other_than_two_rejects() {
        // A real client tx requires two signers (payer + server
        // fee-payer). Forcing the count to 1 trips the `MaliciousTx`
        // branch even with the rest of the shape canonical.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        tx.message.header.num_required_signatures = 1;
        // Trim sigs to keep bincode happy; the validator reads
        // `header.num_required_signatures`, not `signatures.len()`.
        tx.signatures.truncate(1);
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect_err("wrong sig count must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("num_required_signatures")),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_open_ix_data_rejects() {
        // Flip one byte inside the open ix data. Everything else is
        // canonical (allow-listed programs, correct fee-payer slot,
        // two required sigs, matching blockhash) so only the
        // canonical-bytes comparison fires.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        // Find the open ix and flip a byte inside its borsh
        // `OpenArgs` payload. Index 1 sits inside the `salt` u64, so
        // the canonical rebuild yields different bytes.
        let pc_program_pk = addr_to_pk(&PAYMENT_CHANNELS_ID);
        for ix in tx.message.instructions.iter_mut() {
            let key = tx.message.account_keys[ix.program_id_index as usize];
            if addr_to_pk(&key) == pc_program_pk {
                let i = 1; // inside the discriminator + salt window
                ix.data[i] ^= 0xFF;
                break;
            }
        }
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect_err("tampered ix must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("does not match canonical bytes")),
            "{err:?}"
        );
    }

    #[test]
    fn blockhash_mismatch_rejects() {
        // Challenge committed to one blockhash, tx uses another.
        // Reject with `BlockhashMismatch` carrying both string forms.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let cached_blockhash = Hash::new_from_array([7u8; 32]);
        let tx_blockhash = Hash::new_from_array([8u8; 32]);
        let (payload, _tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, tx_blockhash);

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &cached_blockhash)
            .expect_err("blockhash drift must reject");
        match err {
            SessionError::BlockhashMismatch { expected, got } => {
                assert_eq!(expected, cached_blockhash.to_string());
                assert_eq!(got, tx_blockhash.to_string());
            }
            other => panic!("expected BlockhashMismatch, got {other:?}"),
        }
    }
}
