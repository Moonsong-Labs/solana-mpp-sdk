//! `process_open` handler. Validates the open tx against the advertised
//! challenge, co-signs as fee payer, broadcasts, and persists the
//! channel record.
//!
//! Validation rebuilds the canonical `open` ix from the server's view
//! of the args (salt, deposit, splits, grace period) and checks the
//! submitted tx carries exactly that one ix, byte-for-byte, with
//! account-meta flags and signature-vec length matching the message
//! header. Anything else trips a typed `MaliciousTx`, `BadFeePayerSlot`,
//! or `BlockhashMismatch` rejection before we hit the RPC.

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
/// `Transaction` plus the typed values pulled out of the open ix args.
#[derive(Debug)]
pub(crate) struct DecodedOpenTx {
    /// Fee-payer signature slot is empty; the caller fills it after
    /// co-signing.
    pub tx: Transaction,
    pub salt: u64,
    pub deposit: u64,
    pub grace_period: u32,
    pub canonical_bump: u8,
    pub channel_id: Pubkey,
}

/// Inputs for rebuilding the canonical open ix.
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
/// `OpenBuilder` wants. Trailing slots beyond `splits.len()` are
/// zero-filled out to the fixed 32-entry wire shape.
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
/// `spl_token` and `spl_associated_token_account_client` re-export)
/// into the SDK's 3.x `Pubkey`. No-op byte-wise.
fn id_v2_to_v3(bytes: [u8; 32]) -> Pubkey {
    Pubkey::new_from_array(bytes)
}

pub fn spl_token_id() -> Pubkey {
    id_v2_to_v3(spl_token::id().to_bytes())
}

pub(crate) fn ata_program_id() -> Pubkey {
    id_v2_to_v3(spl_associated_token_account_client::program::ID.to_bytes())
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

/// Build the canonical `open` ix matching what an honest client emits
/// via `OpenBuilder`.
pub fn build_canonical_open_ix(inputs: &CanonicalOpenInputs<'_>) -> Instruction {
    // Event authority PDA, single seed `b"event_authority"`. Upstream
    // declares it in `program/payment_channels/src/event_engine.rs`
    // but the Codama client doesn't re-export it.
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

    // ATAs derive against classic SPL Token in v1; using a different
    // token program here would yield a different ATA.
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

/// Writability of `account_keys[i]` from the message header. Mirrors
/// the crate-private `Message::is_writable_index`.
pub(crate) fn key_is_writable(
    header: &solana_message::MessageHeader,
    account_keys_len: usize,
    i: usize,
) -> bool {
    let num_signed = header.num_required_signatures as usize;
    let writable_signed_end = num_signed.saturating_sub(header.num_readonly_signed_accounts as usize);
    if i < writable_signed_end {
        return true;
    }
    if i >= num_signed {
        let writable_unsigned_end =
            account_keys_len.saturating_sub(header.num_readonly_unsigned_accounts as usize);
        return i < writable_unsigned_end;
    }
    false
}

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
    let _advertised_bump = payload.bump; // re-derived below; carried for the assertion in `process_open`
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
/// Decodes the base64 partial-signed tx and checks: exactly one
/// instruction targeting the payment-channels program, fee-payer in
/// slot 0, two required signatures with a matching signature-vec
/// length, blockhash matches the cached challenge, and account metas
/// (pubkey, signer, writable) all line up with the canonical ix the
/// server would emit. Typed `splits` keeps the wire/typed conversion
/// at the handler boundary so this helper stays on the byte contract.
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

    // Any extra ix (system transfer, compute-budget tweak, ATA-create)
    // would land under the server's fee-payer signature.
    if tx.message.instructions.len() != 1 {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected exactly 1 instruction, got {}",
                tx.message.instructions.len()
            ),
        });
    }

    // Payer + server fee-payer.
    if tx.message.header.num_required_signatures != 2 {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected num_required_signatures == 2, got {}",
                tx.message.header.num_required_signatures
            ),
        });
    }

    // A short signature vec sails through the slot-0 overwrite the
    // orchestrator does later; the cluster would only reject after
    // broadcast.
    let expected_sig_count = tx.message.header.num_required_signatures as usize;
    if tx.signatures.len() != expected_sig_count {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected {expected_sig_count} signatures, got {}",
                tx.signatures.len()
            ),
        });
    }

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

    if tx.message.recent_blockhash != *expected_blockhash {
        return Err(SessionError::BlockhashMismatch {
            expected: expected_blockhash.to_string(),
            got: tx.message.recent_blockhash.to_string(),
        });
    }

    let (canonical_pda, canonical_bump) = find_channel_pda(
        &parsed.payer,
        &parsed.payee,
        &parsed.mint,
        &parsed.authorized_signer,
        parsed.salt,
        &config.program_id,
    );

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

    let pc_program_pk = addr_to_pk(&PAYMENT_CHANNELS_ID);
    let open_ix_compiled = &tx.message.instructions[0];
    let program_idx = open_ix_compiled.program_id_index as usize;
    let program_key = tx
        .message
        .account_keys
        .get(program_idx)
        .ok_or_else(|| SessionError::MaliciousTx {
            reason: format!("compiled ix references account index {program_idx} out of range"),
        })?;
    if addr_to_pk(program_key) != pc_program_pk {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected payment-channels program at instruction[0], got {}",
                addr_to_pk(program_key)
            ),
        });
    }

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
    let account_keys_len = tx.message.account_keys.len();
    for (i, (slot_idx, expected_meta)) in open_ix_compiled
        .accounts
        .iter()
        .zip(canonical_ix.accounts.iter())
        .enumerate()
    {
        let slot = *slot_idx as usize;
        let got = tx
            .message
            .account_keys
            .get(slot)
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
        let got_signer = tx.message.is_signer(slot);
        if got_signer != expected_meta.is_signer {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "open ix account #{i} signer flag mismatch: expected {}, got {}",
                    expected_meta.is_signer, got_signer
                ),
            });
        }
        let got_writable = key_is_writable(&tx.message.header, account_keys_len, slot);
        if got_writable != expected_meta.is_writable {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "open ix account #{i} writable flag mismatch: expected {}, got {}",
                    expected_meta.is_writable, got_writable
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
    //! Each case trips one specific check in `validate_open_tx_shape`.
    //! End-to-end happy-path coverage lives in the L1 oracle.

    use super::*;
    use crate::protocol::intents::session::{typed_to_wire, Split};
    use crate::server::session::Pricing;
    use solana_keychain::MemorySigner;
    use solana_message::Message;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;
    use std::sync::Arc;

    fn fresh_memory_signer() -> Arc<dyn solana_keychain::SolanaSigner> {
        let kp = Keypair::new();
        let bytes = kp.to_bytes();
        Arc::new(MemorySigner::from_bytes(&bytes).expect("memory signer accepts keypair bytes"))
    }

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

    /// Payload + canonical tx pair, signed by the payer only. Fee-payer
    /// slot stays empty per the wire format.
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

        let message = Message::new_with_blockhash(
            &[canonical_ix],
            Some(&fee_payer_addr),
            &blockhash,
        );

        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
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
    fn extra_instruction_rejects_with_malicious_tx() {
        // System ix appended; the count check fires before any per-ix
        // work, so even a benign program is rejected.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        let system_addr = Address::new_from_array(solana_sdk_ids::system_program::ID.to_bytes());
        tx.message.account_keys.push(system_addr);
        let sys_idx = (tx.message.account_keys.len() - 1) as u8;
        tx.message
            .instructions
            .push(solana_message::compiled_instruction::CompiledInstruction {
                program_id_index: sys_idx,
                accounts: vec![0, 1],
                data: vec![],
            });
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect_err("extra ix must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("expected exactly 1 instruction")),
            "{err:?}"
        );
    }

    #[test]
    fn signature_count_below_required_rejects() {
        // Header still says two required sigs; vec is truncated to one
        // so the slot-0 overwrite would wipe the lone client sig.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        assert_eq!(tx.message.header.num_required_signatures, 2);
        tx.signatures.truncate(1);
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_open_tx_shape(&payload, &empty_splits(), &cfg, &blockhash)
            .expect_err("short signature vec must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("expected 2 signatures")),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_fee_payer_slot_rejects() {
        let (cfg, server_fee_payer_pk) = config_with_fresh_fee_payer();
        let attacker_fee_payer = Keypair::new();

        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);

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
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        tx.message.header.num_required_signatures = 1;
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
        // Flip one byte inside the open ix data; everything else stays
        // canonical so only the byte-compare fires.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        // Index 1 sits inside the `OpenArgs.salt` u64.
        let pc_program_pk = addr_to_pk(&PAYMENT_CHANNELS_ID);
        for ix in tx.message.instructions.iter_mut() {
            let key = tx.message.account_keys[ix.program_id_index as usize];
            if addr_to_pk(&key) == pc_program_pk {
                ix.data[1] ^= 0xFF;
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
