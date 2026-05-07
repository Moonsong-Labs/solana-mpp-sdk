//! `process_open` handler. Validates the open tx against the advertised
//! challenge, co-signs as fee payer, broadcasts, and persists the
//! channel record.
//!
//! Validation rebuilds the canonical multi-ix tx the server would emit
//! (compute-budget prelude, `CreateIdempotent` ATAs for payee, payer,
//! and each split recipient, then the payment-channels `open` ix) and
//! byte-compares the submitted tx slot-by-slot. The channel vault ATA
//! is intentionally NOT in the prelude: upstream's `open` ix creates it
//! itself non-idempotently, and a preceding `CreateIdempotent` would
//! race with that and trip `IllegalOwner`. Any reorder, insert, or
//! tamper trips a typed `MaliciousTx`, `BadFeePayerSlot`, or
//! `BlockhashMismatch` rejection before we hit the RPC.

use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use crate::error::SessionError;
use crate::program::payment_channels::canonical_tx::{
    self, build_canonical_open_ixs, DEFAULT_COMPUTE_UNIT_LIMIT, DEFAULT_COMPUTE_UNIT_PRICE,
    MAX_SPLITS,
};
use crate::program::payment_channels::state::find_channel_pda;
use crate::protocol::intents::session::{OpenPayload, Split};
use crate::server::session::SessionConfig;

// Re-exports so callers that already import from this module
// (`session::ix`, `session::topup`, `session::tx_shape`, downstream
// tests) keep resolving without hopping the canonical path.
pub use canonical_tx::{
    addr_to_pk, ata_address, ata_program_id, build_canonical_open_ix, pk_to_addr, spl_token_id,
    CanonicalOpenInputs,
};

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

/// Validate a client-submitted open tx against the canonical multi-ix
/// list the server would emit. Typed `splits` keeps the wire/typed
/// conversion at the handler boundary so this helper stays on the byte
/// contract.
pub(crate) fn validate_open_tx_shape(
    payload: &OpenPayload,
    splits: &[Split],
    config: &SessionConfig,
    expected_blockhash: &Hash,
) -> Result<DecodedOpenTx, SessionError> {
    if splits.len() > MAX_SPLITS {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "open: splits.len() = {} exceeds the {}-recipient cap",
                splits.len(),
                MAX_SPLITS,
            ),
        });
    }

    let parsed = parse_open_payload(payload)?;

    let fee_payer = config.fee_payer.as_ref().ok_or_else(|| {
        SessionError::InternalError("session config missing fee_payer; v1 is server-submit".into())
    })?;
    let fee_payer_pk = fee_payer.signer.pubkey();

    let (canonical_pda, canonical_bump) = find_channel_pda(
        &parsed.payer,
        &parsed.payee,
        &parsed.mint,
        &parsed.authorized_signer,
        parsed.salt,
        &config.program_id,
    );

    let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
        program_id: config.program_id,
        payer: parsed.payer,
        payee: parsed.payee,
        mint: parsed.mint,
        authorized_signer: parsed.authorized_signer,
        salt: parsed.salt,
        deposit: parsed.deposit,
        grace_period_seconds: config.grace_period_seconds,
        splits,
        channel_id: canonical_pda,
        compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
        compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
    });

    let tx = crate::server::session::tx_shape::validate_canonical_multi_ix_tx_shape(
        &payload.transaction,
        &canonical_ixs,
        &fee_payer_pk,
        expected_blockhash,
        "open",
    )?;

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
    use payment_channels_client::programs::PAYMENT_CHANNELS_ID;
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

    /// Payload + canonical multi-ix tx pair, signed by the payer only.
    /// Fee-payer slot stays empty per the wire format.
    fn build_payload_and_tx(
        config: &SessionConfig,
        payer: &Keypair,
        authorized_signer: Pubkey,
        salt: u64,
        deposit: u64,
        blockhash: Hash,
    ) -> (OpenPayload, Transaction) {
        build_payload_and_tx_with_splits(
            config,
            payer,
            authorized_signer,
            salt,
            deposit,
            blockhash,
            &empty_splits(),
        )
    }

    fn build_payload_and_tx_with_splits(
        config: &SessionConfig,
        payer: &Keypair,
        authorized_signer: Pubkey,
        salt: u64,
        deposit: u64,
        blockhash: Hash,
        splits: &[Split],
    ) -> (OpenPayload, Transaction) {
        let (channel_pda, bump) = find_channel_pda(
            &payer.pubkey(),
            &config.payee,
            &config.mint,
            &authorized_signer,
            salt,
            &config.program_id,
        );

        let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
            program_id: config.program_id,
            payer: payer.pubkey(),
            payee: config.payee,
            mint: config.mint,
            authorized_signer,
            salt,
            deposit,
            grace_period_seconds: config.grace_period_seconds,
            splits,
            channel_id: channel_pda,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });

        let fee_payer_pk = config.fee_payer.as_ref().unwrap().signer.pubkey();
        let fee_payer_addr = pk_to_addr(&fee_payer_pk);

        let message = Message::new_with_blockhash(&canonical_ixs, Some(&fee_payer_addr), &blockhash);

        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        tx.partial_sign(&[payer], blockhash);

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
            distribution_splits: typed_to_wire(splits),
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
        // Append an extra ix beyond the canonical multi-ix list. Length
        // mismatch fires before any per-ix work.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

        let system_addr = solana_address::Address::new_from_array(
            solana_sdk_ids::system_program::ID.to_bytes(),
        );
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
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch") || reason.contains("expected")),
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

        let (channel_pda, bump) = find_channel_pda(
            &payer.pubkey(),
            &cfg.payee,
            &cfg.mint,
            &auth_signer,
            42,
            &cfg.program_id,
        );

        let canonical_ixs = build_canonical_open_ixs(&CanonicalOpenInputs {
            program_id: cfg.program_id,
            payer: payer.pubkey(),
            payee: cfg.payee,
            mint: cfg.mint,
            authorized_signer: auth_signer,
            salt: 42,
            deposit: 1_000_000,
            grace_period_seconds: cfg.grace_period_seconds,
            splits: &empty_splits(),
            channel_id: channel_pda,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });
        let attacker_fp_addr = pk_to_addr(&attacker_fee_payer.pubkey());
        let message =
            Message::new_with_blockhash(&canonical_ixs, Some(&attacker_fp_addr), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        tx.partial_sign(&[&payer], blockhash);

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
        // canonical so only the byte-compare on the matching slot fires.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let auth_signer = Keypair::new().pubkey();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_payload_and_tx(&cfg, &payer, auth_signer, 42, 1_000_000, blockhash);

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
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
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
