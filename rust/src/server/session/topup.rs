//! `process_topup` handler. Validates the submitted top-up tx
//! against the advertised challenge, co-signs as fee payer,
//! broadcasts, and bumps the persisted deposit.
//!
//! Validation rebuilds the canonical multi-ix top-up tx (compute-budget
//! prelude plus the upstream `top_up` ix) and byte-compares the
//! submitted tx slot-by-slot. Same fee-payer-slot, signer-count,
//! signature-vec, and blockhash gates as `process_open`. Token-2022
//! ATAs derive against a different program id, so v1 keeps the
//! canonical ix on classic SPL.

use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use crate::error::SessionError;
use crate::program::payment_channels::canonical_tx::{
    self, build_canonical_topup_ixs, DEFAULT_COMPUTE_UNIT_LIMIT, DEFAULT_COMPUTE_UNIT_PRICE,
};
use crate::protocol::intents::session::TopUpPayload;
use crate::server::session::tx_shape::validate_canonical_multi_ix_tx_shape;
use crate::server::session::SessionConfig;

// Re-exports so downstream tests that import from this module keep
// resolving without hopping the canonical path.
pub use canonical_tx::{build_canonical_topup_ix, CanonicalTopupInputs};

/// Validated top-up tx; slot 0 stays empty for the caller to fill
/// with the fee-payer sig.
#[derive(Debug)]
pub(crate) struct DecodedTopupTx {
    pub tx: Transaction,
}

/// Validate a client-submitted top-up tx against the canonical multi-ix
/// list the server would emit for `(channel_id, additional)`.
pub(crate) fn validate_topup_tx_shape(
    tx_b64: &str,
    config: &SessionConfig,
    expected_channel_id: &Pubkey,
    expected_additional: u64,
    expected_payer: &Pubkey,
    expected_mint: &Pubkey,
    expected_blockhash: &Hash,
) -> Result<DecodedTopupTx, SessionError> {
    let fee_payer = config.fee_payer.as_ref().ok_or_else(|| {
        SessionError::InternalError("session config missing fee_payer; v1 is server-submit".into())
    })?;
    let fee_payer_pk = fee_payer.signer.pubkey();

    let canonical_ixs = build_canonical_topup_ixs(&CanonicalTopupInputs {
        program_id: config.program_id,
        payer: *expected_payer,
        channel_id: *expected_channel_id,
        mint: *expected_mint,
        amount: expected_additional,
        compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
        compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
    });

    let tx = validate_canonical_multi_ix_tx_shape(
        tx_b64,
        &canonical_ixs,
        &fee_payer_pk,
        expected_blockhash,
        "topup",
    )?;

    Ok(DecodedTopupTx { tx })
}

pub(crate) struct ParsedTopupPayload {
    pub channel_id: Pubkey,
    pub additional_amount: u64,
}

pub(crate) fn parse_topup_payload(
    payload: &TopUpPayload,
) -> Result<ParsedTopupPayload, SessionError> {
    let channel_id = decode_pubkey("channelId", &payload.channel_id)?;
    let additional_amount: u64 =
        payload
            .additional_amount
            .parse()
            .map_err(|e| SessionError::InvalidAmount(format!("additionalAmount: {e}")))?;
    if additional_amount == 0 {
        return Err(SessionError::InvalidAmount(
            "additionalAmount must be > 0".into(),
        ));
    }
    Ok(ParsedTopupPayload {
        channel_id,
        additional_amount,
    })
}

fn decode_pubkey(field: &'static str, raw: &str) -> Result<Pubkey, SessionError> {
    let bytes = bs58::decode(raw)
        .into_vec()
        .map_err(|e| SessionError::OnChainStateMismatch {
            field,
            expected: "base58 pubkey".into(),
            got: format!("{raw}: {e}"),
        })?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SessionError::OnChainStateMismatch {
            field,
            expected: "32-byte pubkey".into(),
            got: raw.to_string(),
        })?;
    Ok(Pubkey::new_from_array(arr))
}

#[cfg(test)]
mod tests {
    //! Each case trips one specific check in `validate_topup_tx_shape`.
    //! End-to-end happy-path coverage lives in the L1 oracle.

    use super::*;
    use crate::server::session::open::{addr_to_pk, pk_to_addr};
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

    /// Canonical multi-ix top-up tx signed by the payer; slot 0 stays
    /// empty for the server's fee-payer sig.
    fn build_topup_payload_and_tx(
        config: &SessionConfig,
        payer: &Keypair,
        channel_id: Pubkey,
        additional: u64,
        blockhash: Hash,
    ) -> (TopUpPayload, Transaction) {
        let canonical_ixs = build_canonical_topup_ixs(&CanonicalTopupInputs {
            program_id: config.program_id,
            payer: payer.pubkey(),
            channel_id,
            mint: config.mint,
            amount: additional,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });

        let fee_payer_pk = config.fee_payer.as_ref().unwrap().signer.pubkey();
        let fee_payer_addr = pk_to_addr(&fee_payer_pk);

        let message =
            Message::new_with_blockhash(&canonical_ixs, Some(&fee_payer_addr), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        tx.partial_sign(&[payer], blockhash);

        let payload = TopUpPayload {
            challenge_id: "challenge-id".into(),
            channel_id: channel_id.to_string(),
            additional_amount: additional.to_string(),
            transaction: encode_tx_b64(&tx),
        };
        (payload, tx)
    }

    fn encode_tx_b64(tx: &Transaction) -> String {
        let bytes = bincode::serialize(tx).expect("bincode serialize Transaction");
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
    }

    fn dummy_channel_id() -> Pubkey {
        Pubkey::new_from_array([0xC1; 32])
    }

    #[test]
    fn happy_path_validates_canonical_tx() {
        let (cfg, _fee_payer_pk) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let cid = dummy_channel_id();
        let blockhash = Hash::new_from_array([7u8; 32]);

        let (payload, _tx) = build_topup_payload_and_tx(&cfg, &payer, cid, 500_000, blockhash);
        let decoded = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &blockhash,
        )
        .expect("canonical topup tx must validate");
        assert_eq!(
            decoded.tx.signatures[0],
            solana_signature::Signature::default()
        );
    }

    #[test]
    fn extra_instruction_rejects_with_malicious_tx() {
        // Append an extra ix beyond the canonical multi-ix list; the
        // length check fires before any per-ix work.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let cid = dummy_channel_id();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_topup_payload_and_tx(&cfg, &payer, cid, 500_000, blockhash);

        let system_addr =
            solana_address::Address::new_from_array(solana_sdk_ids::system_program::ID.to_bytes());
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

        let err = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &blockhash,
        )
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
        let cid = dummy_channel_id();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_topup_payload_and_tx(&cfg, &payer, cid, 500_000, blockhash);

        assert_eq!(tx.message.header.num_required_signatures, 2);
        tx.signatures.truncate(1);
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &blockhash,
        )
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
        let cid = dummy_channel_id();
        let blockhash = Hash::new_from_array([7u8; 32]);

        let canonical_ixs = build_canonical_topup_ixs(&CanonicalTopupInputs {
            program_id: cfg.program_id,
            payer: payer.pubkey(),
            channel_id: cid,
            mint: cfg.mint,
            amount: 500_000,
            compute_unit_price: DEFAULT_COMPUTE_UNIT_PRICE,
            compute_unit_limit: DEFAULT_COMPUTE_UNIT_LIMIT,
        });
        let attacker_addr = pk_to_addr(&attacker_fee_payer.pubkey());
        let message =
            Message::new_with_blockhash(&canonical_ixs, Some(&attacker_addr), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        tx.partial_sign(&[&payer], blockhash);

        let payload = TopUpPayload {
            challenge_id: "challenge-id".into(),
            channel_id: cid.to_string(),
            additional_amount: 500_000.to_string(),
            transaction: encode_tx_b64(&tx),
        };

        let err = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &blockhash,
        )
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
        let cid = dummy_channel_id();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_topup_payload_and_tx(&cfg, &payer, cid, 500_000, blockhash);

        tx.message.header.num_required_signatures = 1;
        tx.signatures.truncate(1);
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &blockhash,
        )
        .expect_err("wrong sig count must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("num_required_signatures")),
            "{err:?}"
        );
    }

    #[test]
    fn tampered_topup_ix_data_rejects() {
        // Flip a byte inside the payment-channels `top_up` ix data
        // (index 1 sits inside the `TopUpArgs.amount` u64; byte 0 is
        // the discriminator). Only the matching slot's byte-compare
        // fires.
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let cid = dummy_channel_id();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let (mut payload, mut tx) =
            build_topup_payload_and_tx(&cfg, &payer, cid, 500_000, blockhash);

        let pc_program_pk = addr_to_pk(&PAYMENT_CHANNELS_ID);
        for ix in tx.message.instructions.iter_mut() {
            let key = tx.message.account_keys[ix.program_id_index as usize];
            if addr_to_pk(&key) == pc_program_pk {
                ix.data[1] ^= 0xFF;
                break;
            }
        }
        payload.transaction = encode_tx_b64(&tx);

        let err = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &blockhash,
        )
        .expect_err("tampered topup ix must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
            "{err:?}"
        );
    }

    #[test]
    fn blockhash_mismatch_rejects() {
        let (cfg, _) = config_with_fresh_fee_payer();
        let payer = Keypair::new();
        let cid = dummy_channel_id();
        let cached_blockhash = Hash::new_from_array([7u8; 32]);
        let tx_blockhash = Hash::new_from_array([8u8; 32]);
        let (payload, _tx) =
            build_topup_payload_and_tx(&cfg, &payer, cid, 500_000, tx_blockhash);

        let err = validate_topup_tx_shape(
            &payload.transaction,
            &cfg,
            &cid,
            500_000,
            &payer.pubkey(),
            &cfg.mint,
            &cached_blockhash,
        )
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
