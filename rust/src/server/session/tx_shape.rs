//! Canonical multi-ix tx-shape gate for client-submitted handler txs.
//!
//! Open and topup share the same broadcast contract: the client sends a
//! partial-signed tx, the server rebuilds the canonical multi-ix list,
//! signs slot 0, and broadcasts. The gate refuses anything that isn't
//! byte-equal to the canonical list at every slot. A looser check (extra
//! ix, reordered ix, drifting account flags, short signature vec) lets a
//! malicious client smuggle ops under the server fee-payer signature.
//!
//! The byte-equality check works by re-compiling the canonical ix list
//! into a `Message` with the same fee payer and blockhash, then diffing
//! the compiled form (account_keys, header, per-ix indices and data)
//! against the submitted tx. This way the dedup-and-promote logic
//! Solana's message compiler runs (a key that's signer in any ix gets
//! promoted to signer in the message header, then back-fills every ix
//! that references it) is applied to both sides identically, so two
//! byte-equal canonical ix lists yield byte-equal compiled messages.

use bincode::Options;
use solana_address::Address;
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use crate::error::SessionError;
use crate::server::session::open::addr_to_pk;

/// Validate a partial-signed client tx against the canonical multi-ix
/// list the server would emit. Returns the decoded `Transaction` on
/// success; the caller signs slot 0 with the server fee-payer.
///
/// The check walks the list in order:
///
/// 1. base64 decode + bincode deserialize.
/// 2. `recent_blockhash` matches the cached challenge blockhash.
/// 3. Slot 0 of `account_keys` is the advertised fee payer and
///    `num_required_signatures == 2` (payer + server fee payer).
/// 4. The submitted message and the canonical message have the same
///    header (`num_required_signatures`, `num_readonly_signed_accounts`,
///    `num_readonly_unsigned_accounts`) and the same `account_keys` in
///    the same order.
/// 5. `instructions.len() == canonical_ixs.len()` and each compiled ix
///    matches the canonical compiled ix slot-for-slot
///    (`program_id_index`, `accounts`, `data`).
/// 6. `tx.signatures.len() == header.num_required_signatures` (a short
///    signature vec sails through the slot-0 overwrite the handler does
///    later).
pub(crate) fn validate_canonical_multi_ix_tx_shape(
    tx_b64: &str,
    canonical_ixs: &[Instruction],
    fee_payer_pk: &Pubkey,
    expected_blockhash: &Hash,
    ix_label: &'static str,
) -> Result<Transaction, SessionError> {
    let tx_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tx_b64)
        .map_err(|e| SessionError::MaliciousTx {
            reason: format!("base64 decode failed: {e}"),
        })?;

    // bincode 1.x defaults to varint length-prefix and silently accepts
    // trailing bytes. Solana txs are fixint-encoded, and an attacker who
    // appends junk after a canonical tx would get a "valid" decode that
    // re-serialises clean: the gate would pass and the server would sign
    // and broadcast. Fixint + reject-trailing-bytes matches Solana's
    // standard tx serialisation and surfaces tampering as MaliciousTx.
    let tx: Transaction = bincode::options()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize::<Transaction>(&tx_bytes)
        .map_err(|e| SessionError::MaliciousTx {
            reason: format!("transaction bincode decode failed: {e}"),
        })?;

    if tx.message.recent_blockhash != *expected_blockhash {
        return Err(SessionError::BlockhashMismatch {
            expected: expected_blockhash.to_string(),
            got: tx.message.recent_blockhash.to_string(),
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
    if slot0_pk != *fee_payer_pk {
        return Err(SessionError::BadFeePayerSlot {
            expected: *fee_payer_pk,
            got: slot0_pk,
        });
    }

    if tx.message.header.num_required_signatures != 2 {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected num_required_signatures == 2, got {}",
                tx.message.header.num_required_signatures
            ),
        });
    }

    // Slot 0 is the server fee-payer's signature; the handler overwrites
    // it after validation, so today a forged sig in slot 0 is benign.
    // Reject anyway: a future refactor that conditionally skips the
    // overwrite would let a forgery through, and the check is one byte
    // compare.
    if tx
        .signatures
        .first()
        .copied()
        .unwrap_or_default()
        != solana_signature::Signature::default()
    {
        return Err(SessionError::MaliciousTx {
            reason: "slot 0 signature must be empty for server fee-payer co-sign".into(),
        });
    }

    // Compile the canonical ix list into a Message with the same fee
    // payer and blockhash. The compiler dedups account keys and
    // promotes signer / writable flags identically on both sides, so
    // two byte-equal canonical lists yield byte-equal compiled forms.
    // Note: the open-side splits cap (rejected upstream of this gate at
    // 32 entries) keeps the compiled key set well under the 256 u8
    // index ceiling, so `Message::new_with_blockhash` cannot panic on
    // a key-count overflow on the canonical side.
    let fee_payer_addr = Address::new_from_array(fee_payer_pk.to_bytes());
    let canonical_msg = Message::new_with_blockhash(
        canonical_ixs,
        Some(&fee_payer_addr),
        expected_blockhash,
    );

    if tx.message.header != canonical_msg.header {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "{ix_label}: mismatch on message header (expected {:?}, got {:?})",
                canonical_msg.header, tx.message.header
            ),
        });
    }

    if tx.message.account_keys.len() != canonical_msg.account_keys.len() {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "{ix_label}: mismatch on account_keys length (expected {}, got {})",
                canonical_msg.account_keys.len(),
                tx.message.account_keys.len()
            ),
        });
    }
    for (i, (got, expected)) in tx
        .message
        .account_keys
        .iter()
        .zip(canonical_msg.account_keys.iter())
        .enumerate()
    {
        if got != expected {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "{ix_label}: mismatch on account_keys[{i}] (expected {}, got {})",
                    addr_to_pk(expected),
                    addr_to_pk(got),
                ),
            });
        }
    }

    if tx.message.instructions.len() != canonical_msg.instructions.len() {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "{ix_label}: expected {} ixs, got {}",
                canonical_msg.instructions.len(),
                tx.message.instructions.len()
            ),
        });
    }

    for (i, (got, expected)) in tx
        .message
        .instructions
        .iter()
        .zip(canonical_msg.instructions.iter())
        .enumerate()
    {
        if got.program_id_index != expected.program_id_index {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "{ix_label}: ix {i} mismatch on program_id_index (expected {}, got {})",
                    expected.program_id_index, got.program_id_index
                ),
            });
        }
        if got.accounts != expected.accounts {
            return Err(SessionError::MaliciousTx {
                reason: format!("{ix_label}: ix {i} mismatch on accounts"),
            });
        }
        if got.data != expected.data {
            return Err(SessionError::MaliciousTx {
                reason: format!("{ix_label}: ix {i} mismatch on data"),
            });
        }
    }

    // A short signature vec sails through the slot-0 overwrite the
    // handler does later, and the cluster only catches it after
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

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::AccountMeta;
    use solana_sdk::signature::Keypair;
    use solana_sdk::signer::Signer;

    fn pk_addr(pk: &Pubkey) -> Address {
        Address::new_from_array(pk.to_bytes())
    }

    /// Two-program canonical fixture: two distinct programs, the first
    /// reading the payer (signer + writable), the second writing the
    /// payer. Both compile cleanly into a 2-required-signatures message
    /// (fee payer plus payer) without colliding flags. Enough to
    /// exercise the multi-ix gate without dragging in the full open /
    /// topup canonical builders.
    fn fixture_ixs(payer: Pubkey) -> [Instruction; 2] {
        [
            Instruction {
                program_id: Pubkey::new_from_array([0xCBu8; 32]),
                accounts: vec![AccountMeta::new(payer, true)],
                data: vec![3, 1, 0, 0, 0, 0, 0, 0, 0],
            },
            Instruction {
                program_id: Pubkey::new_from_array([0xCAu8; 32]),
                accounts: vec![AccountMeta::new(payer, true)],
                data: vec![2, 0x40, 0x0D, 0x03, 0x00],
            },
        ]
    }

    /// Build a partial-signed tx (slot 0 fee-payer empty, slot 1 payer
    /// signed) carrying `ixs`. Sized for two required signatures.
    fn build_partial_signed_tx(
        ixs: &[Instruction],
        fee_payer: &Pubkey,
        payer: &Keypair,
        blockhash: Hash,
    ) -> Transaction {
        let fee_payer_addr = pk_addr(fee_payer);
        let message = Message::new_with_blockhash(ixs, Some(&fee_payer_addr), &blockhash);
        let mut tx = Transaction::new_unsigned(message);
        tx.signatures = vec![
            solana_signature::Signature::default();
            tx.message.header.num_required_signatures as usize
        ];
        tx.partial_sign(&[payer], blockhash);
        tx
    }

    fn encode_tx_b64(tx: &Transaction) -> String {
        let bytes = bincode::serialize(tx).expect("bincode serialize");
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
    }

    #[test]
    fn happy_path_validates_canonical_multi_ix_tx() {
        let fee_payer = Keypair::new().pubkey();
        let payer = Keypair::new();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let canonical = fixture_ixs(payer.pubkey());

        let tx = build_partial_signed_tx(&canonical, &fee_payer, &payer, blockhash);
        let encoded = encode_tx_b64(&tx);

        validate_canonical_multi_ix_tx_shape(
            &encoded,
            &canonical,
            &fee_payer,
            &blockhash,
            "fixture",
        )
        .expect("byte-equal multi-ix tx must validate");
    }

    #[test]
    fn reordered_ixs_reject_as_malicious() {
        let fee_payer = Keypair::new().pubkey();
        let payer = Keypair::new();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let canonical = fixture_ixs(payer.pubkey());

        let mut swapped = canonical.clone().to_vec();
        swapped.swap(0, 1);
        let tx = build_partial_signed_tx(&swapped, &fee_payer, &payer, blockhash);
        let encoded = encode_tx_b64(&tx);

        let err = validate_canonical_multi_ix_tx_shape(
            &encoded,
            &canonical,
            &fee_payer,
            &blockhash,
            "fixture",
        )
        .expect_err("reordered ixs must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch")),
            "{err:?}"
        );
    }

    #[test]
    fn extra_ix_rejects_as_malicious() {
        let fee_payer = Keypair::new().pubkey();
        let payer = Keypair::new();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let canonical = fixture_ixs(payer.pubkey());

        let mut padded = canonical.clone().to_vec();
        padded.push(Instruction {
            program_id: Pubkey::new_from_array([0xFFu8; 32]),
            accounts: vec![AccountMeta::new(payer.pubkey(), true)],
            data: vec![0xAA],
        });
        let tx = build_partial_signed_tx(&padded, &fee_payer, &payer, blockhash);
        let encoded = encode_tx_b64(&tx);

        let err = validate_canonical_multi_ix_tx_shape(
            &encoded,
            &canonical,
            &fee_payer,
            &blockhash,
            "fixture",
        )
        .expect_err("extra ix must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("mismatch") || reason.contains("expected")),
            "{err:?}"
        );
    }

    #[test]
    fn trailing_bytes_after_canonical_tx_reject_as_malicious() {
        // Encode a canonical tx, append junk bytes to the bincode buffer,
        // and base64 the result. With the default bincode decoder the junk
        // sails through and the recompiled-Message diff still matches; with
        // reject-trailing-bytes on, the decode fails and the validator
        // surfaces MaliciousTx before any RPC work.
        let fee_payer = Keypair::new().pubkey();
        let payer = Keypair::new();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let canonical = fixture_ixs(payer.pubkey());

        let tx = build_partial_signed_tx(&canonical, &fee_payer, &payer, blockhash);
        let mut bytes = bincode::serialize(&tx).expect("bincode serialize");
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes);

        let err = validate_canonical_multi_ix_tx_shape(
            &encoded,
            &canonical,
            &fee_payer,
            &blockhash,
            "fixture",
        )
        .expect_err("trailing bytes must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("decode failed")),
            "{err:?}"
        );
    }

    #[test]
    fn slot_0_signature_must_be_empty() {
        // Pre-fill slot 0 with a non-default signature. The handler
        // overwrites slot 0 after validation; a future refactor that
        // skips the overwrite would let the forgery through, so reject
        // pre-emptively.
        let fee_payer = Keypair::new().pubkey();
        let payer = Keypair::new();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let canonical = fixture_ixs(payer.pubkey());

        let mut tx = build_partial_signed_tx(&canonical, &fee_payer, &payer, blockhash);
        // Forge a non-empty slot-0 sig. The wire shape stays valid (header
        // still says two required sigs and the vec length matches) so the
        // dedicated check is the one that fires.
        tx.signatures[0] = solana_signature::Signature::from([0xAAu8; 64]);
        let encoded = encode_tx_b64(&tx);

        let err = validate_canonical_multi_ix_tx_shape(
            &encoded,
            &canonical,
            &fee_payer,
            &blockhash,
            "fixture",
        )
        .expect_err("non-empty slot 0 sig must reject");
        assert!(
            matches!(err, SessionError::MaliciousTx { ref reason } if reason.contains("slot 0 signature must be empty")),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_fee_payer_rejects() {
        let server_fee_payer = Keypair::new().pubkey();
        let attacker = Keypair::new().pubkey();
        let payer = Keypair::new();
        let blockhash = Hash::new_from_array([7u8; 32]);
        let canonical = fixture_ixs(payer.pubkey());

        let tx = build_partial_signed_tx(&canonical, &attacker, &payer, blockhash);
        let encoded = encode_tx_b64(&tx);

        let err = validate_canonical_multi_ix_tx_shape(
            &encoded,
            &canonical,
            &server_fee_payer,
            &blockhash,
            "fixture",
        )
        .expect_err("wrong fee payer must reject");
        match err {
            SessionError::BadFeePayerSlot { expected, got } => {
                assert_eq!(expected, server_fee_payer);
                assert_eq!(got, attacker);
            }
            other => panic!("expected BadFeePayerSlot, got {other:?}"),
        }
    }
}
