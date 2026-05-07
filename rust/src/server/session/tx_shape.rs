//! Canonical tx-shape gate for client-submitted handler txs.
//!
//! Open and topup share the same broadcast contract: the client sends
//! a partial-signed tx, the server rebuilds the canonical ix, signs
//! slot 0, and broadcasts. The gate refuses anything that isn't
//! byte-equal to a single canonical ix targeting the payment-channels
//! program. A looser check (extra ix, short signature vec, drifting
//! account flags) lets a malicious client smuggle ops under the server
//! fee-payer signature.

use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;

use payment_channels_client::programs::PAYMENT_CHANNELS_ID;

use crate::error::SessionError;
use crate::server::session::open::addr_to_pk;

/// Writability of `account_keys[i]` from the message header. Mirrors
/// `solana_message::Message::is_writable_index`, which is crate-private
/// upstream.
pub(crate) fn key_is_writable(
    header: &solana_message::MessageHeader,
    account_keys_len: usize,
    i: usize,
) -> bool {
    let num_signed = header.num_required_signatures as usize;
    let writable_signed_end =
        num_signed.saturating_sub(header.num_readonly_signed_accounts as usize);
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

/// Validate a partial-signed client tx against the canonical ix the
/// server would emit. Returns the decoded `Transaction` on success;
/// the caller signs slot 0 with the server fee-payer.
pub(crate) fn validate_canonical_single_ix_tx_shape(
    tx_b64: &str,
    canonical_ix: &Instruction,
    fee_payer_pk: &Pubkey,
    expected_blockhash: &Hash,
    ix_label: &'static str,
) -> Result<Transaction, SessionError> {
    let tx_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, tx_b64)
        .map_err(|e| SessionError::MaliciousTx {
            reason: format!("base64 decode failed: {e}"),
        })?;

    let tx: Transaction = bincode::deserialize(&tx_bytes).map_err(|e| SessionError::MaliciousTx {
        reason: format!("transaction bincode decode failed: {e}"),
    })?;

    // Any extra ix (system transfer, compute-budget tweak, ATA-create)
    // would land under the server fee-payer signature.
    if tx.message.instructions.len() != 1 {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "expected exactly 1 instruction, got {}",
                tx.message.instructions.len()
            ),
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

    // A short signature vec sails through the slot-0 overwrite the
    // orchestrator does later, and the cluster only catches it after
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
    if slot0_pk != *fee_payer_pk {
        return Err(SessionError::BadFeePayerSlot {
            expected: *fee_payer_pk,
            got: slot0_pk,
        });
    }

    if tx.message.recent_blockhash != *expected_blockhash {
        return Err(SessionError::BlockhashMismatch {
            expected: expected_blockhash.to_string(),
            got: tx.message.recent_blockhash.to_string(),
        });
    }

    let pc_program_pk = addr_to_pk(&PAYMENT_CHANNELS_ID);
    let ix_compiled = &tx.message.instructions[0];
    let program_idx = ix_compiled.program_id_index as usize;
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

    if ix_compiled.data != canonical_ix.data {
        return Err(SessionError::MaliciousTx {
            reason: format!("{ix_label} ix data does not match canonical bytes"),
        });
    }

    if ix_compiled.accounts.len() != canonical_ix.accounts.len() {
        return Err(SessionError::MaliciousTx {
            reason: format!(
                "{ix_label} ix expects {} accounts, got {}",
                canonical_ix.accounts.len(),
                ix_compiled.accounts.len()
            ),
        });
    }

    let account_keys_len = tx.message.account_keys.len();
    for (i, (slot_idx, expected_meta)) in ix_compiled
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
                reason: format!("{ix_label} ix account index {slot_idx} out of range"),
            })?;
        let got_pk = addr_to_pk(got);
        let expected_pk = addr_to_pk(&expected_meta.pubkey);
        if got_pk != expected_pk {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "{ix_label} ix account #{i} mismatch: expected {expected_pk}, got {got_pk}"
                ),
            });
        }
        let got_signer = tx.message.is_signer(slot);
        if got_signer != expected_meta.is_signer {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "{ix_label} ix account #{i} signer flag mismatch: expected {}, got {}",
                    expected_meta.is_signer, got_signer
                ),
            });
        }
        let got_writable = key_is_writable(&tx.message.header, account_keys_len, slot);
        if got_writable != expected_meta.is_writable {
            return Err(SessionError::MaliciousTx {
                reason: format!(
                    "{ix_label} ix account #{i} writable flag mismatch: expected {}, got {}",
                    expected_meta.is_writable, got_writable
                ),
            });
        }
    }

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_message::MessageHeader;

    fn header(req: u8, ro_signed: u8, ro_unsigned: u8) -> MessageHeader {
        MessageHeader {
            num_required_signatures: req,
            num_readonly_signed_accounts: ro_signed,
            num_readonly_unsigned_accounts: ro_unsigned,
        }
    }

    #[test]
    fn key_is_writable_writable_signer() {
        let h = header(2, 0, 0);
        assert!(key_is_writable(&h, 4, 0));
        assert!(key_is_writable(&h, 4, 1));
    }

    #[test]
    fn key_is_writable_readonly_signer() {
        let h = header(2, 1, 0);
        assert!(key_is_writable(&h, 4, 0));
        assert!(!key_is_writable(&h, 4, 1));
    }

    #[test]
    fn key_is_writable_writable_unsigned() {
        // 1 required sig, 0 readonly signed, 1 readonly unsigned over 4 keys:
        // slot 1 (first unsigned) is writable, slot 3 (last) is readonly.
        let h = header(1, 0, 1);
        assert!(key_is_writable(&h, 4, 1));
        assert!(key_is_writable(&h, 4, 2));
        assert!(!key_is_writable(&h, 4, 3));
    }

    #[test]
    fn key_is_writable_readonly_unsigned() {
        let h = header(1, 0, 2);
        assert!(key_is_writable(&h, 4, 1));
        assert!(!key_is_writable(&h, 4, 2));
        assert!(!key_is_writable(&h, 4, 3));
    }

    #[test]
    fn key_is_writable_all_readonly_signers_returns_false() {
        let h = header(2, 2, 0);
        assert!(!key_is_writable(&h, 4, 0));
        assert!(!key_is_writable(&h, 4, 1));
    }
}
