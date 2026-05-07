//! Tx assembly for the close path. Three transactions:
//!
//! - **ATA preflight:** `[ComputeBudget,
//!   CreateIdempotent { payee, payer, treasury, splits[..] }]`. Same
//!   shape on both close paths. Only the fee payer signs; the
//!   `CreateIdempotent` wallet metas are unsigned.
//! - **settle_and_finalize:**
//!     - Apply-voucher path: `[ComputeBudget, ed25519_verify,
//!       settle_and_finalize { has_voucher: 1 }]`. The precompile sits
//!       at `current - 1` of `settle_and_finalize` because the program
//!       walks the instructions sysvar to read its result.
//!     - Lock-settled path: `[ComputeBudget,
//!       settle_and_finalize { has_voucher: 0 }]`. No precompile.
//! - **distribute:** `[ComputeBudget, distribute]`. Single ix carrying
//!   the full distribution args.
//!
//! Splitting into three txs is a sizing decision: even with upstream's
//! `Vec<DistributionEntry>` recipients (length-prefixed, only active
//! entries serialized), folding `distribute` into the same tx as
//! `settle_and_finalize` blows past Solana's 1232-byte packet limit
//! once both ixs' account lists land on the same message. The ATA
//! preflight is its own tx for the same reason: cold-start
//! `CreateIdempotent` for payee, payer, treasury, and every split
//! recipient adds a wallet meta per recipient.
//!
//! Fee payer is the operator's `config.fee_payer`. The merchant signer
//! on `settle_and_finalize` is the operator's configured payee key:
//! `Channel.payee` is set at open time to `config.payee`, and the
//! program asserts `merchant.address() == ch.payee`. The distribute tx
//! only needs the fee payer to sign; the on-chain ix doesn't authorize
//! any party beyond the program-derived channel.

use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use payment_channels_client::instructions::{DistributeBuilder, SettleAndFinalizeBuilder};
use payment_channels_client::types::{DistributeArgs, SettleAndFinalizeArgs, VoucherArgs};
use solana_ed25519_program::new_ed25519_instruction_with_signature;

use crate::error::SessionError;
use crate::program::payment_channels::canonical_tx::{create_ata_idempotent_ix, splits_to_recipients};
use crate::program::payment_channels::splits::TREASURY_OWNER;
use crate::program::payment_channels::voucher::build_signed_payload;
use crate::protocol::intents::session::{SignedVoucher, Split};
use crate::server::session::open::{ata_address, pk_to_addr, spl_token_id};
use crate::store::ChannelRecord;

/// Compute budget for the settle_and_finalize tx. The apply-voucher
/// path burns the ed25519 precompile (~3k CU) plus settle_and_finalize
/// (~150k); the lock-settled path is just the latter. 200k covers both
/// with headroom.
const SETTLE_COMPUTE_UNIT_LIMIT: u32 = 200_000;
/// Compute budget for the distribute tx. Distribute with `MAX_SPLITS`
/// (8) burns ~150k CU; 200k covers worst case with headroom.
const DISTRIBUTE_COMPUTE_UNIT_LIMIT: u32 = 200_000;
/// Compute budget for the ATA preflight tx. Each `CreateIdempotent`
/// burns ~25k CU on a missing account; payee + payer + treasury + 8
/// splits is 11 ATAs, so 300k covers the cold-start worst case.
const PREFLIGHT_COMPUTE_UNIT_LIMIT: u32 = 300_000;
const COMPUTE_UNIT_PRICE_MICROLAMPORTS: u64 = 1;

/// Hard cap on serialized tx size. Solana rejects anything over the
/// packet limit at the cluster boundary. ATA preflight, both
/// settle_and_finalize variants, and distribute all fit under this
/// budget at the SDK's `MAX_SPLITS = 8` cardinality with the upstream
/// `Vec<DistributionEntry>` args layout. Each builder enforces the cap
/// and surfaces a typed `InternalError` so the failure shows up at
/// build time instead of as an opaque RPC rejection.
const MAX_TX_BYTES: usize = 1232;

/// Build the ATA preflight tx: `[ComputeBudget,
/// CreateIdempotent { payee, payer, treasury, splits[..] }]`. Same
/// shape on both close paths. Only the fee payer signs; the recipient
/// field of `CreateIdempotent` is unsigned.
pub(crate) fn build_ata_preflight_tx(
    record: &ChannelRecord,
    blockhash: &Hash,
    fee_payer: &Pubkey,
) -> Result<Transaction, SessionError> {
    let mut ixs = compute_budget_prelude(PREFLIGHT_COMPUTE_UNIT_LIMIT);
    ixs.extend(create_idempotent_ata_ixs(record, fee_payer));

    fee_payer_only_tx(ixs, fee_payer, blockhash)
}

/// Build the apply-voucher settle_and_finalize tx: `[ComputeBudget,
/// ed25519_verify, settle_and_finalize { has_voucher: 1 }]`.
///
/// The precompile ix is composed from the supplied voucher's existing
/// signature bytes; nothing re-signs here. The caller has already run
/// the voucher through the same checks `verify_voucher` does, so the
/// signature is known good against `record.authorized_signer`.
///
/// Signature slots are sized for fee payer + merchant. The caller drops
/// both real signatures in (slot 0 = fee payer, slot 1 = merchant)
/// before broadcasting.
pub(crate) fn build_settle_tx_apply_voucher(
    record: &ChannelRecord,
    voucher: &SignedVoucher,
    blockhash: &Hash,
    fee_payer: &Pubkey,
    payee_signer: &Pubkey,
) -> Result<Transaction, SessionError> {
    let (cumulative_amount, expires_at) = parse_voucher_scalars(voucher)?;
    let signer_bytes = decode_fixed::<32>(&voucher.signer)
        .ok_or(SessionError::VoucherSignatureInvalid)?;
    let signature_bytes = decode_fixed::<64>(&voucher.signature)
        .ok_or(SessionError::VoucherSignatureInvalid)?;

    let payload = build_signed_payload(&record.channel_id, cumulative_amount, expires_at);
    let precompile_ix =
        new_ed25519_instruction_with_signature(&payload, &signature_bytes, &signer_bytes);

    let settle_finalize_ix = build_settle_and_finalize_ix(
        record,
        Some(VoucherArgs {
            channel_id: pk_to_addr(&record.channel_id),
            cumulative_amount,
            expires_at,
        }),
        payee_signer,
    );

    let mut ixs = compute_budget_prelude(SETTLE_COMPUTE_UNIT_LIMIT);
    ixs.push(precompile_ix);
    ixs.push(settle_finalize_ix);

    fee_payer_plus_merchant_tx(ixs, fee_payer, blockhash)
}

/// Pull `cumulative_amount` and `expires_at` off a wire `SignedVoucher`.
/// `expires_at = None` is the wire encoding for "no expiry" and maps to
/// `0` on the on-chain `i64`.
fn parse_voucher_scalars(voucher: &SignedVoucher) -> Result<(u64, i64), SessionError> {
    let cumulative_amount: u64 = voucher
        .voucher
        .cumulative_amount
        .parse()
        .map_err(|e| SessionError::InvalidAmount(format!("cumulativeAmount: {e}")))?;
    let expires_at: i64 = match voucher.voucher.expires_at.as_deref() {
        None => 0,
        Some(s) => time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
            .map_err(|e| SessionError::InvalidAmount(format!("expiresAt: {e}")))?
            .unix_timestamp(),
    };
    Ok((cumulative_amount, expires_at))
}

/// Decode a base58 fixed-length byte field. Returns `None` on any
/// failure; callers map that to `VoucherSignatureInvalid` so the wire
/// error doesn't reveal which structural check tripped.
fn decode_fixed<const N: usize>(raw: &str) -> Option<[u8; N]> {
    bs58::decode(raw).into_vec().ok()?.try_into().ok()
}

/// Build the lock-settled settle_and_finalize tx: `[ComputeBudget,
/// settle_and_finalize { has_voucher: 0 }]`. No precompile; the voucher
/// field in the args is a zeroed placeholder the program ignores when
/// `has_voucher = 0`.
pub(crate) fn build_settle_tx_lock_settled(
    record: &ChannelRecord,
    blockhash: &Hash,
    fee_payer: &Pubkey,
    payee_signer: &Pubkey,
) -> Result<Transaction, SessionError> {
    let settle_finalize_ix = build_settle_and_finalize_ix(record, None, payee_signer);

    let mut ixs = compute_budget_prelude(SETTLE_COMPUTE_UNIT_LIMIT);
    ixs.push(settle_finalize_ix);

    fee_payer_plus_merchant_tx(ixs, fee_payer, blockhash)
}

/// Build the distribute tx: `[ComputeBudget, distribute]`. Only the
/// fee payer signs; the upstream `distribute` ix lists no signer
/// accounts (channel, payer, and token accounts are all `[writable]`
/// without `is_signer`).
pub(crate) fn build_distribute_tx(
    record: &ChannelRecord,
    blockhash: &Hash,
    fee_payer: &Pubkey,
) -> Result<Transaction, SessionError> {
    let distribute_ix = build_distribute_ix(record);

    let mut ixs = compute_budget_prelude(DISTRIBUTE_COMPUTE_UNIT_LIMIT);
    ixs.push(distribute_ix);

    fee_payer_only_tx(ixs, fee_payer, blockhash)
}

/// Build the `settle_and_finalize` ix. `voucher` is `Some` for the
/// with-voucher branch and `None` for the no-voucher branch (the args
/// carry a zeroed `VoucherArgs` placeholder in that case).
fn build_settle_and_finalize_ix(
    record: &ChannelRecord,
    voucher: Option<VoucherArgs>,
    merchant: &Pubkey,
) -> Instruction {
    let (voucher_args, has_voucher) = match voucher {
        Some(v) => (v, 1u8),
        None => (
            VoucherArgs {
                channel_id: pk_to_addr(&record.channel_id),
                cumulative_amount: 0,
                expires_at: 0,
            },
            0u8,
        ),
    };
    SettleAndFinalizeBuilder::new()
        .merchant(pk_to_addr(merchant))
        .channel(pk_to_addr(&record.channel_id))
        .instructions_sysvar(pk_to_addr(&solana_sdk_ids::sysvar::instructions::ID))
        .settle_and_finalize_args(SettleAndFinalizeArgs {
            voucher: voucher_args,
            has_voucher,
        })
        .instruction()
}

/// Build the `distribute` ix. Recipient ATAs go in as remaining
/// accounts in the same order as `record.splits`; upstream zips entries
/// with remaining accounts by index in `distribute::process`, so the
/// order has to match.
fn build_distribute_ix(record: &ChannelRecord) -> Instruction {
    let token_program_pk = spl_token_id();
    let token_program = pk_to_addr(&token_program_pk);
    let channel_token_account =
        ata_address(&record.channel_id, &record.mint, &token_program_pk);
    let payer_token_account = ata_address(&record.payer, &record.mint, &token_program_pk);
    let payee_token_account = ata_address(&record.payee, &record.mint, &token_program_pk);
    let treasury_token_account = ata_address(&TREASURY_OWNER, &record.mint, &token_program_pk);

    let recipients = splits_to_recipients(&record.splits);

    let mut builder = DistributeBuilder::new();
    builder
        .channel(pk_to_addr(&record.channel_id))
        .payer(pk_to_addr(&record.payer))
        .channel_token_account(pk_to_addr(&channel_token_account))
        .payer_token_account(pk_to_addr(&payer_token_account))
        .payee_token_account(pk_to_addr(&payee_token_account))
        .treasury_token_account(pk_to_addr(&treasury_token_account))
        .mint(pk_to_addr(&record.mint))
        .token_program(token_program)
        .distribute_args(DistributeArgs { recipients });

    for split in &record.splits {
        let recipient = match split {
            Split::Bps { recipient, .. } => *recipient,
        };
        let recipient_ata = ata_address(&recipient, &record.mint, &token_program_pk);
        builder.add_remaining_account(AccountMeta::new(pk_to_addr(&recipient_ata), false));
    }

    builder.instruction()
}

/// `CreateIdempotent` ATA ixs for payee, each split recipient, payer
/// (refund), and the treasury. Distribute reads from these accounts, so
/// any missing one would fail the on-chain transfer. `CreateIdempotent`
/// no-ops when the ATA exists, so we always emit the full set.
fn create_idempotent_ata_ixs(record: &ChannelRecord, fee_payer: &Pubkey) -> Vec<Instruction> {
    let token_program_pk = spl_token_id();
    let mut ixs = Vec::with_capacity(3 + record.splits.len());

    ixs.push(create_ata_idempotent_ix(
        fee_payer,
        &record.payee,
        &record.mint,
        &token_program_pk,
    ));
    ixs.push(create_ata_idempotent_ix(
        fee_payer,
        &record.payer,
        &record.mint,
        &token_program_pk,
    ));
    ixs.push(create_ata_idempotent_ix(
        fee_payer,
        &TREASURY_OWNER,
        &record.mint,
        &token_program_pk,
    ));
    for split in &record.splits {
        let recipient = match split {
            Split::Bps { recipient, .. } => *recipient,
        };
        ixs.push(create_ata_idempotent_ix(
            fee_payer,
            &recipient,
            &record.mint,
            &token_program_pk,
        ));
    }
    ixs
}

/// ComputeBudget prelude (limit and price). Each builder picks its own
/// limit; the price is shared.
fn compute_budget_prelude(unit_limit: u32) -> Vec<Instruction> {
    use solana_compute_budget_interface::ComputeBudgetInstruction;
    vec![
        ComputeBudgetInstruction::set_compute_unit_limit(unit_limit),
        ComputeBudgetInstruction::set_compute_unit_price(COMPUTE_UNIT_PRICE_MICROLAMPORTS),
    ]
}

/// Wrap a `[Instruction]` in a `Transaction` with one signature slot
/// for the fee payer. ATA preflight only needs the fee payer; the
/// wallet / recipient meta on `CreateIdempotent` is unsigned.
fn fee_payer_only_tx(
    ixs: Vec<Instruction>,
    fee_payer: &Pubkey,
    blockhash: &Hash,
) -> Result<Transaction, SessionError> {
    let fee_payer_addr = pk_to_addr(fee_payer);
    let message = Message::new_with_blockhash(&ixs, Some(&fee_payer_addr), blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let required = tx.message.header.num_required_signatures as usize;
    tx.signatures = vec![Signature::default(); required];
    enforce_size(&tx)?;
    Ok(tx)
}

/// Wrap a `[Instruction]` in a `Transaction` with two signature slots
/// (fee payer + merchant). The caller fills them in.
fn fee_payer_plus_merchant_tx(
    ixs: Vec<Instruction>,
    fee_payer: &Pubkey,
    blockhash: &Hash,
) -> Result<Transaction, SessionError> {
    let fee_payer_addr = pk_to_addr(fee_payer);
    let message = Message::new_with_blockhash(&ixs, Some(&fee_payer_addr), blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let required = tx.message.header.num_required_signatures as usize;
    tx.signatures = vec![Signature::default(); required];
    enforce_size(&tx)?;
    Ok(tx)
}

/// Hard size check. Both close txs should fit; an overflow points at a
/// real bug (split count exceeded, account list grew unexpectedly), so
/// we want it to surface as a typed error before broadcast rather than
/// an opaque cluster rejection.
fn enforce_size(tx: &Transaction) -> Result<(), SessionError> {
    let serialized = bincode::serialize(tx).map_err(|e| {
        SessionError::InternalError(format!("close tx serialize failed: {e}"))
    })?;
    if serialized.len() > MAX_TX_BYTES {
        return Err(SessionError::InternalError(format!(
            "close tx size {} exceeds packet limit {}",
            serialized.len(),
            MAX_TX_BYTES,
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::payment_channels::voucher::VoucherSigner;
    use crate::protocol::intents::session::{SigType, SignedVoucher, VoucherData};
    use crate::server::session::open::addr_to_pk;
    use crate::store::ChannelStatus;
    use ed25519_dalek::SigningKey;

    fn pk(b: u8) -> Pubkey {
        Pubkey::new_from_array([b; 32])
    }

    fn base_record(channel_id: Pubkey) -> ChannelRecord {
        ChannelRecord {
            channel_id,
            payer: pk(0xA1),
            payee: pk(0xA2),
            mint: pk(0xA3),
            salt: 0,
            program_id: pk(0xA4),
            authorized_signer: pk(0xA5),
            deposit: 1_000_000,
            accepted_cumulative: 500_000,
            on_chain_settled: 0,
            last_voucher: None,
            close_tx: None,
            status: ChannelStatus::Open,
            splits: vec![Split::Bps {
                recipient: pk(0xB1),
                share_bps: 1_000,
            }],
        }
    }

    /// Sign a voucher payload off a stable seed so the precompile
    /// composer below can produce a real, verifiable ix. The signer
    /// pubkey and signature both flow into the wire `SignedVoucher`.
    fn signed_voucher(channel_id: Pubkey, cumulative: u64) -> SignedVoucher {
        let signing_key = SigningKey::from_bytes(&[0x42u8; 32]);
        let payload = build_signed_payload(&channel_id, cumulative, 0);
        let sig = signing_key
            .sign_voucher_payload(&payload)
            .expect("dalek signer is infallible");
        SignedVoucher {
            voucher: VoucherData {
                channel_id: bs58::encode(channel_id.as_ref()).into_string(),
                cumulative_amount: cumulative.to_string(),
                expires_at: None,
            },
            signer: bs58::encode(signing_key.verifying_key_bytes()).into_string(),
            signature: bs58::encode(sig).into_string(),
            signature_type: SigType::Ed25519,
        }
    }

    /// Use the production `MAX_SPLITS` directly so the size-fit tests
    /// exercise the actual cap.
    use crate::program::payment_channels::canonical_tx::MAX_SPLITS;

    fn record_with_splits(channel_id: Pubkey, n: usize) -> ChannelRecord {
        let mut record = base_record(channel_id);
        record.splits = (0..n)
            .map(|i| Split::Bps {
                recipient: pk(0xB0u8.wrapping_add(i as u8)),
                share_bps: 100,
            })
            .collect();
        record
    }

    #[test]
    fn apply_voucher_settle_tx_has_precompile_directly_before_settle_and_finalize() {
        let cid = pk(0xC1);
        let record = base_record(cid);
        let voucher = signed_voucher(cid, 600_000);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);
        let merchant = pk(0xA2);

        let tx = build_settle_tx_apply_voucher(
            &record,
            &voucher,
            &blockhash,
            &fee_payer,
            &merchant,
        )
        .expect("apply-voucher settle tx builds");

        let pc_program = addr_to_pk(&payment_channels_client::programs::PAYMENT_CHANNELS_ID);
        let ed25519_program_pk = solana_sdk_ids::ed25519_program::ID;

        let settle_idx = tx
            .message
            .instructions
            .iter()
            .position(|ix| {
                let key = tx.message.account_keys[ix.program_id_index as usize];
                addr_to_pk(&key) == pc_program && ix.data.first() == Some(&4u8)
            })
            .expect("settle_and_finalize present");

        assert!(
            settle_idx >= 1,
            "settle_and_finalize needs a slot before it for the precompile",
        );
        let prev = &tx.message.instructions[settle_idx - 1];
        let prev_program = tx.message.account_keys[prev.program_id_index as usize];
        assert_eq!(
            addr_to_pk(&prev_program),
            ed25519_program_pk,
            "precompile sits at settle_and_finalize - 1",
        );
    }

    #[test]
    fn lock_settled_settle_tx_has_no_precompile() {
        let cid = pk(0xC2);
        let record = base_record(cid);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);
        let merchant = pk(0xA2);

        let tx = build_settle_tx_lock_settled(&record, &blockhash, &fee_payer, &merchant)
            .expect("lock-settled settle tx builds");

        let ed25519_program_pk = solana_sdk_ids::ed25519_program::ID;
        for ix in &tx.message.instructions {
            let key = tx.message.account_keys[ix.program_id_index as usize];
            assert_ne!(
                addr_to_pk(&key),
                ed25519_program_pk,
                "lock-settled path should not include the ed25519 precompile",
            );
        }
    }

    #[test]
    fn settle_tx_signature_slots_size_for_fee_payer_plus_merchant() {
        // Both close paths need fee payer plus merchant to sign on the
        // settle_and_finalize tx, so the header reserves exactly two
        // signature slots and the caller fills them in without resizing.
        let cid = pk(0xC3);
        let record = base_record(cid);
        let voucher = signed_voucher(cid, 600_000);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);
        let merchant = pk(0xA2);

        let tx_apply = build_settle_tx_apply_voucher(
            &record,
            &voucher,
            &blockhash,
            &fee_payer,
            &merchant,
        )
        .unwrap();
        assert_eq!(tx_apply.message.header.num_required_signatures, 2);
        assert_eq!(tx_apply.signatures.len(), 2);

        let tx_lock = build_settle_tx_lock_settled(&record, &blockhash, &fee_payer, &merchant)
            .unwrap();
        assert_eq!(tx_lock.message.header.num_required_signatures, 2);
        assert_eq!(tx_lock.signatures.len(), 2);
    }

    #[test]
    fn ata_preflight_tx_signature_slots_size_for_fee_payer_only() {
        // ATA preflight only needs the fee payer's signature;
        // `CreateIdempotent`'s wallet meta is unsigned.
        let cid = pk(0xC9);
        let record = base_record(cid);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);

        let tx = build_ata_preflight_tx(&record, &blockhash, &fee_payer)
            .expect("ata preflight builds");
        assert_eq!(tx.message.header.num_required_signatures, 1);
        assert_eq!(tx.signatures.len(), 1);
    }

    #[test]
    fn distribute_tx_signature_slots_size_for_fee_payer_only() {
        // Distribute lists no signer accounts on-chain, so the wrapping
        // tx only needs the fee payer's signature.
        let cid = pk(0xCD);
        let record = base_record(cid);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);

        let tx = build_distribute_tx(&record, &blockhash, &fee_payer)
            .expect("distribute tx builds");
        assert_eq!(tx.message.header.num_required_signatures, 1);
        assert_eq!(tx.signatures.len(), 1);
    }

    #[test]
    fn distribute_tx_remaining_accounts_match_split_count() {
        // Distribute attaches recipient ATAs as remaining accounts in
        // the same order as `record.splits`. Upstream zips entries with
        // remaining accounts by index, so count and order pin the contract.
        let cid = pk(0xC4);
        let mut record = base_record(cid);
        record.splits = vec![
            Split::Bps {
                recipient: pk(0xB1),
                share_bps: 4_000,
            },
            Split::Bps {
                recipient: pk(0xB2),
                share_bps: 3_000,
            },
        ];
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);

        let tx = build_distribute_tx(&record, &blockhash, &fee_payer).unwrap();

        let pc_program = addr_to_pk(&payment_channels_client::programs::PAYMENT_CHANNELS_ID);
        let distribute = tx
            .message
            .instructions
            .iter()
            .find(|ix| {
                let key = tx.message.account_keys[ix.program_id_index as usize];
                addr_to_pk(&key) == pc_program && ix.data.first() == Some(&7u8)
            })
            .expect("distribute present");
        assert_eq!(
            distribute.accounts.len(),
            8 + record.splits.len(),
            "8 base accounts + one remaining per split",
        );
    }

    #[test]
    fn ata_preflight_tx_fits_in_packet_limit_at_max_splits() {
        // Cold-start worst case: 8 splits plus payee, payer, treasury,
        // with every `CreateIdempotent` expanding a new ATA and wallet
        // account into the message. Has to stay under 1232 bytes.
        let cid = pk(0xCA);
        let record = record_with_splits(cid, MAX_SPLITS);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);

        let tx = build_ata_preflight_tx(&record, &blockhash, &fee_payer)
            .expect("ata preflight builds at MAX_SPLITS");
        let bytes = bincode::serialize(&tx).expect("serialize");
        assert!(
            bytes.len() <= MAX_TX_BYTES,
            "ata preflight tx is {} bytes, limit {}",
            bytes.len(),
            MAX_TX_BYTES,
        );
    }

    #[test]
    fn apply_voucher_settle_tx_fits_in_packet_limit_at_max_splits() {
        let cid = pk(0xCB);
        let record = record_with_splits(cid, MAX_SPLITS);
        let voucher = signed_voucher(cid, 600_000);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);
        let merchant = pk(0xA2);

        let tx = build_settle_tx_apply_voucher(
            &record,
            &voucher,
            &blockhash,
            &fee_payer,
            &merchant,
        )
        .expect("apply-voucher settle tx builds at MAX_SPLITS");
        let bytes = bincode::serialize(&tx).expect("serialize");
        assert!(
            bytes.len() <= MAX_TX_BYTES,
            "apply-voucher settle tx is {} bytes, limit {}",
            bytes.len(),
            MAX_TX_BYTES,
        );
    }

    #[test]
    fn lock_settled_settle_tx_fits_in_packet_limit_at_max_splits() {
        let cid = pk(0xCC);
        let record = record_with_splits(cid, MAX_SPLITS);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);
        let merchant = pk(0xA2);

        let tx = build_settle_tx_lock_settled(&record, &blockhash, &fee_payer, &merchant)
            .expect("lock-settled settle tx builds at MAX_SPLITS");
        let bytes = bincode::serialize(&tx).expect("serialize");
        assert!(
            bytes.len() <= MAX_TX_BYTES,
            "lock-settled settle tx is {} bytes, limit {}",
            bytes.len(),
            MAX_TX_BYTES,
        );
    }

    #[test]
    fn distribute_tx_fits_in_packet_limit_at_max_splits() {
        // Build-time size budget: distribute with MAX_SPLITS recipients
        // fits under Solana's 1232-byte packet limit. The L1 distribute
        // and tombstone oracles cover the path against the loaded
        // program.
        let cid = pk(0xCE);
        let record = record_with_splits(cid, MAX_SPLITS);
        let blockhash = Hash::new_from_array([7u8; 32]);
        let fee_payer = pk(0xFE);

        let tx = build_distribute_tx(&record, &blockhash, &fee_payer)
            .expect("distribute tx builds at MAX_SPLITS");
        let bytes = bincode::serialize(&tx).expect("serialize");
        assert!(
            bytes.len() <= MAX_TX_BYTES,
            "distribute tx is {} bytes, limit {}",
            bytes.len(),
            MAX_TX_BYTES,
        );
    }
}
